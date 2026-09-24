//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed) -- including the directory the
//!   live $TMPDIR resolves to, see `resolved_temp_roots`

use std::sync::OnceLock;

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, Platform, SafePattern, Severity};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `rm -rf` on root/home paths pattern.
const RM_RF_ROOT_HOME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview what files would be deleted before running",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
    PatternSuggestion::new(
        "rm -rf /path/to/specific/subdirectory",
        "Use explicit, specific paths instead of root or home",
    ),
];

/// Suggestions for general `rm -rf` pattern.
const RM_RF_GENERAL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent deletion (requires trash-cli)",
        Platform::Linux,
    ),
    PatternSuggestion::with_platform(
        "gio trash {path}",
        "Move to trash via GNOME (requires gio)",
        Platform::Linux,
    ),
    PatternSuggestion::new(
        "mv {path} /tmp/delete-me-{timestamp}",
        "Move to a temp holding area instead of deleting immediately",
    ),
    PatternSuggestion::new(
        "rm -rf /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
];

/// Suggestions for `rm -r -f` (separate flags) pattern.
const RM_R_F_SEPARATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "rm -r -f /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "rm -r -f $TMPDIR/{subdir}",
        "Use system temp directory (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview files before deletion",
    ),
];

/// Suggestions for `rm --recursive --force` (long flags) pattern.
const RM_RECURSIVE_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm --interactive --recursive {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "find {path} --maxdepth 2 -ls | head -30",
        "Preview directory structure before deletion",
    ),
    PatternSuggestion::new(
        "rm --recursive --force /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
];
use crate::{normalize::NormalizeTokenKind, normalize::tokenize_for_normalization};
use std::ops::Range;

const RM_RF_ROOT_HOME_NAME: &str = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON: &str = "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_RF_GENERAL_NAME: &str = "rm-rf-general";
const RM_RF_GENERAL_REASON: &str = "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME: &str = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON: &str =
    "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME: &str = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON: &str =
    "rm --recursive --force is destructive and requires human approval.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteKind {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone)]
pub(crate) struct RmParseMatch {
    pub(crate) pattern_name: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) severity: Severity,
    pub(crate) span: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
pub(crate) enum RmParseDecision {
    Allow,
    Deny(RmParseMatch),
    NoMatch,
}

#[derive(Debug)]
struct PathToken<'a> {
    unquoted: &'a str,
    quote: QuoteKind,
    range: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmFlagStyle {
    Combined,
    Separate,
    Long,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RmFlagState {
    style: RmFlagStyle,
    span: Option<Range<usize>>,
    saw_terminator: bool,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct RmFlagTracker {
    combined_span: Option<Range<usize>>,
    seen_r: bool,
    r_span: Option<Range<usize>>,
    seen_f: bool,
    f_span: Option<Range<usize>>,
    seen_long_recursive: bool,
    recursive_span: Option<Range<usize>>,
    seen_long_force: bool,
    force_span: Option<Range<usize>>,
    saw_terminator: bool,
}

impl RmFlagTracker {
    fn resolve(self) -> Option<RmFlagState> {
        if let Some(span) = self.combined_span {
            return Some(RmFlagState {
                style: RmFlagStyle::Combined,
                span: Some(span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_r && self.seen_f {
            return Some(RmFlagState {
                style: RmFlagStyle::Separate,
                span: self.r_span.or(self.f_span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_long_recursive && self.seen_long_force {
            return Some(RmFlagState {
                style: RmFlagStyle::Long,
                span: self.recursive_span.or(self.force_span),
                saw_terminator: self.saw_terminator,
            });
        }

        None
    }
}

pub(crate) fn parse_rm_command(command: &str) -> RmParseDecision {
    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return RmParseDecision::NoMatch;
    }

    // EVERY `rm` segment on the line is judged, not just the first one
    // (.agent-config-6nnw8). Returning the first segment's decision meant a
    // demonstrably safe leading `rm -rf` under /tmp produced `Allow`, and the
    // evaluator skips the whole core.filesystem pack on `Allow` -- so a
    // destructive `rm` appended to a harmless one was permitted while the same
    // destructive `rm` alone was blocked. A Deny anywhere on the line wins.
    let mut deny: Option<RmParseMatch> = None;
    let mut saw_allow = false;

    let mut i = 0;
    while i < tokens.len() {
        let current = &tokens[i];
        if current.kind == NormalizeTokenKind::Separator {
            i += 1;
            continue;
        }

        let Some(text) = current.text(command) else {
            i += 1;
            continue;
        };

        if text == "rm" {
            match parse_rm_segment(command, &tokens, i + 1) {
                RmParseDecision::Deny(hit) => {
                    // Keep the most serious hit, so a Critical segment behind a
                    // High one is still reported as Critical -- severity decides
                    // whether an allowlist may override the denial.
                    let held_is_critical = deny
                        .as_ref()
                        .is_some_and(|held| held.severity == Severity::Critical);
                    if deny.is_none() || (!held_is_critical && hit.severity == Severity::Critical) {
                        deny = Some(hit);
                    }
                }
                RmParseDecision::Allow => saw_allow = true,
                RmParseDecision::NoMatch => {}
            }
        }

        // Skip to the next separator before scanning for another command word.
        i += 1;
        while i < tokens.len() && tokens[i].kind != NormalizeTokenKind::Separator {
            i += 1;
        }
    }

    if let Some(hit) = deny {
        return RmParseDecision::Deny(hit);
    }
    if saw_allow {
        return RmParseDecision::Allow;
    }

    RmParseDecision::NoMatch
}

#[allow(clippy::too_many_lines)]
fn parse_rm_segment(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
) -> RmParseDecision {
    let mut options_ended = false;
    let mut flags = RmFlagTracker::default();

    let mut paths: Vec<PathToken<'_>> = Vec::new();

    for token in tokens.iter().skip(start_idx) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }

        let Some(text) = token.text(command) else {
            continue;
        };

        if !options_ended {
            if text == "--" {
                options_ended = true;
                flags.saw_terminator = true;
                continue;
            }

            if text.starts_with('-') && text != "-" {
                if text.starts_with("--") {
                    if text.starts_with("--recursive") {
                        flags.seen_long_recursive = true;
                        if flags.recursive_span.is_none() {
                            flags.recursive_span = Some(token.byte_range.clone());
                        }
                    }
                    if text.starts_with("--force") {
                        flags.seen_long_force = true;
                        if flags.force_span.is_none() {
                            flags.force_span = Some(token.byte_range.clone());
                        }
                    }
                } else {
                    let flag_text = text.trim_start_matches('-');
                    if !flag_text.is_empty() {
                        let has_r = flag_text.chars().any(|c| c == 'r' || c == 'R');
                        let has_f = flag_text.chars().any(|c| c == 'f');
                        if has_r && has_f {
                            if flags.combined_span.is_none() {
                                flags.combined_span = Some(token.byte_range.clone());
                            }
                        } else {
                            if has_r && !flags.seen_r {
                                flags.seen_r = true;
                                flags.r_span = Some(token.byte_range.clone());
                            }
                            if has_f && !flags.seen_f {
                                flags.seen_f = true;
                                flags.f_span = Some(token.byte_range.clone());
                            }
                        }
                    }
                }

                continue;
            }
        }

        options_ended = true;
        let (quote, unquoted) = strip_outer_quotes(text);
        paths.push(PathToken {
            unquoted,
            quote,
            range: token.byte_range.clone(),
        });
    }

    let flag_state = flags.resolve();
    let Some(flag_state) = flag_state else {
        return RmParseDecision::NoMatch;
    };

    let safe_paths = !paths.is_empty()
        && !flag_state.saw_terminator
        && paths
            .iter()
            .all(|path| path_is_safe_for_style(path, flag_state.style));

    if safe_paths {
        return RmParseDecision::Allow;
    }

    let first_path = paths.first();
    let is_critical = flag_state.style == RmFlagStyle::Combined
        && !flag_state.saw_terminator
        && first_path.is_some_and(path_is_root_home);

    let (pattern_name, reason, severity) = if is_critical {
        (
            RM_RF_ROOT_HOME_NAME,
            RM_RF_ROOT_HOME_REASON,
            Severity::Critical,
        )
    } else {
        match flag_state.style {
            RmFlagStyle::Combined => (RM_RF_GENERAL_NAME, RM_RF_GENERAL_REASON, Severity::High),
            RmFlagStyle::Separate => (RM_R_F_SEPARATE_NAME, RM_R_F_SEPARATE_REASON, Severity::High),
            RmFlagStyle::Long => (
                RM_RECURSIVE_FORCE_NAME,
                RM_RECURSIVE_FORCE_REASON,
                Severity::High,
            ),
        }
    };

    let span = flag_state
        .span
        .or_else(|| paths.first().map(|path| path.range.clone()));

    RmParseDecision::Deny(RmParseMatch {
        pattern_name,
        reason,
        severity,
        span,
    })
}

fn strip_outer_quotes(token: &str) -> (QuoteKind, &str) {
    if token.len() >= 2 {
        if token.starts_with('"') && token.ends_with('"') {
            return (QuoteKind::Double, &token[1..token.len() - 1]);
        }
        if token.starts_with('\'') && token.ends_with('\'') {
            return (QuoteKind::Single, &token[1..token.len() - 1]);
        }
    }
    (QuoteKind::None, token)
}

fn path_is_safe_for_style(path: &PathToken<'_>, style: RmFlagStyle) -> bool {
    if path.quote == QuoteKind::Double && style != RmFlagStyle::Combined {
        return false;
    }

    match path.quote {
        QuoteKind::None => path_is_safe_unquoted(path.unquoted),
        QuoteKind::Double => path_is_safe_double_quoted(path.unquoted),
        QuoteKind::Single => false,
    }
}

/// The absolute temp roots the live `TMPDIR` actually names, WITHOUT a trailing
/// slash, so each one slots into the same `<root>/<rest>` shape `/tmp` uses.
///
/// `/tmp`, `/var/tmp` and the `$TMPDIR` spellings are literals dcg recognises
/// without knowing the machine it runs on. The directory macOS actually hands
/// out is not: it is `/var/folders/<2>/<hash>/T/`, which is exactly what
/// `mktemp -d` prints, so an agent that makes scratch the standard way holds a
/// path no literal here could match. Measured 2026-09-24 on the installed
/// binary, a recursive force delete of `/var/folders/<..>/T/tmp.X` DENIED as
/// `rm-rf-root-home` -- a rule named for something that path is not -- while the
/// `"$TMPDIR/tmp.X"` spelling of the SAME directory ALLOWED
/// (`.agent-config-o4e8j`).
///
/// Resolving the variable closes that spelling gap and grants nothing new:
/// every path admitted here is already admitted under its `$TMPDIR` spelling.
/// `/var/folders` itself, another user's hash, and an opaque `$VAR` all still
/// fail the prefix test, and the root without a trailing `/` is refused exactly
/// as the bare `/tmp` is.
///
/// Both members of the macOS pair are returned, because `/var` is a symlink to
/// `/private/var` and the same directory is handed around in either spelling
/// (`pending_exceptions.rs` documents that pair for its own path comparison).
/// Note what that is, precisely: a widening the literal does NOT get. `/tmp` is a
/// symlink to `/private/tmp` in exactly the same way, and `/private/tmp/x` is
/// denied. So the resolved root is treated like `/tmp` PLUS its twin, which is
/// asymmetric in the permissive direction; the bead asks for the twin by name
/// (`mktemp -d` and `realpath` disagree about which spelling they print), so it
/// stays, but calling it parity would be false.
///
/// Empty when `TMPDIR` is unset, relative, or shallower than two segments, so a
/// missing or degenerate environment admits nothing rather than admitting a
/// prefix near the root. That is also why the integration harness sees no
/// resolved root unless it sets `TMPDIR` itself: `tests/common/spawn.rs` clears
/// the environment.
pub(crate) fn resolved_temp_roots() -> &'static [String] {
    static ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        std::env::var_os("TMPDIR")
            .map(|raw| temp_roots_from_tmpdir_value(&raw.to_string_lossy()))
            .unwrap_or_default()
    })
}

/// Whether a `TMPDIR` value names a directory worth resolving as scratch.
///
/// An allowlist of SHAPES, and deliberately not a depth floor. The floor this
/// replaced — absolute, at least two segments — admitted `/Users/<anyone>` and
/// `/var/folders` itself, so `TMPDIR=$HOME` (a value people really do export)
/// made an entire home directory scratch, and `TMPDIR=/var/folders/` made every
/// OTHER user's temp dir scratch. Both are named in the grant as things that stay
/// blocked, and both were found by cold review on 2026-09-24 before this shipped.
///
/// Recognised, and nothing else:
///
/// - `/tmp`, `/var/tmp` — already literals in both packs, so this adds nothing
/// - `/var/folders/<a>/<b>/T` — the macOS per-user temp dir
/// - `/private/var/folders/<a>/<b>/T` — the same directory, the other spelling
///
/// `T` only: the sibling `C` is the per-user CACHE directory and is not scratch.
/// Anything else resolves to NOTHING, which leaves the `$TMPDIR` spellings
/// working and simply declines to admit the literal — fail closed, not fail open.
/// Nothing is stat'd; this is a judgement about a name, and a guard that trusted
/// the filesystem here would be answering a different question.
fn is_recognised_temp_root(value: &str) -> bool {
    if value == "/tmp" || value == "/var/tmp" {
        return true;
    }
    let Some(rest) = value
        .strip_prefix("/private/var/folders/")
        .or_else(|| value.strip_prefix("/var/folders/"))
    else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() == 3 && !parts[0].is_empty() && !parts[1].is_empty() && parts[2] == "T"
}

/// [`resolved_temp_roots`] without the environment, so the refusals are testable.
///
/// A `OnceLock` reads `TMPDIR` once per process, which a unit test cannot vary.
/// Everything that decides whether a value is usable lives here instead, and
/// [`braced_tmpdir_without_separator_is_scratch`] reads its answer rather than
/// re-deciding — one refusal list, two readers.
fn temp_roots_from_tmpdir_value(value: &str) -> Vec<String> {
    let trimmed = value.trim_end_matches('/');
    if !is_recognised_temp_root(trimmed) {
        return Vec::new();
    }
    let twin = trimmed
        .strip_prefix("/private/var/")
        .map(|rest| format!("/var/{rest}"))
        .or_else(|| {
            trimmed
                .strip_prefix("/var/")
                .map(|rest| format!("/private/var/{rest}"))
        });
    let mut roots = vec![trimmed.to_string()];
    if let Some(twin) = twin {
        if twin != roots[0] {
            roots.push(twin);
        }
    }
    roots
}

/// Whether `${TMPDIR}x` — no separator — names a path inside the temp root.
///
/// `${TMPDIR:?}tmp.X` and `${TMPDIR}tmp.X` carry no separator of their own,
/// because the macOS value already ends in one, and `${TMPDIR:?}` is the form
/// `.claude/rules/bash-safety.md` prescribes for a delete target, so it is a
/// spelling agents are told to write. Two things must hold for it to be scratch:
/// the value has to be a temp root this module recognises, AND it has to end in
/// `/` so the concatenation lands inside that root rather than beside it.
///
/// BOTH halves, from ONE refusal list, and that is the whole point of the first
/// line. This used to ask only "does the value end in `/`", which let a value
/// [`temp_roots_from_tmpdir_value`] REFUSES one function away still open the
/// widest arm the carve-out has: with `TMPDIR=/`, `${TMPDIR}etc` was admitted as
/// scratch while the literal `/etc` was denied — the guard reopened, through a
/// variable, exactly what it refuses spelled out. Both blind reviewers found it
/// independently on 2026-09-24 and it never shipped. A second reader of the same
/// environment variable is a second policy; there is now one.
///
/// Unset, `${TMPDIR}src` expands to a RELATIVE `src`, so a recursive force delete
/// written that way inside a repo would take that repo's own `src`. The spellings
/// that carry their own `/` need no gate and do not consult this.
pub(crate) fn braced_tmpdir_without_separator_is_scratch() -> bool {
    static SCRATCH: OnceLock<bool> = OnceLock::new();
    *SCRATCH.get_or_init(|| {
        if resolved_temp_roots().is_empty() {
            return false;
        }
        std::env::var_os("TMPDIR").is_some_and(|value| value.to_string_lossy().ends_with('/'))
    })
}

/// Whether `path` sits under `root`, separator required.
///
/// Split out from [`path_is_resolved_temp`] so it can be tested for real. The
/// test that used to cover this built its own copy of the strip/strip/dotdot
/// chain and asserted against that, which certified the test file and not the
/// binary: deleting the feature outright left it green (cold review, 2026-09-24).
///
/// The `/` is required, so the root itself (`/var/folders/<..>/T`) is refused
/// just as the bare `/tmp` is, and a sibling that merely shares the prefix
/// (`/var/folders/<..>/TOTHER`) cannot pass.
fn path_is_under_temp_root(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| !has_dotdot_segment(rest))
}

/// Whether `path` is a literal path under one of [`resolved_temp_roots`].
fn path_is_resolved_temp(path: &str) -> bool {
    resolved_temp_roots()
        .iter()
        .any(|root| path_is_under_temp_root(path, root))
}

/// The `${TMPDIR}`/`${TMPDIR:?}` forms written without a separator.
///
/// Gated on [`braced_tmpdir_without_separator_is_scratch`]; see there for why.
fn path_is_safe_braced_tmpdir_without_separator(path: &str) -> bool {
    if !braced_tmpdir_without_separator_is_scratch() {
        return false;
    }
    for prefix in ["${TMPDIR:?}", "${TMPDIR}"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return !rest.is_empty() && !has_dotdot_segment(rest);
        }
    }
    false
}

fn path_is_safe_unquoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("/var/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // `${TMPDIR:?}` expands exactly as `${TMPDIR}` does, and aborts rather than
    // expanding empty. It was denied until `.agent-config-o4e8j`.
    if let Some(rest) = path.strip_prefix("${TMPDIR:?}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    // The resolved per-user temp dir, unquoted only -- a double-quoted `/tmp`
    // literal is denied here, so the literal this mirrors is denied in quotes
    // too.
    if path_is_resolved_temp(path) {
        return true;
    }
    path_is_safe_braced_tmpdir_without_separator(path)
}

fn path_is_safe_double_quoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // `${TMPDIR:?}` expands exactly as `${TMPDIR}` does, and aborts rather than
    // expanding empty. It was denied until `.agent-config-o4e8j`.
    if let Some(rest) = path.strip_prefix("${TMPDIR:?}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    path_is_safe_braced_tmpdir_without_separator(path)
}

fn has_dotdot_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == "..")
}

fn path_is_root_home(path: &PathToken<'_>) -> bool {
    // Check if the path is root or home, ignoring quotes for absolute paths.
    // Tilde expansion only happens if UNQUOTED, but / is absolute regardless.

    let text = path.unquoted;

    // Absolute paths starting with / are dangerous regardless of quotes
    // e.g. rm -rf "/" is just as deadly as rm -rf /
    if text.starts_with('/') {
        return true;
    }

    // Tilde expansion (~/) only happens if unquoted
    if path.quote == QuoteKind::None && text.starts_with('~') {
        return true;
    }

    false
}

/// Command words that let this pack be consulted at all.
///
/// The registry's `PackEntry` points at this same const. They used to be two
/// lists, and 26 of 80 packs had drifted: the pack claimed a keyword the
/// registry gate did not carry, so rules for those words could never run
/// (`.agent-config-x74pe`).
pub const KEYWORDS: &[&str] = &["rm", "/rm"];

/// Create the core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.filesystem".to_string(),
        name: "Core Filesystem",
        description: "Protects against dangerous rm -rf commands outside temp directories",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

#[allow(clippy::too_many_lines)]
fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // rm -rf in /tmp (combined flags)
        safe_pattern!(
            "rm-rf-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with $TMPDIR (combined flags)
        safe_pattern!(
            "rm-rf-tmpdir",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with ${TMPDIR} (braced form)
        safe_pattern!(
            "rm-rf-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with quoted $TMPDIR
        safe_pattern!(
            "rm-rf-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -rf with quoted ${TMPDIR}
        safe_pattern!(
            "rm-rf-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with $TMPDIR
        safe_pattern!(
            "rm-r-f-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with ${TMPDIR}
        safe_pattern!(
            "rm-r-f-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with $TMPDIR
        safe_pattern!(
            "rm-recursive-force-tmpdir",
            r"^rm\s+.*--recursive.*--force\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir",
            r"^rm\s+.*--force.*--recursive\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with ${TMPDIR}
        safe_pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"^rm\s+.*--recursive.*--force\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"^rm\s+.*--force.*--recursive\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
        destructive_pattern!(
            "rm-rf-root-home",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]",
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.",
            Critical,
            "This command would recursively delete files starting from the root filesystem (/) \
             or home directory (~). This is catastrophic and will destroy:\n\n\
             - Your entire operating system\n\
             - All installed applications and libraries\n\
             - All user data, documents, and configurations\n\
             - Boot files, making the system unbootable\n\n\
             There is NO recovery without backups. Even with backups, full restoration \
             takes hours to days.\n\n\
             If you need to delete specific files, use explicit paths:\n  \
             rm -rf /path/to/specific/directory\n\n\
             Always preview what would be deleted first:\n  \
             find /path/to/directory -type f | head -20",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // General rm -rf (caught after safe patterns) - High because temp paths are allowed
        destructive_pattern!(
            "rm-rf-general",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
            High,
            "rm -rf recursively removes files and directories without confirmation prompts. \
             The -f (force) flag suppresses all warnings, making accidental deletions \
             silent and immediate.\n\n\
             Why this is dangerous:\n\
             - Deleted files bypass the trash - they're gone immediately\n\
             - Typos in paths can delete unintended directories\n\
             - Wildcards can expand to match more than expected\n\
             - No undo mechanism exists\n\n\
             Safe alternatives:\n\
             - rm -ri: Interactive mode, confirms each file\n\
             - trash-cli: Moves files to trash instead of deleting\n\
             - rm -rf in /tmp, /var/tmp, $TMPDIR: Allowed (safe temp directories)\n\n\
             Preview what would be deleted:\n  \
             find /path/to/delete -type f | wc -l  # Count files\n  \
             ls -la /path/to/delete               # List contents",
            RM_RF_GENERAL_SUGGESTIONS
        ),
        // rm -r -f (separate flags)
        destructive_pattern!(
            "rm-r-f-separate",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval.",
            High,
            "rm with separate -r and -f flags has the same effect as rm -rf: recursive \
             forced deletion without confirmation.\n\n\
             Common variations that are all equivalent:\n\
             - rm -r -f path\n\
             - rm -f -r path\n\
             - rm -r -f -v path (verbose but still forced)\n\n\
             All carry the same risks as rm -rf: immediate, silent, irreversible deletion.\n\n\
             Safer approach for temporary directories:\n\
             - rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n\
             - rm -r -f $TMPDIR/mydir # Allowed - uses system temp dir\n\n\
             For other paths, prefer:\n  \
             rm -ri /path  # Interactive confirmation",
            RM_R_F_SEPARATE_SUGGESTIONS
        ),
        // rm --recursive --force (long flags)
        destructive_pattern!(
            "rm-recursive-force-long",
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval.",
            High,
            "rm --recursive --force is the long-form equivalent of rm -rf. While more \
             readable, it carries identical risks: silent, recursive, irreversible deletion.\n\n\
             The long flags may appear in:\n\
             - Scripts aiming for clarity\n\
             - Generated code from build tools\n\
             - Cross-platform compatibility scenarios\n\n\
             All standard rm -rf precautions apply:\n\
             - Verify the path before running\n\
             - Use absolute paths to avoid ambiguity\n\
             - Consider using trash-cli for recoverable deletion\n\n\
             Preview command:\n  \
             find /path --maxdepth 2 -ls | head -30",
            RM_RECURSIVE_FORCE_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn a_macos_tmpdir_value_yields_both_members_of_the_private_pair() {
        let roots = temp_roots_from_tmpdir_value("/var/folders/2j/abc0000gn/T/");
        assert_eq!(
            roots,
            vec![
                "/var/folders/2j/abc0000gn/T".to_string(),
                "/private/var/folders/2j/abc0000gn/T".to_string(),
            ],
            "the trailing slash is stripped and the /private twin is derived"
        );
    }

    #[test]
    fn a_private_tmpdir_value_yields_the_same_pair_the_other_way_round() {
        let roots = temp_roots_from_tmpdir_value("/private/var/folders/2j/abc0000gn/T");
        assert_eq!(
            roots,
            vec![
                "/private/var/folders/2j/abc0000gn/T".to_string(),
                "/var/folders/2j/abc0000gn/T".to_string(),
            ]
        );
    }

    #[test]
    fn a_degenerate_tmpdir_value_admits_nothing() {
        // Each of these, admitted, would make a path near the root scratch.
        for value in ["", "/", "//", "/var", "/var/", "relative/tmp", "tmp"] {
            assert!(
                temp_roots_from_tmpdir_value(value).is_empty(),
                "TMPDIR={value:?} must admit no prefix at all"
            );
        }
    }

    #[test]
    fn a_tmpdir_value_that_is_not_a_temp_dir_shape_admits_nothing() {
        // The floor this replaced admitted every one of these. `TMPDIR=$HOME` is
        // the one that matters: it made a whole home directory scratch.
        for value in [
            "/Users/somebody/scratch",
            "/Users/dalecarman",
            "/Users/dalecarman/",
            "/Users/dalecarman/dev",
            "/home/runner/work/_temp",
            "/var/folders",
            "/var/folders/",
            "/var/folders/2j",
            "/var/folders/2j/abc0000gn",
            "/var/folders/2j/abc0000gn/C",
            "/var/folders/2j/abc0000gn/0",
            "/var/folders/2j/abc0000gn/T/nested",
            "/private/var/folders/2j/abc0000gn/C",
            "/usr/local",
            "/etc",
        ] {
            assert!(
                temp_roots_from_tmpdir_value(value).is_empty(),
                "TMPDIR={value:?} must admit no prefix at all"
            );
        }
    }

    #[test]
    fn the_recognised_temp_root_shapes_are_exactly_these() {
        for value in [
            "/tmp",
            "/var/tmp",
            "/var/folders/2j/abc0000gn/T",
            "/private/var/folders/2j/abc0000gn/T",
        ] {
            assert!(
                is_recognised_temp_root(value),
                "must be recognised: {value}"
            );
        }
        for value in [
            "",
            "/",
            "/var",
            "/var/folders",
            "/var/folders//T",
            "/var/folders/2j/abc0000gn/C",
            "/var/folders/2j/abc0000gn/T/x",
            "/var/folders/2j/T",
            "/Users/dalecarman",
            "/private/tmp",
            "tmp",
            "relative/T",
        ] {
            assert!(
                !is_recognised_temp_root(value),
                "must NOT be recognised: {value:?}"
            );
        }
    }

    #[test]
    fn a_resolved_root_needs_a_separator_and_a_real_prefix_match() {
        // Calls the REAL predicate. The version of this test that shipped to
        // review built its own copy of the chain and asserted against that, so
        // deleting the feature left it green.
        let root = "/var/folders/2j/abc0000gn/T";
        assert!(
            path_is_under_temp_root("/var/folders/2j/abc0000gn/T/tmp.X", root),
            "a path under it"
        );
        assert!(
            path_is_under_temp_root("/var/folders/2j/abc0000gn/T/", root),
            "the root with a trailing slash, as /tmp/ is"
        );
        assert!(
            !path_is_under_temp_root(root, root),
            "the bare root, as bare /tmp is refused"
        );
        assert!(
            !path_is_under_temp_root("/var/folders/2j/abc0000gn/TOTHER/x", root),
            "a sibling sharing the prefix is not inside it"
        );
        assert!(
            !path_is_under_temp_root("/var/folders/2j/abc0000gn/T/../C/x", root),
            "a traversal out of the root is not in the root"
        );
        assert!(
            !path_is_under_temp_root("/var/folders/2j/abc0000gn/T/a/../../C", root),
            "a traversal buried deeper is still a traversal"
        );
    }

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "core.filesystem");
        assert_eq!(pack.name, "Core Filesystem");
        assert!(pack.keywords.contains(&"rm"));
    }

    #[test]
    fn test_rm_rf_root_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -rf /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /home", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -rf /", "rm-rf-root-home");
    }

    #[test]
    fn test_rm_rf_general_high() {
        let pack = create_pack();
        // Outside safe dirs, general rule catches it
        assert_blocks_with_severity(&pack, "rm -rf ./build", Severity::High);
        assert_blocks_with_pattern(&pack, "rm -rf ./build", "rm-rf-general");
    }

    #[test]
    fn test_rm_flags_ordering() {
        let pack = create_pack();
        assert_blocks(&pack, "rm -r -f ./build", "separate -r -f flags");
        assert_blocks(&pack, "rm -f -r ./build", "separate -r -f flags");
        assert_blocks(
            &pack,
            "rm --recursive --force ./build",
            "rm --recursive --force is destructive",
        );
        assert_blocks(
            &pack,
            "rm --force --recursive ./build",
            "rm --recursive --force is destructive",
        );
    }

    #[test]
    fn test_safe_rm_tmp() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -rf /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -rf /var/tmp/stuff");
        assert_safe_pattern_matches(&pack, "rm -rf $TMPDIR/junk");
        assert_safe_pattern_matches(&pack, "rm -rf ${TMPDIR}/junk");
    }

    #[test]
    fn test_tmpdir_brace_requires_exact_var_name() {
        let pack = create_pack();
        assert!(!pack.matches_safe("rm -rf ${TMPDIR_NOT}/junk"));
        assert_rm_parser_denies(
            "rm -rf ${TMPDIR_NOT}/junk",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_safe_rm_variants() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -fr /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -r -f /tmp/test");
        assert_safe_pattern_matches(&pack, "rm --recursive --force /tmp/test");
    }

    #[test]
    fn test_path_traversal_blocked() {
        let pack = create_pack();
        // Should NOT match safe patterns (so it falls through to destructive)
        assert!(!pack.matches_safe("rm -rf /tmp/../etc"));
        assert!(!pack.matches_safe("rm -rf /var/tmp/../etc"));

        // And should be blocked by destructive rules
        assert_blocks(&pack, "rm -rf /tmp/../etc", "rm -rf on root or home paths");
    }

    fn assert_rm_parser_allows(command: &str) {
        let decision = parse_rm_command(command);
        assert!(
            matches!(decision, RmParseDecision::Allow),
            "Expected rm parser to allow '{command}', got {decision:?}",
        );
    }

    fn assert_rm_parser_denies(command: &str, expected_rule: &str, expected_severity: Severity) {
        match parse_rm_command(command) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(
                    hit.pattern_name, expected_rule,
                    "Unexpected rule for '{command}'"
                );
                assert_eq!(
                    hit.severity, expected_severity,
                    "Unexpected severity for '{command}'"
                );
            }
            other => unreachable!("Expected rm parser to deny '{command}', got {other:?}"),
        }
    }

    fn assert_rm_parser_no_match(command: &str) {
        match parse_rm_command(command) {
            RmParseDecision::NoMatch => {}
            other => {
                unreachable!("Expected rm parser to return NoMatch for '{command}', got {other:?}")
            }
        }
    }

    #[test]
    fn test_rm_parser_allows_tmpdir_quotes() {
        assert_rm_parser_allows(r#"rm -rf "$TMPDIR/foo""#);
        assert_rm_parser_allows(r#"rm -rf "${TMPDIR}/foo""#);
        assert_rm_parser_denies(r"rm -rf '$TMPDIR/foo'", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies(
            r#"rm -r -f "$TMPDIR/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm -r -f "${TMPDIR}/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_rm_parser_traversal_blocked() {
        assert_rm_parser_denies(
            "rm -rf /tmp/../etc",
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );
    }

    #[test]
    fn test_rm_parser_option_terminator() {
        assert_rm_parser_no_match("rm -- -rf /tmp/safe");
    }
}
