//! Core find patterns - bulk recursive deletion spelled with `find`.
//!
//! `core.filesystem` names its rules after the SPELLING of the command
//! (`rm-rf-root-home`), not after the act. `find` reaches the same outcome --
//! recursive deletion of every file under a path -- by a route no pack claimed
//! a keyword for, so `find ~/dev/agent-observer -type f -delete` was
//! `quick-rejected (no keywords)` and ALLOWED while `rm -rf` on that same path
//! DENIED (`.agent-config-xzx79`, 2026-09-23).
//!
//! Three spellings reach the same act:
//!
//! - `find <path> ... -delete`
//! - `find <path> ... -exec rm ... {} \;`
//! - `find <path> ... -print0 | xargs -0 rm -f`
//!
//! # The deny surface is find-with-a-delete-action, and nothing wider
//!
//! A `find` that only walks, prints, greps or counts never matches: every
//! destructive pattern here requires a deletion verb. That keeps the common
//! case -- `find . -name '*.log'` -- out of the pack entirely.
//!
//! # Where the temp line is drawn, and why it is the same line as `rm`
//!
//! The safe pattern carves out exactly the roots `core.filesystem` already
//! treats as scratch -- `/tmp`, `/var/tmp`, `$TMPDIR`, `${TMPDIR}`,
//! `${TMPDIR:?}`, the two `${TMPDIR:-...}` default forms, and the directory the
//! live `$TMPDIR` resolves to -- and reuses its `..`-traversal guard verbatim. A path `rm -rf` denies is a path `find -delete` denies; a path
//! `rm -rf` allows is a path `find -delete` allows. One line, two spellings.
//!
//! The two sets are separate mechanisms -- a structural parse there, a regex
//! here -- so nothing but a test can hold them together. That test is
//! `temp_roots_agree_with_the_rm_pack` in `tests/repro_find_delete_family.rs`,
//! which asks BOTH spellings about every root and ends on a non-temp control.
//!
//! The temp set was deliberately not widened HERE FIRST, and that was the live
//! question rather than a matter of taste. The dominant real `find -delete` on
//! this machine targets `/var/folders/<..>/T/codex-workflow/...`, the resolved
//! macOS `$TMPDIR`. Measured on the live binary before any of this landed,
//! `rm -rf` on that same literal path already DENIED, as did the opaque
//! `"$RUN_DIR"` spelling -- dcg does not expand variables, so an opaque one is
//! never scratch. Those commands were spelled with `find` because `find` was
//! the route that went unjudged. Widening here ALONE would have made `find`
//! more permissive than `rm`, which is the defect this pack exists to remove,
//! pointed the other way.
//!
//! That was a scoping decision, not a verdict that the resolved directory can
//! never be scratch, and `.agent-config-o4e8j` reversed it on Dale's word
//! 2026-09-24 -- in BOTH packs at once, so the one-line property above still
//! holds. `core.filesystem::resolved_temp_roots` now resolves `TMPDIR` and both
//! packs read that one answer; `find_temp_root_pattern` is where this pack
//! consumes it. The opaque `$VAR` is untouched and still denied.
//!
//! The carve-out ends at the first non-option operand, so a second root
//! smuggled in behind a temp one (`find /tmp/a /etc -delete`) does not inherit
//! the exemption. Two temp roots (`find /tmp/a /tmp/b -delete`) are denied by
//! the same rule; that is an accepted false positive, and `dcg allow-once`
//! covers it.
//!
//! # What it costs, replayed rather than asserted
//!
//! Both spec-333 populations through the live binary and this one, same
//! harness and config the zm1pj install used:
//!
//! - population A, 1,191 heredoc blocks: **0 moved rows**
//! - population B, 18,723 real Bash invocations (2026-07-03..2026-08-30):
//!   **19 moved rows, 0.10%**, every one `ALLOW -> DENY`, every one a
//!   find-delete, every one `stable`. No row moved `DENY -> ALLOW`, so this
//!   opens no hole.
//!
//! Sixteen of the nineteen are one workflow's run-directory cleanup
//! (`find "$RUN_DIR" -delete`), whose respelling is
//! `.agent-config-codex-workflow-run-dir-cleanup-respell-r1c0j`: name the temp
//! root instead of hiding it behind a variable, and it is allowed again.

use crate::destructive_pattern;
use crate::packs::core::filesystem::{resolved_temp_roots, tmpdir_value_ends_with_slash};
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};

/// Suggestions shared by every rule in this pack: the act is the same one.
const FIND_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview which files the walk reaches before deleting any of them",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count the files that would be deleted",
    ),
    PatternSuggestion::new(
        "find /tmp/{subdir} -type f -delete",
        "Bulk deletion under a temp root is allowed without confirmation",
    ),
    PatternSuggestion::new(
        "find {path} -name '{glob}' -print -delete",
        "Print each path as it is deleted so the transcript records the damage",
    ),
];

/// Command words that let this pack be consulted at all.
///
/// The registry's `PackEntry` points at this same const -- one list, not two
/// (`.agent-config-x74pe`). `/find` covers `/usr/bin/find`, matching the `/rm`
/// entry `core.filesystem` carries for the same reason.
pub const KEYWORDS: &[&str] = &["find", "/find"];

/// Create the core find pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.find".to_string(),
        name: "Core Find",
        description: "Protects against bulk recursive deletion driven by find, outside temp directories",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![SafePattern {
        regex: LazyCompiledRegex::new_owned(find_temp_root_pattern(
            resolved_temp_roots(),
            tmpdir_value_ends_with_slash(),
        )),
        name: "find-temp-root",
    }]
}

/// A walk rooted at a temp directory, and rooted there ONLY.
///
/// The trailing `(?:\s+-|\s*$)` is what makes the second root in
/// `find /tmp/a /etc -delete` fatal: after the temp path the next thing must be
/// an expression primary (`-type`, `-delete`, ...) or the end of the command.
/// Any further operand means a root this pack did not clear, and the exemption
/// is not granted.
///
/// Two arms, because `core.filesystem` has two. Unquoted, it accepts the literal
/// temp roots and the `$TMPDIR` spellings; inside double quotes it accepts ONLY
/// the `$TMPDIR` spellings, since a double-quoted `/tmp` literal is denied there
/// and this pack does not get to be more permissive than the rule it is
/// mirroring. Single quotes are safe in neither.
///
/// The `..` guards are `core.filesystem`'s, verbatim -- one per arm: a path may
/// not be `..` itself nor contain a `..` segment, so `/tmp/../etc` is not a temp
/// root.
///
/// # Why this is built rather than written down
///
/// `resolved` is the directory the live `$TMPDIR` names -- machine- and
/// user-specific, so it cannot be a literal in this file. It arrives already
/// stripped of its trailing slash so it slots into the same `<root>/<rest>`
/// shape `/tmp` uses, and it is regex-escaped here. The parameters exist so the
/// unit tests below can read both shapes without reaching for the environment,
/// which a `OnceLock` would have frozen for the whole process.
///
/// `braced_without_separator` carries
/// `core.filesystem::tmpdir_value_ends_with_slash`; the reason that gate exists
/// is documented there, and it must be the SAME answer in both packs or the two
/// temp sets disagree.
fn find_temp_root_pattern(resolved: &[String], braced_without_separator: bool) -> String {
    const DOTDOT_UNQUOTED: &str = r"(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))";
    const DOTDOT_QUOTED: &str = r#"(?!(?:[^"]*/)?\.\.(?:/|"))"#;
    const UNQUOTED_SPELLINGS: &str = r"/tmp|/var/tmp|\$TMPDIR|\$\{TMPDIR\}|\$\{TMPDIR:\?\}|\$\{TMPDIR:-/tmp\}|\$\{TMPDIR:-/var/tmp\}";
    const QUOTED_SPELLINGS: &str =
        r"\$TMPDIR|\$\{TMPDIR\}|\$\{TMPDIR:\?\}|\$\{TMPDIR:-/tmp\}|\$\{TMPDIR:-/var/tmp\}";
    const BRACED: &str = r"\$\{TMPDIR(?::\?)?\}";

    let mut unquoted_roots = String::from(UNQUOTED_SPELLINGS);
    for root in resolved {
        unquoted_roots.push('|');
        unquoted_roots.push_str(&regex::escape(root));
    }

    let mut pattern = String::from(r"find\s+(?:-[HLPEdsx]+\s+)*(?:(?:");
    pattern.push_str(&unquoted_roots);
    pattern.push_str(r")(?:/");
    pattern.push_str(DOTDOT_UNQUOTED);
    pattern.push_str(r"[^\s;&|]*)?");
    if braced_without_separator {
        pattern.push('|');
        pattern.push_str(BRACED);
        pattern.push_str(DOTDOT_UNQUOTED);
        pattern.push_str(r"[^\s;&|]+");
    }
    pattern.push_str(r#"|"(?:"#);
    pattern.push_str(QUOTED_SPELLINGS);
    pattern.push_str(r")(?:/");
    pattern.push_str(DOTDOT_QUOTED);
    pattern.push_str(r#"[^"]*)?""#);
    if braced_without_separator {
        pattern.push_str(r#"|""#);
        pattern.push_str(BRACED);
        pattern.push_str(DOTDOT_QUOTED);
        pattern.push_str(r#"[^"]+""#);
    }
    pattern.push_str(r")(?:\s+-|\s*$)");
    pattern
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // find ... -delete
        //
        // `[^;&|]*` keeps the match inside the command it starts in: the
        // `-delete` that arms this rule must belong to the same `find`.
        destructive_pattern!(
            "find-delete-outside-temp",
            r"find\s[^;&|]*\s-delete\b",
            "find -delete removes every file the walk reaches. Outside a temp directory this is recursive deletion and requires human approval — ask the user to run it manually.",
            High,
            "find -delete walks the whole tree under its starting path and unlinks \
             everything the expression selects. There is no confirmation, no \
             summary, and no trash: the first you know of a wrong -name is that the \
             files are gone.\n\n\
             This is the same act as rm -rf on the starting path, spelled \
             differently. dcg draws the same line for both: a walk rooted under \
             /tmp, /var/tmp or $TMPDIR is scratch and is allowed; anywhere else \
             needs a human.\n\n\
             Preview before deleting — the expression is the dangerous part, so \
             read what it selects:\n  \
             find /path -name '*.ext'            # list what would go\n  \
             find /path -name '*.ext' | wc -l    # count it\n\n\
             Then delete with a record of what went:\n  \
             find /path -name '*.ext' -print -delete",
            FIND_DELETE_SUGGESTIONS
        ),
        // find ... -exec rm ... / -execdir / -ok / -okdir
        //
        // The deletion verb must sit in the command position -exec opens, so
        // `find . -exec grep rm {} \;` does not match. A `sudo` or an absolute
        // path in front of it does not hide it.
        destructive_pattern!(
            "find-exec-delete-outside-temp",
            r"find\s[^;&|]*-(?:exec|ok)(?:dir)?\s+(?:sudo\s+)?(?:/\S*/)?(?:rm|unlink|shred)\b",
            "find -exec rm runs a delete on every file the walk reaches. Outside a temp directory this is recursive deletion and requires human approval — ask the user to run it manually.",
            High,
            "find -exec rm is rm -rf with extra steps: the walk supplies the paths \
             and rm unlinks them one batch at a time. -f on the rm suppresses even \
             the per-file errors that might otherwise stop you.\n\n\
             -execdir, -ok and -okdir reach the same outcome; -ok prompts per file, \
             which on a large tree is answered with a held-down y.\n\n\
             Preview the walk first — it is the walk, not the rm, that decides what \
             dies:\n  \
             find /path -type f | head -20\n  \
             find /path -type f | wc -l\n\n\
             Under /tmp, /var/tmp or $TMPDIR this is allowed without confirmation.",
            FIND_DELETE_SUGGESTIONS
        ),
        // find ... | xargs ... rm
        //
        // `[^;&]*` lets the pipeline have more stages (`find . | grep x | xargs
        // rm`) while still refusing to read across `;` or `&&` into a separate
        // command. After `xargs`, only its own flags may stand between it and
        // the deletion verb, so `find . | xargs grep rm` does not match.
        destructive_pattern!(
            "find-xargs-delete-outside-temp",
            r"find\s[^;&]*\|\s*(?:sudo\s+)?(?:/\S*/)?xargs\s+(?:-\S+\s+)*(?:sudo\s+)?(?:/\S*/)?(?:rm|unlink|shred)\b",
            "find piped into xargs rm deletes every file the walk reaches. Outside a temp directory this is recursive deletion and requires human approval — ask the user to run it manually.",
            High,
            "find | xargs rm is the third spelling of the same act. The pipe makes it \
             read like two harmless halves — a walk that prints, and an rm that is \
             handed a list — but the outcome is one bulk recursive delete, and \
             -print0 | xargs -0 exists precisely so no filename can stop it.\n\n\
             Preview by stopping at the pipe:\n  \
             find /path -name '*.ext' | head -20\n  \
             find /path -name '*.ext' | wc -l\n\n\
             Under /tmp, /var/tmp or $TMPDIR this is allowed without confirmation.",
            FIND_DELETE_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    // Every literal here is shell command TEXT, and the `${TMPDIR}` in it is
    // the subject under test, not a format argument.
    #![allow(clippy::literal_string_with_formatting_args)]

    use super::*;

    /// The built pattern, compiled, so a row reads as a verdict and not as text.
    ///
    /// Through `LazyCompiledRegex` on purpose: the pattern carries look-ahead, so
    /// the `regex` crate cannot compile it at all and only the engine production
    /// actually selects can answer. A helper that reached for `regex::Regex`
    /// would report a syntax error, not a verdict.
    fn matches(pattern: &str, command: &str) -> bool {
        LazyCompiledRegex::new_owned(pattern.to_string()).is_match(command)
    }

    #[test]
    fn a_resolved_root_is_accepted_unquoted_and_only_with_a_separator() {
        let roots = vec!["/var/folders/2j/abc0000gn/T".to_string()];
        let pattern = find_temp_root_pattern(&roots, true);

        assert!(
            matches(&pattern, "find /var/folders/2j/abc0000gn/T/run -delete"),
            "the resolved root is scratch, exactly as /tmp is"
        );
        // The BARE root is accepted, because that is what this pack already does
        // with a bare `/tmp` and a bare `$TMPDIR` -- measured 2026-09-24 on the
        // pre-change binary 3af31294, all three ALLOW, while the `rm` spellings
        // of the same three DENY. That asymmetry is the pre-existing optional
        // `(?:/...)?` group, not something this change introduced, and mirroring
        // it is what keeps the resolved root treated exactly as `/tmp` is HERE.
        // Nothing new is reachable: `find $TMPDIR -delete` already named this
        // same directory and already passed.
        assert!(
            matches(&pattern, "find /var/folders/2j/abc0000gn/T -delete"),
            "the bare resolved root goes the same way as a bare /tmp in this pack"
        );
        assert!(
            matches(&pattern, "find /tmp -delete"),
            "the control for the row above -- if THIS ever goes red the mirror moved"
        );
        assert!(
            !matches(&pattern, "find /var/folders/2j/abc0000gn/T/../C -delete"),
            "a traversal out of the root is not the root"
        );
        assert!(
            !matches(&pattern, "find /var/folders -delete"),
            "/var/folders itself is not anybody's scratch"
        );
        assert!(
            !matches(&pattern, "find /var/folders/ab/zzzz0000gn/T/x -delete"),
            "another user's hash does not match this user's prefix"
        );
        assert!(
            !matches(
                &pattern,
                r#"find "/var/folders/2j/abc0000gn/T/run" -delete"#
            ),
            "a double-quoted literal is denied here, as a double-quoted /tmp is"
        );
        assert!(
            !matches(
                &pattern,
                "find /var/folders/2j/abc0000gn/T/run /etc -delete"
            ),
            "a second root behind the resolved one does not inherit the exemption"
        );
    }

    #[test]
    fn a_pattern_built_with_no_resolved_root_accepts_no_literal_var_folders() {
        let pattern = find_temp_root_pattern(&[], true);
        assert!(
            !matches(&pattern, "find /var/folders/2j/abc0000gn/T/run -delete"),
            "with TMPDIR unset or degenerate, nothing under /var/folders is scratch"
        );
        assert!(
            matches(&pattern, "find /tmp/run -delete"),
            "and the literal spellings are untouched — the control for the row above"
        );
    }

    #[test]
    fn the_braced_forms_without_a_separator_follow_the_gate() {
        let open = find_temp_root_pattern(&[], true);
        let shut = find_temp_root_pattern(&[], false);

        for command in [
            "find ${TMPDIR:?}run -delete",
            "find ${TMPDIR}run -delete",
            r#"find "${TMPDIR:?}run" -delete"#,
            r#"find "${TMPDIR}run" -delete"#,
        ] {
            assert!(matches(&open, command), "gate open: {command}");
            assert!(
                !matches(&shut, command),
                "gate shut, because TMPDIR does not end in a slash: {command}"
            );
        }

        // `${TMPDIR}` on its own is the bare root, which this pack already
        // accepted before the gate existed -- so it passes with the gate SHUT
        // too, and that is the honest reading rather than a gate effect.
        assert!(matches(&shut, "find ${TMPDIR} -delete"));
        // A traversal is still a traversal without a separator.
        assert!(!matches(&open, "find ${TMPDIR:?}../C -delete"));

        // The separator-carrying spellings do NOT depend on the gate.
        for command in [
            "find ${TMPDIR:?}/run -delete",
            r#"find "${TMPDIR:?}/run" -delete"#,
        ] {
            assert!(matches(&open, command), "gate open: {command}");
            assert!(matches(&shut, command), "gate irrelevant here: {command}");
        }
    }

    #[test]
    fn the_built_pattern_keeps_the_spellings_it_always_had() {
        let pattern = find_temp_root_pattern(&[], false);
        for command in [
            "find /tmp/x -delete",
            "find /var/tmp/x -delete",
            "find $TMPDIR/x -delete",
            "find ${TMPDIR}/x -delete",
            "find ${TMPDIR:-/tmp}/x -delete",
            "find ${TMPDIR:-/var/tmp}/x -delete",
            r#"find "$TMPDIR/x" -delete"#,
            r#"find "${TMPDIR}/x" -delete"#,
        ] {
            assert!(
                matches(&pattern, command),
                "pre-existing spelling: {command}"
            );
        }
        for command in [
            "find /etc -delete",
            r#"find "/tmp/x" -delete"#,
            "find /tmp/../etc -delete",
            "find /tmp/a /etc -delete",
            "find '$TMPDIR/x' -delete",
        ] {
            assert!(!matches(&pattern, command), "still refused: {command}");
        }
    }

    #[test]
    fn pack_claims_the_find_keywords() {
        let pack = create_pack();
        assert!(pack.keywords.contains(&"find"));
        assert!(pack.keywords.contains(&"/find"));
    }

    #[test]
    fn every_destructive_pattern_is_named() {
        let pack = create_pack();
        assert_eq!(pack.destructive_patterns.len(), 3);
        for pattern in &pack.destructive_patterns {
            assert!(
                pattern.name.is_some(),
                "an unnamed rule cannot be allowlisted or allow-once'd"
            );
        }
    }
}
