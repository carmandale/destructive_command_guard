//! AST-based pattern matching for heredoc and inline script content.
//!
//! This module implements Tier 3 of the heredoc detection architecture,
//! using ast-grep-core for structural pattern matching.
//!
//! # Architecture
//!
//! ```text
//! Content + Language
//!      │
//!      ▼
//! ┌─────────────────┐
//! │   AstMatcher    │ ─── Parse error ──► ALLOW + diagnostic
//! │   (ast-grep)    │ ─── Timeout ──► caller's budget path (hook: DENY)
//! │   <5ms typical  │ ─── No match ──► ALLOW
//! │                 │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Error Handling
//!
//! Parse errors and unknown languages result in fail-open behavior (ALLOW)
//! with diagnostics. A timeout is different: it means the code was not judged.
//! The evaluator passes the rest of its deadline as the budget
//! ([`AstMatcher::find_matches_within`]), so a timeout there is a spent
//! deadline, which the hook denies (`.agent-config-6cwlr`).
//!
//! # Performance
//!
//! - Pattern compilation: One-time at startup
//! - Parse: <2ms for typical heredoc sizes
//! - Match: <1ms typical
//! - Default timeout for [`AstMatcher::find_matches`]: 20ms

use crate::context::git_global_option_takes_value;
use crate::heredoc::ScriptLanguage;
use ast_grep_core::{AstGrep, Doc, Node, NodeMatch, Pattern};
use ast_grep_language::SupportLang;
use memchr::memchr_iter;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Default timeout for [`AstMatcher::find_matches`] (20ms as per ADR). The hook
/// evaluator does not use it; it passes its own remaining deadline.
///
/// Tests use a more generous budget because CI/debug builds are slower
/// than optimised release binaries.
#[cfg(not(test))]
const AST_TIMEOUT_MS: u64 = 20;
#[cfg(test)]
const AST_TIMEOUT_MS: u64 = 500;

/// Severity level for pattern matches.
///
/// Determines the default action taken when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Always block - no allowlist override without explicit config.
    Critical,
    /// Block by default, can be allowlisted.
    High,
    /// Warn by default (log but don't block).
    Medium,
    /// Log only - informational.
    Low,
}

impl Severity {
    /// Human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Whether this severity should block by default.
    #[must_use]
    pub const fn blocks_by_default(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

/// Result of a pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Stable rule ID for allowlisting (e.g., `heredoc.python.subprocess_rm`).
    pub rule_id: String,
    /// Human-readable reason for the match.
    pub reason: String,
    /// Preview of the matched text (truncated if too long).
    pub matched_text_preview: String,
    /// Byte offset of match start in the content.
    pub start: usize,
    /// Byte offset of match end in the content.
    pub end: usize,
    /// 1-based line number where match starts.
    pub line_number: usize,
    /// Severity level of this match.
    pub severity: Severity,
    /// Optional suggestion for safe alternative.
    pub suggestion: Option<String>,
}

/// Error during AST matching (all errors are non-fatal, fail-open).
#[derive(Debug, Clone)]
pub enum MatchError {
    /// Language not supported by ast-grep.
    UnsupportedLanguage(ScriptLanguage),
    /// Failed to parse content as the specified language.
    ParseError {
        language: ScriptLanguage,
        detail: String,
    },
    /// Pattern matching exceeded timeout.
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Pattern compilation failed (should not happen with static patterns).
    PatternError { pattern: String, detail: String },
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage(lang) => {
                write!(f, "unsupported language for AST matching: {lang:?}")
            }
            Self::ParseError { language, detail } => {
                write!(f, "AST parse error for {language:?}: {detail}")
            }
            Self::Timeout {
                elapsed_ms,
                budget_ms,
            } => {
                write!(
                    f,
                    "AST matching timeout: {elapsed_ms}ms > {budget_ms}ms budget"
                )
            }
            Self::PatternError { pattern, detail } => {
                write!(f, "pattern compilation error for '{pattern}': {detail}")
            }
        }
    }
}

/// What a widened pattern needs from the body's own imports before it counts.
///
/// A rule that names its receiver literally (`shutil.rmtree($$$)`) misses every
/// other spelling of the same call: `import shutil as sh; sh.rmtree(..)`,
/// `from shutil import rmtree; rmtree(..)`, `const { rmSync } = require('fs')`
/// (`.agent-config-artmu`). Widening the receiver to `$M` fixes that, but these
/// rules are NOT payload-gated the way `execSync`/`spawnSync` are -- they block
/// on any argument -- so an ungated `$M.remove($$$)` would deny
/// `self.remove(item)` in unrelated code.
///
/// So the widened pattern carries a gate, and the gate keeps it to the same
/// MEANING as the spelling it replaced: the receiver is the module, or a name
/// this body's own imports bind to that module. What the imports do not
/// explain is not a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingGate {
    /// Ungated: the pattern names every part of the call literally.
    None,
    /// `$M.<member>($$$)` -- `$M` must be `receiver` itself, a local name bound
    /// to `module`, or an inline `require("<module>")`.
    Receiver {
        /// Canonical module the alias must resolve to (`shutil`, `fs`).
        module: &'static str,
        /// Receiver the replaced pattern named, always accepted so the
        /// canonical spelling keeps its verdict with no import in the body.
        receiver: &'static str,
    },
    /// `<member>($$$)` -- `member` must be imported from `module` in this body.
    Bare {
        /// Canonical module the import must name.
        module: &'static str,
        /// Member the pattern spells, which must be what was imported.
        member: &'static str,
    },
}

/// A compiled AST pattern with metadata.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The pattern string (for debugging/logging).
    pub pattern_str: String,
    /// Stable rule ID.
    pub rule_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Match severity.
    pub severity: Severity,
    /// Optional safe alternative suggestion.
    pub suggestion: Option<String>,
    /// What the body's imports must say for this pattern to count as a match.
    gate: BindingGate,
}

impl CompiledPattern {
    /// Create a new compiled pattern.
    #[must_use]
    pub const fn new(
        pattern_str: String,
        rule_id: String,
        reason: String,
        severity: Severity,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            pattern_str,
            rule_id,
            reason,
            severity,
            suggestion,
            gate: BindingGate::None,
        }
    }

    /// Require the body's imports to explain this pattern's receiver.
    ///
    /// Only for a pattern whose receiver is the metavariable `$M`, or whose
    /// call is a bare name; see [`BindingGate`].
    #[must_use]
    pub(crate) fn with_gate(mut self, gate: BindingGate) -> Self {
        self.gate = gate;
        self
    }
}

#[derive(Debug)]
struct PrecompiledPattern {
    pattern: Pattern,
    meta: CompiledPattern,
}

/// AST pattern matcher using ast-grep-core.
///
/// Holds pre-compiled patterns for each supported language.
pub struct AstMatcher {
    /// Patterns organized by language.
    patterns: HashMap<ScriptLanguage, Vec<PrecompiledPattern>>,
    /// Timeout for matching operations.
    timeout: Duration,
}

impl Default for AstMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AstMatcher {
    /// Create a new matcher with default destructive patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: precompile_patterns(default_patterns()),
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom patterns.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // HashMap is not const-constructible
    pub fn with_patterns(patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>) -> Self {
        Self {
            patterns: precompile_patterns(patterns),
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom timeout.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern, not suitable for const
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find pattern matches in the given code.
    ///
    /// # Errors
    ///
    /// Returns `MatchError` on:
    /// - Unsupported language
    /// - Parse failure
    /// - Timeout
    ///
    /// A timeout is not "no match": a caller on a blocking path must not read
    /// it as one (see [`Self::find_matches_within`]).
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        self.find_matches_within(code, language, self.timeout)
    }

    /// [`Self::find_matches`] under a caller-supplied time budget.
    ///
    /// The hook evaluator passes what is left of its own deadline. A timeout
    /// is "not judged", never "no match", and only the evaluator knows which
    /// way a guard must fail when it runs out of time (`.agent-config-6cwlr`).
    ///
    /// # Errors
    ///
    /// The same as [`Self::find_matches`].
    #[allow(clippy::cast_possible_truncation)] // Only used in the error message
    pub fn find_matches_within(
        &self,
        code: &str,
        language: ScriptLanguage,
        timeout: Duration,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let start_time = Instant::now();
        let budget_ms = timeout.as_millis() as u64;

        // Helper to create timeout error
        let timeout_err = |start: Instant| MatchError::Timeout {
            elapsed_ms: start.elapsed().as_millis() as u64,
            budget_ms,
        };

        // Perl is not supported by ast-grep-language; use a conservative regex fallback.
        if language == ScriptLanguage::Perl {
            return find_matches_perl(code, start_time, timeout, budget_ms);
        }

        // Check language support FIRST (before patterns, so we report unsupported properly)
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            return Err(MatchError::UnsupportedLanguage(language));
        };

        // Get patterns for this language (after language support check)
        let patterns = match self.patterns.get(&language) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(Vec::new()), // No patterns = no matches
        };

        let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();

        // Parse the code
        let ast = AstGrep::new(code, ast_lang);
        let root = ast.root();

        // Check timeout after parsing
        if start_time.elapsed() > timeout {
            return Err(timeout_err(start_time));
        }

        let mut matches = Vec::new();

        // Read the body's imports only if a gated pattern actually matched.
        // Most bodies match nothing, and this is a second O(nodes) walk.
        let mut bindings: Option<ModuleBindings> = None;

        // Match each pattern
        for compiled in patterns {
            // Check timeout before each pattern
            if start_time.elapsed() > timeout {
                return Err(timeout_err(start_time));
            }

            // Find all matches for this pattern
            for node in root.find_all(&compiled.pattern) {
                // Check timeout during matching (a single pattern can match many nodes)
                if start_time.elapsed() > timeout {
                    return Err(timeout_err(start_time));
                }

                if compiled.meta.gate != BindingGate::None {
                    let known = bindings.get_or_insert_with(|| collect_bindings(&root, language));
                    if !gate_admits(compiled.meta.gate, &node, known) {
                        continue;
                    }
                }

                let matched_text = node.text();
                let range = node.range();

                // Calculate line number (1-based)
                let line_number = newline_positions.partition_point(|&idx| idx < range.start) + 1;

                // Create preview (truncate if too long, UTF-8 safe)
                let preview = truncate_preview(&matched_text, 60);

                let Some(refined) = refine_match_meta(language, &compiled.meta, &matched_text)
                else {
                    continue;
                };

                matches.push(PatternMatch {
                    rule_id: refined.rule_id,
                    reason: refined.reason,
                    matched_text_preview: preview,
                    start: range.start,
                    end: range.end,
                    line_number,
                    severity: refined.severity,
                    suggestion: refined.suggestion,
                });
            }
        }

        Ok(matches)
    }

    /// Check if any blocking patterns match (convenience method).
    ///
    /// Returns the first blocking match, or None if no blocking patterns match.
    /// A timeout also returns None, so this is not for a blocking path.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()
            .and_then(|matches| matches.into_iter().find(|m| m.severity.blocks_by_default()))
    }
}

/// Truncate a string to at most `max_chars` characters, UTF-8 safe.
///
/// If truncation occurs, appends "..." to indicate more content exists.
fn truncate_preview(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        text.to_string()
    } else {
        // Leave room for "..."
        let truncate_at = max_chars.saturating_sub(3);
        let truncated: String = text.chars().take(truncate_at).collect();
        format!("{truncated}...")
    }
}

/// Convert `ScriptLanguage` to ast-grep's `SupportLang`.
const fn script_language_to_ast_lang(lang: ScriptLanguage) -> Option<SupportLang> {
    match lang {
        ScriptLanguage::Python => Some(SupportLang::Python),
        ScriptLanguage::JavaScript => Some(SupportLang::JavaScript),
        ScriptLanguage::TypeScript => Some(SupportLang::TypeScript),
        ScriptLanguage::Ruby => Some(SupportLang::Ruby),
        ScriptLanguage::Bash => Some(SupportLang::Bash),
        ScriptLanguage::Go => Some(SupportLang::Go),
        ScriptLanguage::Php => Some(SupportLang::Php),
        ScriptLanguage::Perl | ScriptLanguage::Unknown => None,
    }
}

// ============================================================================
// Match refinement (payload / path analysis)
// ============================================================================

#[derive(Debug)]
struct RefinedMatchMeta {
    rule_id: String,
    reason: String,
    severity: Severity,
    suggestion: Option<String>,
}

static JS_RECURSIVE_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\brecursive\s*:\s*true\b").expect("js recursive:true regex compiles")
});

static JS_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches the arguments of execSync("...") / exec('...') / exec(`...`) -- the
    // calls that take one shell string. The child_process regexes read a template
    // by its raw text, which may span lines; a `${..}` stays in it as an opaque
    // word, so `/var/lib/${app}` is judged as `"/var/lib/" + app` already is
    // (.agent-config-crqi7).
    Regex::new(r#"^\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|`(?P<bq>[^`]*)`)"#)
        .expect("js exec/execSync literal regex compiles")
});

static JS_REQUIRE_CHILD_PROCESS_RECEIVER: LazyLock<Regex> = LazyLock::new(|| {
    // Matches a call whose receiver is `require('child_process')` / `require("node:child_process")`.
    Regex::new(
        r#"^\s*require\s*\(\s*(?:'(?:node:)?child_process'|"(?:node:)?child_process")\s*\)\s*\.\s*execSync\b"#,
    )
        .expect("js require(child_process) receiver regex compiles")
});

/// The rule id for an `execSync` match (.agent-config-w9pvb).
///
/// One pattern reads every receiver. `require('child_process').execSync(..)` had a
/// pattern of its own, and allowlists name its id, so that receiver keeps it.
/// Whatever this returns, the call was matched and is judged. The name still
/// matters: allowlists and `[policy.rules]` match on it, so a misread spelling
/// can change a verdict under such config, never without it.
fn execsync_rule_id(rule_id: &str, matched_text: &str) -> String {
    match rule_id.strip_suffix(".execsync") {
        Some(pack) if JS_REQUIRE_CHILD_PROCESS_RECEIVER.is_match(matched_text) => {
            format!("{pack}.require_execsync")
        }
        _ => rule_id.to_string(),
    }
}

static JS_ARGV_CALL_CMD_ARGS: LazyLock<Regex> = LazyLock::new(|| {
    // Matches the arguments of spawnSync("cmd", [ ... ]) / execFile('cmd', [ ... ])
    // -- the calls that take a file and an argv (spawn, spawnSync, execFile,
    // execFileSync). The array consumes strings and comments whole before it
    // looks for its `]`, so one inside them does not end it.
    Regex::new(
        r#"^\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|`(?P<bq>[^`]*)`)\s*,\s*\[(?P<args>(?:"[^"\n]*"|'[^'\n]*'|`[^`]*`|//[^\n]*|/\*(?s:.)*?\*/|[^\]])*)\]"#,
    )
    .expect("js argv call (cmd, [args]) regex compiles")
});

static JS_ARRAY_STRING_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js array string literal regex compiles")
});

static JS_ARGV_ELEMENTS: LazyLock<Regex> = LazyLock::new(|| {
    // The elements of a child_process argv array: string and template literals.
    // The comment alternatives capture nothing: they consume a `//` or `/* */`
    // comment whole, so a quote or backtick inside one is never read as an
    // element (.agent-config-crqi7).
    Regex::new(
        r#"(?m)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|`(?P<bq>[^`]*)`|//[^\n]*|/\*(?s:.)*?\*/)"#,
    )
    .expect("js argv element regex compiles")
});

static JS_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures the first string literal argument in a call expression.
    //
    // Reads from the FIRST open paren in the match, so it is only correct when
    // the call the rule matched is the first call in the text. It stays as the
    // fallback for a match whose call cannot be located; `js_call_arguments`
    // is the reader for everything else (`.agent-config-rmxds`).
    Regex::new(r#"(?m)\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js first string arg regex compiles")
});

/// The member a call pattern names: `$M.rmSync($$$)` and `rmSync($$$)` both
/// give `rmSync`, `Deno.remove($$$)` gives `remove`.
///
/// Derived from the pattern the rule is compiled from, never from a rule_id ->
/// member table: a table is a second source that has to be edited in step with
/// `default_patterns`, and the one that drifts is the one nobody reads
/// (`.claude/rules/structural-coupling.md`).
fn pattern_member(pattern_str: &str) -> Option<&str> {
    let head = pattern_str.split('(').next()?;
    let member = head.rsplit('.').next()?.trim();
    (!member.is_empty()
        && member
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(member)
}

/// The argument text of the `member(..)` call inside `matched_text`, starting
/// just after its open paren.
///
/// The point is what it EXCLUDES. A receiver can carry a string literal of its
/// own -- `require("fs").rmSync("/etc", {recursive: true})` -- and a reader
/// that starts at the first open paren judges `"fs"` as the target path,
/// answers "not catastrophic", and lets the call through. Measured
/// 2026-09-19: that spelling allowed while the `fs.rmSync` spelling denied
/// (`.agent-config-rmxds`).
///
/// Deliberately still LOOSE inside the argument list: the caller takes the
/// first string literal anywhere in it, so `fs.rmSync(path.join("/etc", "x"),
/// {recursive: true})` keeps denying. Narrowing to "the literal must be the
/// first argument" would turn this fix into a weakening; the mutant runner
/// pins that.
fn js_call_arguments<'t>(matched_text: &'t str, member: &str) -> Option<&'t str> {
    let bytes = matched_text.as_bytes();
    let mut from = 0usize;
    while let Some(offset) = matched_text.get(from..)?.find(member) {
        let start = from + offset;
        let end = start + member.len();
        let after_word_char = start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || bytes[start - 1] == b'_'
                || bytes[start - 1] == b'$');
        let rest = matched_text.get(end..)?.trim_start();
        // A trailing `(` is also the boundary on the right: `rmSyncLater(`
        // leaves `Later(` here, which is not a call to `rmSync`.
        if !after_word_char && rest.starts_with('(') {
            let open = matched_text.len() - rest.len();
            return matched_text.get(open + 1..);
        }
        from = end;
    }
    None
}

/// The literal target path a `heredoc.*.fs_*` / `fspromises_*` / `deno_remove`
/// match is about, or `None` when the call takes no string literal.
fn js_literal_target<'t>(meta: &CompiledPattern, matched_text: &'t str) -> Option<&'t str> {
    match pattern_member(&meta.pattern_str)
        .and_then(|member| js_call_arguments(matched_text, member))
    {
        Some(arguments) => JS_ARRAY_STRING_LITERALS
            .captures(arguments)
            .and_then(|caps| string_literal_from_caps(&caps)),
        // The call could not be located in its own match. Read the whole text,
        // exactly as this did before: a wrong path here is a false DENY, and
        // the old reader's failure mode was a false ALLOW.
        None => JS_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps)),
    }
}

static RUBY_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    // - Kernel.system("...") / Kernel.exec("...")
    Regex::new(
        r#"(?m)\b(?:(?:Kernel|Process)\.)?(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("ruby system/exec literal regex compiles")
});

static RUBY_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("ruby backticks regex compiles"));

static RUBY_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures first string literal argument in Ruby call forms:
    // - foo("...") / foo('...')
    // - foo "..."  / foo '...'
    Regex::new(r#"(?m)(?:\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("ruby first string arg regex compiles")
});

fn refine_match_meta(
    language: ScriptLanguage,
    meta: &CompiledPattern,
    matched_text: &str,
) -> Option<RefinedMatchMeta> {
    match language {
        ScriptLanguage::JavaScript => refine_javascript_match(meta, matched_text),
        ScriptLanguage::TypeScript => refine_typescript_match(meta, matched_text),
        // Wrapped here, not inside: the javascript, typescript and ruby
        // refiners can DROP a match (an fs call with no recursive flag is not
        // a finding), and python's cannot -- every subprocess call it is
        // handed keeps at least the Medium meta it arrived with.
        ScriptLanguage::Python => Some(refine_python_match(meta, matched_text)),
        ScriptLanguage::Ruby => refine_ruby_match(meta, matched_text),
        _ => Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        }),
    }
}

fn refine_javascript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.javascript.execsync" | "heredoc.javascript.exec"
    ) {
        let rule_id = execsync_rule_id(rule_id, matched_text);
        // Read from the call's own arguments (rmxds's `js_call_arguments`), so a
        // nested call's literal -- `/x/.exec("y")` inside an `execSync` -- never
        // stands in for them (.agent-config-crqi7).
        let literal = pattern_member(&meta.pattern_str)
            .and_then(|member| js_call_arguments(matched_text, member))
            .and_then(|arguments| {
                let caps = JS_EXEC_LITERAL.captures(arguments)?;
                let rest = &arguments[caps.get(0)?.end()..];
                Some((string_literal_from_caps(&caps)?, rest))
            });

        if let Some((payload, rest)) = literal {
            let hit = detect_shell_payload(payload);
            // A `${..}` may be anything, and so may whatever is concatenated onto
            // the literal (`"npm run " + s`): finding nothing is not a verdict, so
            // the call stays the dynamic match (.agent-config-crqi7).
            let whole = rest.trim_start().starts_with([',', ')']);
            if hit.is_some() || (whole && !payload.contains("${")) {
                return hit.map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }
        }

        // Dynamic payloads: warn only (fail-open).
        return Some(RefinedMatchMeta {
            rule_id,
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    if matches!(
        rule_id,
        "heredoc.javascript.spawnsync"
            | "heredoc.javascript.spawn"
            | "heredoc.javascript.execfilesync"
            | "heredoc.javascript.execfile"
    ) {
        if let Some((caps, rest)) = pattern_member(&meta.pattern_str)
            .and_then(|member| js_call_arguments(matched_text, member))
            .and_then(|arguments| {
                let caps = JS_ARGV_CALL_CMD_ARGS.captures(arguments)?;
                let rest = &arguments[caps.get(0)?.end()..];
                Some((caps, rest))
            })
        {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let array = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARGV_ELEMENTS
                .captures_iter(array)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            let hit = detect_spawn_argv(cmd, &args);
            // A word holding a `${..}`, an element that is not a literal at all (a
            // variable, a spread, a call), or anything applied to the array after
            // its `]` (`["-rf"].concat(dirs)`) may be anything: finding nothing is
            // not a verdict, so the call stays the dynamic match
            // (.agent-config-crqi7).
            let whole = rest.trim_start().starts_with([',', ')']);
            let dynamic = !whole
                || std::iter::once(cmd)
                    .chain(args.iter().copied())
                    .any(|word| word.contains("${"))
                || JS_ARGV_ELEMENTS
                    .replace_all(array, "")
                    .contains(|c: char| !c.is_whitespace() && c != ',');
            if hit.is_some() || !dynamic {
                return hit.map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }
        }

        // Dynamic spawnSync: warn only.
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.javascript.fs_")
        || rule_id.starts_with("heredoc.javascript.fspromises_")
    {
        let path = js_literal_target(meta, matched_text);

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        // For fs.rm* / fs.rmdir* we only care about recursive deletion (or catastrophic literal paths).
        let needs_recursive = matches!(
            rule_id,
            "heredoc.javascript.fs_rmsync"
                | "heredoc.javascript.fs_rmdirsync"
                | "heredoc.javascript.fs_rm"
                | "heredoc.javascript.fs_rmdir"
                | "heredoc.javascript.fspromises_rm"
                | "heredoc.javascript.fspromises_rmdir"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_typescript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.typescript.execsync" | "heredoc.typescript.exec"
    ) {
        let rule_id = execsync_rule_id(rule_id, matched_text);
        // Read from the call's own arguments (rmxds's `js_call_arguments`), so a
        // nested call's literal -- `/x/.exec("y")` inside an `execSync` -- never
        // stands in for them (.agent-config-crqi7).
        let literal = pattern_member(&meta.pattern_str)
            .and_then(|member| js_call_arguments(matched_text, member))
            .and_then(|arguments| {
                let caps = JS_EXEC_LITERAL.captures(arguments)?;
                let rest = &arguments[caps.get(0)?.end()..];
                Some((string_literal_from_caps(&caps)?, rest))
            });

        if let Some((payload, rest)) = literal {
            let hit = detect_shell_payload(payload);
            // A `${..}` may be anything, and so may whatever is concatenated onto
            // the literal (`"npm run " + s`): finding nothing is not a verdict, so
            // the call stays the dynamic match (.agent-config-crqi7).
            let whole = rest.trim_start().starts_with([',', ')']);
            if hit.is_some() || (whole && !payload.contains("${")) {
                return hit.map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }
        }

        return Some(RefinedMatchMeta {
            rule_id,
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if matches!(
        rule_id,
        "heredoc.typescript.spawnsync"
            | "heredoc.typescript.spawn"
            | "heredoc.typescript.execfilesync"
            | "heredoc.typescript.execfile"
    ) {
        if let Some((caps, rest)) = pattern_member(&meta.pattern_str)
            .and_then(|member| js_call_arguments(matched_text, member))
            .and_then(|arguments| {
                let caps = JS_ARGV_CALL_CMD_ARGS.captures(arguments)?;
                let rest = &arguments[caps.get(0)?.end()..];
                Some((caps, rest))
            })
        {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let array = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARGV_ELEMENTS
                .captures_iter(array)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            let hit = detect_spawn_argv(cmd, &args);
            // A word holding a `${..}`, an element that is not a literal at all (a
            // variable, a spread, a call), or anything applied to the array after
            // its `]` (`["-rf"].concat(dirs)`) may be anything: finding nothing is
            // not a verdict, so the call stays the dynamic match
            // (.agent-config-crqi7).
            let whole = rest.trim_start().starts_with([',', ')']);
            let dynamic = !whole
                || std::iter::once(cmd)
                    .chain(args.iter().copied())
                    .any(|word| word.contains("${"))
                || JS_ARGV_ELEMENTS
                    .replace_all(array, "")
                    .contains(|c: char| !c.is_whitespace() && c != ',');
            if hit.is_some() || !dynamic {
                return hit.map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.typescript.fs_")
        || rule_id.starts_with("heredoc.typescript.fspromises_")
        || rule_id == "heredoc.typescript.deno_remove"
    {
        let path = js_literal_target(meta, matched_text);

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        let needs_recursive = matches!(
            rule_id,
            "heredoc.typescript.fs_rmsync"
                | "heredoc.typescript.fs_rmdirsync"
                | "heredoc.typescript.fs_rm"
                | "heredoc.typescript.fs_rmdir"
                | "heredoc.typescript.fspromises_rm"
                | "heredoc.typescript.fspromises_rmdir"
                | "heredoc.typescript.deno_remove"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_ruby_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.ruby.system"
            | "heredoc.ruby.exec"
            | "heredoc.ruby.kernel_system"
            | "heredoc.ruby.kernel_exec"
            | "heredoc.ruby.backticks"
            | "heredoc.ruby.open3_capture3"
            | "heredoc.ruby.open3_popen3"
    ) {
        let payload = if rule_id == "heredoc.ruby.backticks" {
            RUBY_BACKTICKS_LITERAL
                .captures(matched_text)
                .and_then(|caps| caps.name("cmd").map(|m| m.as_str()))
        } else if rule_id.starts_with("heredoc.ruby.open3_") {
            // Open3 methods take the command as first argument
            RUBY_FIRST_STRING_ARG
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        } else {
            RUBY_SYSTEM_EXEC_LITERAL
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        };

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        // Dynamic system/exec/backticks/Open3: warn only (couldn't extract literal command).
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.ruby.fileutils_")
        || rule_id.starts_with("heredoc.ruby.file_")
        || rule_id.starts_with("heredoc.ruby.dir_")
    {
        let path = RUBY_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        let catastrophic = path.is_some_and(is_catastrophic_path);
        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

/// The first argument of a python call, when that argument is a LIST literal.
///
/// `[^\]]*` spans newlines, so a list broken across lines is still read.
/// An unmatched call falls back to the pattern's own Medium meta -- the
/// behaviour before this rule existed.
///
/// The list ends at the FIRST `]`, whatever opened it: a nested list matches,
/// truncated there, and an element holding a subscript (`os.environ["X"]`,
/// `sys.argv[1]`) ends the list before the words after it are ever read
/// (.agent-config-xyi3s).
static PY_CALL_ARGV_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*\[(?P<items>[^\]]*)\]").expect("python argv list regex compiles")
});

/// A single-line python string literal. Deliberately separate from the
/// JavaScript one: python's literal grammar is its own (prefixes, triple
/// quotes), and the two must be free to diverge.
static PY_STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("python string literal regex compiles")
});

/// The string literals of the first argument, when that argument is a list.
///
/// What comes back is the literal SKELETON of the argv, not the argv: an
/// element that is not a literal -- a variable, a call, a join -- cannot be
/// read here and is simply absent. That is deliberate, because a composed
/// target still names itself (`os.path.join("/srv", "data")` yields `/srv`),
/// and a guard that reads less than it could is the defect this rule exists
/// to fix. `None` only when there is no list, or nothing literal inside it.
///
/// The HEAD is no exception (.agent-config-dcg-argv-command-head-dxnfo): in
/// `[tool, <rm>, <-rf>, "/srv"]` the unread head is absent and the words after
/// it are judged, which is the verdict the shell pack gives the same words as
/// text (`"$TOOL" <rm> <-rf> /srv` denies, `"$TOOL" <-rf> /srv` allows).
/// Bailing out on an unreadable head would make the list spelling of that
/// command weaker than its string spelling again.
///
/// The skeleton comes back with a second, POSITIONAL reading
/// (.agent-config-2uqwz): one word per list element -- the literal when the
/// element is one, [`PY_UNREAD_ELEMENT`] when it is not -- so the words after
/// an unread element keep their place. In `["sudo", "-u", user, <rm>, ...]`
/// the skeleton hands `<rm>` to `-u` as its value; the positional reading does
/// not. A literal nested in an element (`os.environ.get("SUDO_USER", "root")`)
/// is part of that element: the skeleton reads it, the positional reading
/// counts the element once. Neither reading is right alone -- in
/// `["env", spec, <rm>, ...]` the stand-in is what `env` would run, so only
/// the skeleton finds `<rm>` -- and the caller judges both, as
/// [`detect_spawn_argv`] does its two readings. Only elements BETWEEN literals
/// get a stand-in: a leading one is the head, decided above, and a trailing
/// one has nothing after it to move.
///
/// Elements are counted by the list-level commas between two list-level
/// literals, less the one that separates neighbours; a comma or a literal
/// inside a bracket is a call's, not the list's. The depth runs across the
/// whole list and never goes below the list's own, so a stray closer cannot
/// underflow it.
fn python_argv_list(matched_text: &str) -> Option<(Vec<&str>, Vec<&str>)> {
    let caps = PY_CALL_ARGV_LIST.captures(matched_text)?;
    let items = caps.name("items")?.as_str();

    let mut skeleton = Vec::new();
    let mut positional = Vec::new();
    let mut depth = 0_usize;
    let mut commas = 0_usize;
    let mut previous_end = 0;
    for caps in PY_STRING_LITERAL.captures_iter(items) {
        let (Some(whole), Some(literal)) = (caps.get(0), string_literal_from_caps(&caps)) else {
            continue;
        };
        for c in items[previous_end..whole.start()].chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => commas += 1,
                _ => {}
            }
        }
        previous_end = whole.end();
        skeleton.push(literal);
        if depth == 0 {
            if !positional.is_empty() {
                let unread = commas.saturating_sub(1);
                positional.extend(std::iter::repeat_n(PY_UNREAD_ELEMENT, unread));
            }
            positional.push(literal);
            commas = 0;
        }
    }

    if skeleton.is_empty() {
        None
    } else {
        Some((skeleton, positional))
    }
}

/// Stands in for a list element that is not a literal. Empty, so it is never
/// a flag, a `NAME=value`, a wrapper or a destructive command: as a command
/// word it judges nothing. As a delete's TARGET it is not a catastrophic path
/// either, so the worst it can reach is the non-blocking `rm_rf`.
const PY_UNREAD_ELEMENT: &str = "";

/// Upgrade a `subprocess` call that was handed a destructive argv.
///
/// `subprocess.run($$$)` is deliberately Medium: "do not block on shell=True
/// alone". But the STRING form of the same call carries its command as
/// contiguous shell text, which the filesystem pack already denies, while the
/// LIST form hides it in separate literals that no pack can see -- so the
/// SAFER spelling of the call was the one that got through
/// (.agent-config-ei4it).
///
/// The list is handed to [`detect_command_words`], which judges ONE command
/// whose words are already separated. That is the whole reason it is the right
/// reader here: an argv list goes to execve, not to a shell, so it must not be
/// re-joined into text and split again on metacharacters it never had -- a
/// semicolon inside an element is a character in an argument and starts no
/// second command. Both readings [`python_argv_list`] gives are judged, and the
/// more severe hit decides; the skeleton goes first, so among equals the
/// verdict is the one this rule gave before the positional reading existed.
fn refine_python_match(meta: &CompiledPattern, matched_text: &str) -> RefinedMatchMeta {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.python.subprocess_run"
            | "heredoc.python.subprocess_call"
            | "heredoc.python.subprocess_popen"
    ) {
        if let Some(hit) = python_argv_list(matched_text).and_then(|(skeleton, positional)| {
            strongest_hit([
                detect_command_words(skeleton.iter().copied()),
                detect_command_words(positional.iter().copied()),
            ])
        }) {
            return RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            };
        }
    }

    RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    }
}

// ============================================================================
// Perl regex fallback ast_matcher (git_safety_guard-2d4)
// ============================================================================

static PERL_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    //
    // We intentionally only match *simple single-line* string literals to keep signal high.
    Regex::new(
        r#"(?m)\b(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("perl system/exec literal regex compiles")
});

static PERL_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("perl backticks regex compiles"));

static PERL_QX_SLASH_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches qx/.../ (slash delimiter only, v1).
    Regex::new(r"(?m)\bqx\s*/(?P<cmd>(?:\\.|[^/\n])*)/").expect("perl qx// regex compiles")
});

static PERL_FILE_PATH_RMTREE_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // The `File::Path::` qualifier is OPTIONAL, because the documented way to
    // call these is to import them: `use File::Path qw(rmtree); rmtree($dir)`.
    // Requiring the qualifier read the one spelling nobody writes and allowed
    // the one everybody does (.agent-config-ei4it).
    //
    // An unqualified `rmtree`/`remove_tree` from some other module matches too,
    // and that is the intent: the name is the behaviour. A non-catastrophic
    // target is still only Medium, so ordinary build-directory cleanup warns
    // rather than denies -- the same bar the qualified form already met.
    Regex::new(
        r#"(?m)\b(?P<qual>File::Path::)?(?P<fn>rmtree|remove_tree)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("perl File::Path rmtree/remove_tree regex compiles")
});

static PERL_UNLINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\bunlink\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl unlink regex compiles")
});

static PERL_RMDIR_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\brmdir\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl rmdir regex compiles")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PerlShellCall {
    System,
    Exec,
    Backticks,
    Qx,
}

impl PerlShellCall {
    #[must_use]
    const fn id_prefix(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Exec => "exec",
            Self::Backticks => "backticks",
            Self::Qx => "qx",
        }
    }
}

#[derive(Clone, Copy)]
enum PerlCommentState {
    Normal,
    Single,
    Double,
    Backtick,
}

fn find_matches_perl(
    code: &str,
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<Vec<PatternMatch>, MatchError> {
    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();
    let masked = mask_perl_comments(code);
    let haystack = masked.as_ref();

    let mut matches = Vec::new();

    scan_perl_system_exec(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_backticks(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_qx(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_file_path(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_unlink_rmdir(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;

    Ok(matches)
}

#[inline]
fn perl_check_timeout(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    if start_time.elapsed() > timeout {
        let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        return Err(MatchError::Timeout {
            elapsed_ms,
            budget_ms,
        });
    }
    Ok(())
}

fn scan_perl_system_exec(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_SYSTEM_EXEC_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };

        let call = caps.name("call").map_or("", |m| m.as_str());
        let call = match call {
            "system" => PerlShellCall::System,
            "exec" => PerlShellCall::Exec,
            _ => continue,
        };

        let Some(payload) = string_literal_from_caps(&caps) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            call,
            payload,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_backticks(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_BACKTICKS_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Backticks,
            payload,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_qx(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_QX_SLASH_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Qx,
            unescape_perl_qx_payload(payload).as_ref(),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn unescape_perl_qx_payload(payload: &str) -> std::borrow::Cow<'_, str> {
    if payload.contains("\\/") {
        return std::borrow::Cow::Owned(payload.replace("\\/", "/"));
    }
    std::borrow::Cow::Borrowed(payload)
}

fn scan_perl_file_path(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_FILE_PATH_RMTREE_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(path) = string_literal_from_caps(&caps) else {
            continue;
        };
        let fn_name = caps.name("fn").map_or("rmtree", |m| m.as_str());

        // The rule id is the FUNCTION, so the qualified and imported spellings
        // are one rule and an allowlist written for either covers both. Only
        // the reason names the spelling that was actually read, so it cannot
        // claim a `File::Path::` prefix that was not in the body.
        let display = caps.name("qual").map_or_else(
            || fn_name.to_string(),
            |qual| format!("{}{fn_name}", qual.as_str()),
        );

        let severity = if is_catastrophic_path(path) {
            Severity::Critical
        } else {
            Severity::Medium
        };

        let rule_id = format!("heredoc.perl.file_path.{fn_name}");
        let reason = format!("{display}() recursively deletes directories");

        push_regex_match(
            out,
            code,
            newline_positions,
            &rule_id,
            &reason,
            severity,
            Some("Verify target path carefully before running".to_string()),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_unlink_rmdir(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_UNLINK_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        // Only match string-literal unlink; severity is warn-only by default.
        push_regex_match(
            out,
            code,
            newline_positions,
            "heredoc.perl.unlink",
            "unlink() deletes files",
            Severity::Low,
            None,
            m.start(),
            m.end(),
        );
    }

    for caps in PERL_RMDIR_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        push_regex_match(
            out,
            code,
            newline_positions,
            "heredoc.perl.rmdir",
            "rmdir() deletes directories",
            Severity::Low,
            None,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn mask_perl_comments(code: &str) -> std::borrow::Cow<'_, str> {
    if !code.as_bytes().contains(&b'#') {
        return std::borrow::Cow::Borrowed(code);
    }

    let mut out = code.as_bytes().to_vec();
    let mut state = PerlCommentState::Normal;
    let mut i = 0usize;

    while i < out.len() {
        match state {
            PerlCommentState::Normal => match out[i] {
                b'#' => {
                    // Mask until newline (keep newline itself).
                    let start = i;
                    while i < out.len() && out[i] != b'\n' {
                        i += 1;
                    }
                    for b in &mut out[start..i] {
                        *b = b' ';
                    }
                }
                b'\'' => {
                    state = PerlCommentState::Single;
                    i += 1;
                }
                b'"' => {
                    state = PerlCommentState::Double;
                    i += 1;
                }
                b'`' => {
                    state = PerlCommentState::Backtick;
                    i += 1;
                }
                _ => i += 1,
            },
            PerlCommentState::Single => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'\'' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Double => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'"' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Backtick => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'`' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_or(std::borrow::Cow::Borrowed(code), std::borrow::Cow::Owned)
}

fn string_literal_from_caps<'t>(caps: &regex::Captures<'t>) -> Option<&'t str> {
    caps.name("dq")
        .or_else(|| caps.name("sq"))
        .or_else(|| caps.name("bq"))
        .map(|m| m.as_str())
}

fn push_perl_shell_payload_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    call: PerlShellCall,
    payload: &str,
    start: usize,
    end: usize,
) {
    let Some(hit) = detect_shell_payload(payload) else {
        return;
    };

    let rule_id = format!("heredoc.perl.{}.{}", call.id_prefix(), hit.rule_suffix);
    push_regex_match(
        out,
        code,
        newline_positions,
        &rule_id,
        hit.reason,
        hit.severity,
        hit.suggestion.map(str::to_string),
        start,
        end,
    );
}

struct ShellPayloadHit {
    rule_suffix: &'static str,
    reason: &'static str,
    severity: Severity,
    suggestion: Option<&'static str>,
}

/// Judge a `spawnSync(cmd, [args], ..)` call (.agent-config-w9pvb).
///
/// Read twice, and the most severe hit of either reading decides
/// (`strongest_hit`). As WORDS, the way the argv runs with no
/// shell: `/bin/rm`, `/usr/bin/env` and an `sh -c <script>` are read. As the
/// JOINED line, the way node runs it under `{ shell: true }` -- which a cast, a
/// comment or an options variable can hide from a text check -- and the only
/// reading this rule had before. The joined reading is unconditional so that no
/// call it denied is ever allowed: every attempt to skip it (a words-only
/// argv, then a guess at whether an options argument follows) reopened a call
/// the old rule denied. The price: a `;` inside one argv element can still
/// over-block, as in any shell string (.agent-config-fqbws).
fn detect_spawn_argv(cmd: &str, args: &[&str]) -> Option<ShellPayloadHit> {
    let words = std::iter::once(cmd).chain(args.iter().copied());
    let line: Vec<&str> = std::iter::once(cmd).chain(args.iter().copied()).collect();
    strongest_hit([
        detect_command_words(words),
        detect_shell_payload(&line.join(" ")),
    ])
}

/// The verdict of several readings: the MOST SEVERE hit, the first among equals.
/// A less severe hit must never hide a more severe one after it -- in a later
/// segment of a shell line, or in the other reading of a spawn argv
/// (.agent-config-w9pvb). Not merely the first blocking hit: a policy warn can
/// downgrade a high hit but never a critical one, so an earlier high must not
/// replace the critical the old first-hit reading returned. That old hit is
/// always among these candidates, so the result is never less severe than it.
fn strongest_hit<I>(hits: I) -> Option<ShellPayloadHit>
where
    I: IntoIterator<Item = Option<ShellPayloadHit>>,
{
    const fn rank(severity: Severity) -> u8 {
        match severity {
            Severity::Critical => 3,
            Severity::High => 2,
            Severity::Medium => 1,
            Severity::Low => 0,
        }
    }
    let mut best: Option<ShellPayloadHit> = None;
    for hit in hits.into_iter().flatten() {
        if best
            .as_ref()
            .is_none_or(|b| rank(hit.severity) > rank(b.severity))
        {
            best = Some(hit);
        }
    }
    best
}

fn detect_shell_payload(payload: &str) -> Option<ShellPayloadHit> {
    strongest_hit(
        payload
            .split(&[';', '\n', '|', '&'][..])
            .map(|segment| detect_command_words(segment.split_whitespace())),
    )
}

/// Judge ONE command, given as its words (a shell segment split on whitespace,
/// or a spawn argv as-is).
///
/// Wrappers (`sudo`, `env`, `command`, by any path) are skipped with the flags
/// `next_shell_command` knows -- a wrapper flag taking a value it does not know
/// (`env -u X`) still hides the command (.agent-config-ok70w). The command word is
/// compared by basename (`/bin/rm` is `rm`), and `sh -c <script>` judges the
/// script as a shell string (.agent-config-w9pvb).
fn detect_command_words<'a, I>(words: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let mut words = words.peekable();
    let cmd = next_shell_command(&mut words)?;
    match cmd.rsplit('/').next().unwrap_or(cmd) {
        "git" => detect_git_destructive(words),
        "rm" => detect_rm_rf_destructive(words),
        "sh" | "bash" | "zsh" | "dash" => match (words.next(), words.next()) {
            (Some("-c"), Some(script)) => detect_shell_payload(script),
            _ => None,
        },
        _ => None,
    }
}

fn detect_git_destructive<'a, I>(tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    // The subcommand is the first word after git's global options and their
    // values: `git -C <dir> reset --hard` read `-C` as the subcommand and let
    // every argv spelled that way through (.agent-config-5cw2y). A
    // value-taking option is read both ways, owning the next word and not,
    // because an argv element that is not a literal is dropped before this
    // reads it: `["-C", dir, "reset", "--hard"]` arrives as `-C reset --hard`.
    // Every word a reading reaches is judged as the subcommand, and the most
    // severe hit decides. A word is judged once, where it is first reached:
    // what follows it there includes what follows any later copy, so a later
    // copy adds no hit -- and judging every copy was quadratic.
    let words: Vec<&str> = tokens.collect();
    let mut reached = vec![false; words.len() + 2];
    reached[0] = true;
    let mut judged = HashSet::new();
    let mut hits = Vec::new();
    for (i, word) in words.iter().enumerate() {
        if !reached[i] {
            continue;
        }
        if word.starts_with('-') {
            reached[i + 1] = true;
            reached[i + 2] |= git_global_option_takes_value(word);
        } else if judged.insert(*word) {
            hits.push(detect_git_subcommand(word, words[i + 1..].iter().copied()));
        }
    }
    strongest_hit(hits)
}

/// Judge one git subcommand by the words after it.
///
/// Must stay monotone in those words: more of them never remove a hit.
/// `detect_git_destructive` judges a word once, where it is first reached,
/// and relies on it -- a veto such as a dry-run `-n` would need that dedupe
/// dropped or rekeyed (`.agent-config-g5xom`).
fn detect_git_subcommand<'a, I>(sub: &str, mut tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    if sub == "reset" {
        if tokens.any(|t| t == "--hard") {
            return Some(ShellPayloadHit {
                rule_suffix: "git_reset_hard",
                reason: "git reset --hard destroys uncommitted changes",
                severity: Severity::High,
                suggestion: Some("Use 'git stash' first, or prefer safer alternatives"),
            });
        }
        return None;
    }

    if sub == "clean" {
        let mut has_f = false;
        let mut has_d = false;

        for t in tokens {
            if t == "--force" {
                has_f = true;
                continue;
            }
            if t == "--dry-run" || t == "-n" {
                continue;
            }
            if t.starts_with('-') {
                let flags = t.trim_start_matches('-');
                has_f |= flags.contains('f');
                has_d |= flags.contains('d');
            }
        }

        if has_f && has_d {
            return Some(ShellPayloadHit {
                rule_suffix: "git_clean_fd",
                reason: "git clean -fd permanently deletes untracked files",
                severity: Severity::High,
                suggestion: Some("Use 'git clean -n' first to preview deletions"),
            });
        }
    }

    None
}

fn detect_rm_rf_destructive<'a, I>(tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let mut has_r = false;
    let mut has_f = false;
    let mut target: Option<&str> = None;
    let mut options_ended = false;

    for token in tokens {
        if !options_ended && token == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && token.starts_with('-') {
            if token == "--recursive" {
                has_r = true;
                continue;
            }
            if token == "--force" {
                has_f = true;
                continue;
            }

            let flags = token.trim_start_matches('-');
            has_r |= flags.chars().any(|c| matches!(c, 'r' | 'R'));
            has_f |= flags.contains('f');
            continue;
        }

        target = Some(token);
        break;
    }

    if !has_r || !has_f {
        return None;
    }

    let target = clean_path_token(target?);
    let catastrophic = is_catastrophic_path(target);

    Some(ShellPayloadHit {
        rule_suffix: if catastrophic {
            "rm_rf_catastrophic"
        } else {
            "rm_rf"
        },
        reason: if catastrophic {
            "rm -rf recursively deletes files/directories (catastrophic target path)"
        } else {
            "rm -rf recursively deletes files/directories"
        },
        severity: if catastrophic {
            Severity::Critical
        } else {
            Severity::Medium
        },
        suggestion: Some("Verify the target path and use safer alternatives when possible"),
    })
}

fn next_shell_command<'a, I>(tokens: &mut std::iter::Peekable<I>) -> Option<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    loop {
        let token = tokens.next()?;
        // By basename, so `/usr/bin/env` and `/usr/bin/sudo` are wrappers too.
        match token.rsplit('/').next().unwrap_or(token) {
            "sudo" => {
                while let Some(&next) = tokens.peek() {
                    if !next.starts_with('-') {
                        break;
                    }
                    let flag = tokens.next().unwrap_or_default();
                    if matches!(flag, "-u" | "-g" | "-h") {
                        let _ = tokens.next();
                    }
                }
            }
            "command" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            "env" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') || next.contains('=') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            _ => return Some(token),
        }
    }
}

fn clean_path_token(token: &str) -> &str {
    let token = token.trim_matches(|c: char| c == '"' || c == '\'');
    token.trim_end_matches(&[';', ',', ')', ']', '}'][..])
}

/// Check if a path contains `..` as an actual path component (not in a filename).
///
/// Examples:
/// - `/tmp/../etc` → true (path traversal)
/// - `/tmp/foo..bar` → false (dots in filename, not traversal)
/// - `../etc` → true (relative path traversal)
fn contains_path_traversal(path: &str) -> bool {
    // Check for `..` as a path segment: `/../`, `/..` at end, `../` at start, or exactly `..`
    path.contains("/../") || path.ends_with("/..") || path.starts_with("../") || path == ".."
}

fn has_path_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    // It starts with prefix. It's a match if exact match OR next char is separator.
    path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

fn is_catastrophic_path(path: &str) -> bool {
    // Root or home always catastrophic
    if matches!(path, "/" | "~") || path.starts_with("~/") {
        return true;
    }

    // Temp directories are safe UNLESS they contain path traversal.
    // Path traversal can escape temp directories (e.g., /tmp/../etc -> /etc).
    if has_path_prefix(path, "/tmp") || has_path_prefix(path, "/var/tmp") {
        return contains_path_traversal(path);
    }

    // Standard catastrophic system paths
    let sys_dirs = [
        "/etc", "/home", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/boot", "/root",
        "/opt", "/sys", "/proc", "/dev", "/mnt", "/media", "/srv", "/run",
    ];

    sys_dirs.iter().any(|&dir| has_path_prefix(path, dir))
}

#[allow(clippy::too_many_arguments)]
fn push_regex_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    rule_id: &str,
    reason: &str,
    severity: Severity,
    suggestion: Option<String>,
    start: usize,
    end: usize,
) {
    let line_number = newline_positions.partition_point(|&idx| idx < start) + 1;
    let matched_text = code.get(start..end).unwrap_or("");
    let preview = truncate_preview(matched_text, 60);

    out.push(PatternMatch {
        rule_id: rule_id.to_string(),
        reason: reason.to_string(),
        matched_text_preview: preview,
        start,
        end,
        line_number,
        severity,
        suggestion,
    });
}

/// What this body's own imports bind, for [`BindingGate`].
///
/// Read from the parsed tree, not from the text, so an import spelled inside a
/// comment or a string binds nothing.
#[derive(Debug, Default)]
struct ModuleBindings {
    /// Local receiver name -> canonical module (`sh` -> `shutil`, `f` -> `fs`).
    receivers: HashMap<String, String>,
    /// Local call name -> (canonical module, the member that was imported).
    ///
    /// The member is kept because `from shutil import copy as rmtree` binds
    /// the NAME `rmtree` to something harmless; only the pair decides.
    bare: HashMap<String, (String, String)>,
    /// Modules imported wholesale (`from shutil import *`).
    wildcards: HashSet<String>,
    /// Names a python body binds with a plain `import X` (`import os.path`
    /// binds `os`). The name IS the module, so this only matters when the same
    /// name is ALSO aliased to something else; see [`gate_admits`].
    plain_imports: HashSet<String>,
}

static INLINE_REQUIRE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^require\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')\s*\)$"#)
        .expect("inline require regex compiles")
});

static REQUIRED_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    // `require("x").member` -- the older way to take one export (.agent-config-crqi7).
    Regex::new(
        r#"^require\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')\s*\)\s*\.\s*(?P<member>[A-Za-z_$][\w$]*)$"#,
    )
    .expect("required member regex compiles")
});

/// The module and member of a `require("x").member` expression, if that is all
/// the text is.
fn required_member_from_text(text: &str) -> Option<(String, String)> {
    let caps = REQUIRED_MEMBER.captures(text.trim())?;
    let raw = caps.name("dq").or_else(|| caps.name("sq"))?.as_str();
    Some((
        normalize_module(raw),
        caps.name("member")?.as_str().to_string(),
    ))
}

/// `node:fs` and `fs` are the same module; `fs/promises` is not.
fn normalize_module(raw: &str) -> String {
    raw.trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches("node:")
        .to_string()
}

/// The module of a `require("x")` expression, if that is all the text is.
fn require_module_from_text(text: &str) -> Option<String> {
    let caps = INLINE_REQUIRE.captures(text.trim())?;
    let raw = caps
        .name("dq")
        .or_else(|| caps.name("sq"))
        .map(|m| m.as_str())?;
    Some(normalize_module(raw))
}

/// Whether the body's imports admit this match under `gate`.
fn gate_admits<D: Doc>(
    gate: BindingGate,
    node: &NodeMatch<'_, D>,
    bindings: &ModuleBindings,
) -> bool {
    match gate {
        BindingGate::None => true,
        BindingGate::Receiver { module, receiver } => {
            // `$M` is the receiver the pattern widened. No binding, no match:
            // that is the whole point of the gate.
            let Some(matched) = node.get_env().get_match("M") else {
                return false;
            };
            let text = matched.text();
            let text = text.trim();
            // Binding first, and that order is not a preference: a name the
            // body BINDS resolves to exactly one module, so exactly one rule
            // can own the call. Reading the literal receiver first would let
            // `const fs = require("fs/promises")` match the `fs.rm` rule and
            // the `fsPromises.rm` rule at once, and an allowlist for the id
            // the deny named would still deny under the other
            // (`.agent-config-w9pvb` review round 1).
            //
            // An inline `require("fs")` names its module outright, so it is
            // read first: it cannot also be a local binding. It was held back
            // when this gate landed because the payload refinement then read
            // the receiver's own `"fs"` as the target path and the match
            // refined to medium either way; `js_literal_target` fixed that
            // (`.agent-config-rmxds`), so this line is now load-bearing.
            if let Some(required) = require_module_from_text(text) {
                return required == module;
            }
            if let Some(bound) = bindings.receivers.get(text) {
                // A python body can bind one name both ways, and either may be
                // the one live at the call: `try: import subprocess32 as
                // subprocess / except ImportError: import subprocess`. A plain
                // import of the module this rule names keeps the name that
                // module, so the alias cannot talk the call out of its rule
                // (`.agent-config-dcg-subprocess-module-binding-ehxrb` cold
                // review). JS records no plain imports, so the one-owner
                // property above is untouched.
                return bound == module
                    || (text == module && bindings.plain_imports.contains(module));
            }
            text == receiver
        }
        BindingGate::Bare { module, member } => {
            if let Some((bound, imported)) = bindings.bare.get(member) {
                return bound == module && imported == member;
            }
            bindings.wildcards.contains(module)
        }
    }
}

/// Read every import binding in the body.
///
/// Deliberately NOT read, so a later reader is not told they are: a renamed
/// destructure or `import ... as` whose LOCAL name differs from the member the
/// pattern spells (`from shutil import rmtree as rt; rt(..)`), a receiver that
/// is itself an expression (`fs.promises.rm(..)`), a computed or optional
/// member (`fs?.rmSync`, `fs["rmSync"]`), and TypeScript's
/// `import fs = require("fs")`. Catching those needs a pattern per local name,
/// compiled per body, which this hot path does not have the budget for.
fn collect_bindings<D: Doc>(root: &Node<'_, D>, language: ScriptLanguage) -> ModuleBindings {
    let mut out = ModuleBindings::default();
    match language {
        ScriptLanguage::Python => collect_python_bindings(root, &mut out),
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => {
            collect_js_bindings(root, &mut out);
        }
        _ => {}
    }
    out
}

fn collect_python_bindings<D: Doc>(root: &Node<'_, D>, out: &mut ModuleBindings) {
    for node in root.dfs() {
        match node.kind().as_ref() {
            // `import shutil as sh`, and plain `import shutil`. The plain one
            // needs no receiver entry -- the receiver the rule names IS the
            // module -- but it is recorded, because the same body may also
            // alias that name to another module.
            "import_statement" => {
                for name in node.field_children("name") {
                    match name.kind().as_ref() {
                        "aliased_import" => {
                            if let (Some(module), Some(alias)) =
                                (name.field("name"), name.field("alias"))
                            {
                                out.receivers.insert(
                                    alias.text().to_string(),
                                    normalize_module(&module.text()),
                                );
                            }
                        }
                        "dotted_name" => {
                            let text = name.text();
                            if let Some(top) = text.split('.').next() {
                                out.plain_imports.insert(top.trim().to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            // `from shutil import rmtree [as rt]`, `from shutil import *`.
            "import_from_statement" => {
                let Some(module_node) = node.field("module_name") else {
                    continue;
                };
                let module = normalize_module(&module_node.text());
                if node
                    .children()
                    .any(|c| c.kind().as_ref() == "wildcard_import")
                {
                    out.wildcards.insert(module.clone());
                }
                for name in node.field_children("name") {
                    match name.kind().as_ref() {
                        "aliased_import" => {
                            if let (Some(member), Some(alias)) =
                                (name.field("name"), name.field("alias"))
                            {
                                out.bare.insert(
                                    alias.text().to_string(),
                                    (module.clone(), member.text().to_string()),
                                );
                            }
                        }
                        "dotted_name" => {
                            let member = name.text().to_string();
                            out.bare.insert(member.clone(), (module.clone(), member));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_js_bindings<D: Doc>(root: &Node<'_, D>, out: &mut ModuleBindings) {
    for node in root.dfs() {
        match node.kind().as_ref() {
            // `const f = require("fs")`, `const { rmSync } = require("fs")`.
            "variable_declarator" => {
                let (Some(name), Some(value)) = (node.field("name"), node.field("value")) else {
                    continue;
                };
                // `var exec = require("child_process").exec`: the member itself,
                // under its local name (.agent-config-crqi7).
                if let Some((module, member)) = required_member_from_text(&value.text()) {
                    if name.kind().as_ref() == "identifier" {
                        out.bare.insert(name.text().to_string(), (module, member));
                    }
                    continue;
                }
                let Some(module) = require_module_from_text(&value.text()) else {
                    continue;
                };
                match name.kind().as_ref() {
                    "identifier" => {
                        out.receivers.insert(name.text().to_string(), module);
                    }
                    "object_pattern" => {
                        for child in name.children() {
                            match child.kind().as_ref() {
                                "shorthand_property_identifier_pattern" => {
                                    let member = child.text().to_string();
                                    out.bare.insert(member.clone(), (module.clone(), member));
                                }
                                "pair_pattern" => {
                                    if let (Some(key), Some(local)) =
                                        (child.field("key"), child.field("value"))
                                    {
                                        out.bare.insert(
                                            local.text().to_string(),
                                            (module.clone(), key.text().to_string()),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            // `import fs from "fs"`, `import * as fs from "fs"`,
            // `import { rmSync as r } from "fs"`.
            "import_statement" => {
                let Some(source) = node.field("source") else {
                    continue;
                };
                let module = normalize_module(&source.text());
                for clause in node
                    .children()
                    .filter(|c| c.kind().as_ref() == "import_clause")
                {
                    for part in clause.children() {
                        match part.kind().as_ref() {
                            "identifier" => {
                                out.receivers
                                    .insert(part.text().to_string(), module.clone());
                            }
                            "namespace_import" => {
                                if let Some(id) =
                                    part.children().find(|c| c.kind().as_ref() == "identifier")
                                {
                                    out.receivers.insert(id.text().to_string(), module.clone());
                                }
                            }
                            "named_imports" => {
                                for spec in part
                                    .children()
                                    .filter(|c| c.kind().as_ref() == "import_specifier")
                                {
                                    let Some(member) = spec.field("name") else {
                                        continue;
                                    };
                                    let member = member.text().to_string();
                                    let local = spec
                                        .field("alias")
                                        .map_or_else(|| member.clone(), |a| a.text().to_string());
                                    out.bare.insert(local, (module.clone(), member));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Default patterns for heredoc scanning.
///
/// These patterns detect destructive operations in embedded scripts.
/// Each pattern has a stable rule ID for allowlisting.
#[allow(clippy::too_many_lines)]
fn default_patterns() -> HashMap<ScriptLanguage, Vec<CompiledPattern>> {
    let mut patterns = HashMap::new();

    // Python patterns
    patterns.insert(
        ScriptLanguage::Python,
        vec![
            // The receiver is a metavariable gated on this body's imports, so
            // `import shutil as sh; sh.rmtree(..)` reads the same as
            // `shutil.rmtree(..)` and an unexplained `x.rmtree(..)` still does
            // not (`.agent-config-artmu`). Same rule id either way.
            CompiledPattern::new(
                "$M.rmtree($$$)".to_string(),
                "heredoc.python.shutil_rmtree".to_string(),
                "shutil.rmtree() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Use shutil.rmtree with explicit path validation".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "shutil",
                receiver: "shutil",
            }),
            CompiledPattern::new(
                "rmtree($$$)".to_string(),
                "heredoc.python.shutil_rmtree".to_string(),
                "shutil.rmtree() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Use shutil.rmtree with explicit path validation".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "shutil",
                member: "rmtree",
            }),
            CompiledPattern::new(
                "$M.remove($$$)".to_string(),
                "heredoc.python.os_remove".to_string(),
                "os.remove() deletes files".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "os",
                receiver: "os",
            }),
            CompiledPattern::new(
                "remove($$$)".to_string(),
                "heredoc.python.os_remove".to_string(),
                "os.remove() deletes files".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "os",
                member: "remove",
            }),
            CompiledPattern::new(
                "$M.rmdir($$$)".to_string(),
                "heredoc.python.os_rmdir".to_string(),
                "os.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "os",
                receiver: "os",
            }),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.python.os_rmdir".to_string(),
                "os.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "os",
                member: "rmdir",
            }),
            CompiledPattern::new(
                "$M.unlink($$$)".to_string(),
                "heredoc.python.os_unlink".to_string(),
                "os.unlink() deletes files".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "os",
                receiver: "os",
            }),
            CompiledPattern::new(
                "unlink($$$)".to_string(),
                "heredoc.python.os_unlink".to_string(),
                "os.unlink() deletes files".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "os",
                member: "unlink",
            }),
            CompiledPattern::new(
                "$M.Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "pathlib",
                receiver: "pathlib",
            }),
            // Also match when Path is imported directly: from pathlib import Path
            CompiledPattern::new(
                "Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "$M.Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "pathlib",
                receiver: "pathlib",
            }),
            // Also match when Path is imported directly
            CompiledPattern::new(
                "Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Shell execution patterns - Medium severity to avoid false positives
            // per bead guidance: "Do not block on shell=True alone"
            //
            // Module-bound the way shutil is
            // (`.agent-config-dcg-subprocess-module-binding-ehxrb`): the python
            // refiner reads a literal argv off these calls and denies a
            // destructive one, so a spelling these patterns cannot see is a
            // deny that does not happen. The bare twins reach further than
            // `rmtree($$$)` -- `run` and `call` are ordinary names -- but the
            // gate admits one only where this body imported that very member
            // from subprocess, and the match stays Medium, which the hook does
            // not act on, unless its literal argv is destructive. The gate
            // reads imports, not scope: a body that imports `run` from
            // subprocess and then defines its own `run` is still read as
            // subprocess. That deny is accepted, and pinned by
            // tests/repro_subprocess_module_binding.rs.
            CompiledPattern::new(
                "$M.run($$$)".to_string(),
                "heredoc.python.subprocess_run".to_string(),
                "subprocess.run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "subprocess",
                receiver: "subprocess",
            }),
            CompiledPattern::new(
                "run($$$)".to_string(),
                "heredoc.python.subprocess_run".to_string(),
                "subprocess.run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "subprocess",
                member: "run",
            }),
            CompiledPattern::new(
                "$M.call($$$)".to_string(),
                "heredoc.python.subprocess_call".to_string(),
                "subprocess.call() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "subprocess",
                receiver: "subprocess",
            }),
            CompiledPattern::new(
                "call($$$)".to_string(),
                "heredoc.python.subprocess_call".to_string(),
                "subprocess.call() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "subprocess",
                member: "call",
            }),
            CompiledPattern::new(
                "$M.Popen($$$)".to_string(),
                "heredoc.python.subprocess_popen".to_string(),
                "subprocess.Popen() spawns shell processes".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "subprocess",
                receiver: "subprocess",
            }),
            CompiledPattern::new(
                "Popen($$$)".to_string(),
                "heredoc.python.subprocess_popen".to_string(),
                "subprocess.Popen() spawns shell processes".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "subprocess",
                member: "Popen",
            }),
            CompiledPattern::new(
                "os.system($$$)".to_string(),
                "heredoc.python.os_system".to_string(),
                "os.system() executes shell commands".to_string(),
                Severity::Medium, // Lowered per bead: avoid "code execution exists" as default deny
                Some("Use subprocess with explicit arguments instead".to_string()),
            ),
            CompiledPattern::new(
                "os.popen($$$)".to_string(),
                "heredoc.python.os_popen".to_string(),
                "os.popen() executes shell commands".to_string(),
                Severity::Medium,
                Some("Use subprocess instead".to_string()),
            ),
        ],
    );

    // JavaScript/Node patterns
    patterns.insert(
        ScriptLanguage::JavaScript,
        vec![
            CompiledPattern::new(
                "$M.rmSync($$$)".to_string(),
                "heredoc.javascript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmSync($$$)".to_string(),
                "heredoc.javascript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmSync",
            }),
            CompiledPattern::new(
                "$M.rmdirSync($$$)".to_string(),
                "heredoc.javascript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmdirSync($$$)".to_string(),
                "heredoc.javascript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmdirSync",
            }),
            CompiledPattern::new(
                "$M.unlinkSync($$$)".to_string(),
                "heredoc.javascript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "unlinkSync($$$)".to_string(),
                "heredoc.javascript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "unlinkSync",
            }),
            // The receiver is whatever the module is bound to (`cp`, `child_process`,
            // `require("child_process")`), or nothing once destructured, so these
            // rules take any receiver and the bare call (.agent-config-w9pvb): naming
            // `child_process` let `cp.spawnSync("rm", ["-rf", "/srv"])` through.
            // Only a destructive literal payload refines to a blocking severity, so
            // the cost is that ANY object's `spawnSync`/`execSync` handed a
            // catastrophic literal now denies; a benign or dynamic call does not.
            //
            // One pattern per call shape, so one call is one match. The
            // `require('child_process')` receiver is named `require_execsync` by
            // `execsync_rule_id`, not by a second pattern: two patterns on one node
            // make an allowlist entry for the reported id insufficient.
            CompiledPattern::new(
                "$M.execSync($$$)".to_string(),
                "heredoc.javascript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execSync($$$)".to_string(),
                "heredoc.javascript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            // Spawn variants
            CompiledPattern::new(
                "$M.spawnSync($$$)".to_string(),
                "heredoc.javascript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "spawnSync($$$)".to_string(),
                "heredoc.javascript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            // The rest of child_process, read the same way (.agent-config-crqi7):
            // execFile/execFileSync/spawn take an argv as spawnSync does, exec takes a
            // shell string as execSync does. Only exec is gated to a child_process
            // binding, because RegExp and db objects share its name; a gated-out exec
            // falls to the core raw-text rules, which read its one shell string but
            // miss spellings this reads (`git reset -q --hard`). An argv call's split
            // literals have no raw-text reader at all, so those stay ungated. Not read: an optional chain
            // (`cp?.spawn`), a computed member (`cp["spawn"]`), a type argument
            // (`spawn<T>(..)`), and any rebinding of the name (`{ spawn: s }`,
            // `import { spawn as s }`, `promisify(cp.execFile)`).
            CompiledPattern::new(
                "$M.execFileSync($$$)".to_string(),
                "heredoc.javascript.execfilesync".to_string(),
                "execFileSync() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execFileSync($$$)".to_string(),
                "heredoc.javascript.execfilesync".to_string(),
                "execFileSync() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.execFile($$$)".to_string(),
                "heredoc.javascript.execfile".to_string(),
                "execFile() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execFile($$$)".to_string(),
                "heredoc.javascript.execfile".to_string(),
                "execFile() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.spawn($$$)".to_string(),
                "heredoc.javascript.spawn".to_string(),
                "spawn() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "spawn($$$)".to_string(),
                "heredoc.javascript.spawn".to_string(),
                "spawn() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.exec($$$)".to_string(),
                "heredoc.javascript.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "child_process",
                receiver: "child_process",
            }),
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.javascript.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "child_process",
                member: "exec",
            }),
            // Async versions (still dangerous)
            CompiledPattern::new(
                "$M.rm($$$)".to_string(),
                "heredoc.javascript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rm($$$)".to_string(),
                "heredoc.javascript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rm",
            }),
            CompiledPattern::new(
                "$M.rmdir($$$)".to_string(),
                "heredoc.javascript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.javascript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmdir",
            }),
            CompiledPattern::new(
                "$M.unlink($$$)".to_string(),
                "heredoc.javascript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "unlink($$$)".to_string(),
                "heredoc.javascript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "unlink",
            }),
            // Promise-based fs variants
            CompiledPattern::new(
                "$M.rm($$$)".to_string(),
                "heredoc.javascript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs/promises",
                receiver: "fsPromises",
            }),
            CompiledPattern::new(
                "rm($$$)".to_string(),
                "heredoc.javascript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs/promises",
                member: "rm",
            }),
            CompiledPattern::new(
                "$M.rmdir($$$)".to_string(),
                "heredoc.javascript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs/promises",
                receiver: "fsPromises",
            }),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.javascript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs/promises",
                member: "rmdir",
            }),
        ],
    );

    // TypeScript patterns (git_safety_guard-26f)
    patterns.insert(
        ScriptLanguage::TypeScript,
        vec![
            CompiledPattern::new(
                "$M.rmSync($$$)".to_string(),
                "heredoc.typescript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmSync($$$)".to_string(),
                "heredoc.typescript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmSync",
            }),
            CompiledPattern::new(
                "$M.rmdirSync($$$)".to_string(),
                "heredoc.typescript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmdirSync($$$)".to_string(),
                "heredoc.typescript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmdirSync",
            }),
            CompiledPattern::new(
                "$M.unlinkSync($$$)".to_string(),
                "heredoc.typescript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "unlinkSync($$$)".to_string(),
                "heredoc.typescript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "unlinkSync",
            }),
            CompiledPattern::new(
                "Deno.remove($$$)".to_string(),
                "heredoc.typescript.deno_remove".to_string(),
                "Deno.remove() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            // Any receiver and the bare call, as for JavaScript (.agent-config-w9pvb).
            CompiledPattern::new(
                "$M.execSync($$$)".to_string(),
                "heredoc.typescript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execSync($$$)".to_string(),
                "heredoc.typescript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.spawnSync($$$)".to_string(),
                "heredoc.typescript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "spawnSync($$$)".to_string(),
                "heredoc.typescript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            // The rest of child_process, as for JavaScript (.agent-config-crqi7).
            CompiledPattern::new(
                "$M.execFileSync($$$)".to_string(),
                "heredoc.typescript.execfilesync".to_string(),
                "execFileSync() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execFileSync($$$)".to_string(),
                "heredoc.typescript.execfilesync".to_string(),
                "execFileSync() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.execFile($$$)".to_string(),
                "heredoc.typescript.execfile".to_string(),
                "execFile() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "execFile($$$)".to_string(),
                "heredoc.typescript.execfile".to_string(),
                "execFile() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.spawn($$$)".to_string(),
                "heredoc.typescript.spawn".to_string(),
                "spawn() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "spawn($$$)".to_string(),
                "heredoc.typescript.spawn".to_string(),
                "spawn() executes commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "$M.exec($$$)".to_string(),
                "heredoc.typescript.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "child_process",
                receiver: "child_process",
            }),
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.typescript.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "child_process",
                member: "exec",
            }),
            CompiledPattern::new(
                "$M.rm($$$)".to_string(),
                "heredoc.typescript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rm($$$)".to_string(),
                "heredoc.typescript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rm",
            }),
            CompiledPattern::new(
                "$M.rmdir($$$)".to_string(),
                "heredoc.typescript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.typescript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "rmdir",
            }),
            CompiledPattern::new(
                "$M.unlink($$$)".to_string(),
                "heredoc.typescript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Receiver {
                module: "fs",
                receiver: "fs",
            }),
            CompiledPattern::new(
                "unlink($$$)".to_string(),
                "heredoc.typescript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            )
            .with_gate(BindingGate::Bare {
                module: "fs",
                member: "unlink",
            }),
            CompiledPattern::new(
                "$M.rm($$$)".to_string(),
                "heredoc.typescript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs/promises",
                receiver: "fsPromises",
            }),
            CompiledPattern::new(
                "rm($$$)".to_string(),
                "heredoc.typescript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs/promises",
                member: "rm",
            }),
            CompiledPattern::new(
                "$M.rmdir($$$)".to_string(),
                "heredoc.typescript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Receiver {
                module: "fs/promises",
                receiver: "fsPromises",
            }),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.typescript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            )
            .with_gate(BindingGate::Bare {
                module: "fs/promises",
                member: "rmdir",
            }),
        ],
    );

    // Ruby patterns (git_safety_guard-mvh)
    patterns.insert(
        ScriptLanguage::Ruby,
        vec![
            // =========================================================================
            // Filesystem Deletion (High Signal)
            // =========================================================================
            CompiledPattern::new(
                "FileUtils.rm_rf($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_rf".to_string(),
                "FileUtils.rm_rf() recursively deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "FileUtils.remove_dir($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_dir".to_string(),
                "FileUtils.remove_dir() deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.rm($$$)".to_string(),
                "heredoc.ruby.fileutils_rm".to_string(),
                "FileUtils.rm() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.remove($$$)".to_string(),
                "heredoc.ruby.fileutils_remove".to_string(),
                "FileUtils.remove() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.delete($$$)".to_string(),
                "heredoc.ruby.file_delete".to_string(),
                "File.delete() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.unlink($$$)".to_string(),
                "heredoc.ruby.file_unlink".to_string(),
                "File.unlink() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.rmdir($$$)".to_string(),
                "heredoc.ruby.dir_rmdir".to_string(),
                "Dir.rmdir() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.delete($$$)".to_string(),
                "heredoc.ruby.dir_delete".to_string(),
                "Dir.delete() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            // =========================================================================
            // Process Execution (Medium severity by default - avoid false positives)
            // =========================================================================
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.ruby.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.ruby.exec".to_string(),
                "exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "`$$$`".to_string(),
                "heredoc.ruby.backticks".to_string(),
                "Backticks execute shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Kernel.system and Kernel.exec variants
            CompiledPattern::new(
                "Kernel.system($$$)".to_string(),
                "heredoc.ruby.kernel_system".to_string(),
                "Kernel.system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "Kernel.exec($$$)".to_string(),
                "heredoc.ruby.kernel_exec".to_string(),
                "Kernel.exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Open3 for shell execution
            CompiledPattern::new(
                "Open3.capture3($$$)".to_string(),
                "heredoc.ruby.open3_capture3".to_string(),
                "Open3.capture3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
            CompiledPattern::new(
                "Open3.popen3($$$)".to_string(),
                "heredoc.ruby.open3_popen3".to_string(),
                "Open3.popen3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
        ],
    );

    // Bash patterns
    patterns.insert(
        ScriptLanguage::Bash,
        vec![
            CompiledPattern::new(
                "rm -rf $$$".to_string(),
                "heredoc.bash.rm_rf".to_string(),
                "rm -rf recursively deletes files/directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "rm -r $$$".to_string(),
                "heredoc.bash.rm_r".to_string(),
                "rm -r recursively deletes".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "git reset --hard".to_string(),
                "heredoc.bash.git_reset_hard".to_string(),
                "git reset --hard discards uncommitted changes".to_string(),
                Severity::Critical,
                Some("Use 'git stash' to save changes first".to_string()),
            ),
            CompiledPattern::new(
                "git clean -fd".to_string(),
                "heredoc.bash.git_clean_fd".to_string(),
                "git clean -fd deletes untracked files".to_string(),
                Severity::High,
                Some("Use 'git clean -n' to preview first".to_string()),
            ),
        ],
    );

    // Go patterns
    patterns.insert(
        ScriptLanguage::Go,
        vec![
            // Recursive deletion - always dangerous
            CompiledPattern::new(
                "os.RemoveAll($$$)".to_string(),
                "heredoc.go.os_removeall".to_string(),
                "os.RemoveAll() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            // File deletion
            CompiledPattern::new(
                "os.Remove($$$)".to_string(),
                "heredoc.go.os_remove".to_string(),
                "os.Remove() deletes files".to_string(),
                Severity::High,
                None,
            ),
            // Shell command execution - medium severity, refined at match time
            CompiledPattern::new(
                "exec.Command($$$)".to_string(),
                "heredoc.go.exec_command".to_string(),
                "exec.Command() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Combined patterns for common usage
            CompiledPattern::new(
                "exec.Command($$$).Run()".to_string(),
                "heredoc.go.exec_command_run".to_string(),
                "exec.Command().Run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "exec.Command($$$).Output()".to_string(),
                "heredoc.go.exec_command_output".to_string(),
                "exec.Command().Output() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "exec.Command($$$).CombinedOutput()".to_string(),
                "heredoc.go.exec_command_combined_output".to_string(),
                "exec.Command().CombinedOutput() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
        ],
    );

    // PHP patterns
    patterns.insert(
        ScriptLanguage::Php,
        vec![
            // File/directory deletion
            CompiledPattern::new(
                "unlink($$$)".to_string(),
                "heredoc.php.unlink".to_string(),
                "unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.php.rmdir".to_string(),
                "rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Shell execution patterns
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.php.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.php.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "shell_exec($$$)".to_string(),
                "heredoc.php.shell_exec".to_string(),
                "shell_exec() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "passthru($$$)".to_string(),
                "heredoc.php.passthru".to_string(),
                "passthru() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "proc_open($$$)".to_string(),
                "heredoc.php.proc_open".to_string(),
                "proc_open() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "popen($$$)".to_string(),
                "heredoc.php.popen".to_string(),
                "popen() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "`$$$`".to_string(),
                "heredoc.php.backticks".to_string(),
                "Backticks execute shell commands in PHP".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
        ],
    );

    patterns
}

/// Global default matcher instance (lazy-initialized).
pub static DEFAULT_MATCHER: LazyLock<AstMatcher> = LazyLock::new(AstMatcher::new);

fn precompile_patterns(
    patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>,
) -> HashMap<ScriptLanguage, Vec<PrecompiledPattern>> {
    let mut out: HashMap<ScriptLanguage, Vec<PrecompiledPattern>> = HashMap::new();

    for (language, patterns) in patterns {
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            continue;
        };

        let mut compiled = Vec::with_capacity(patterns.len());
        for meta in patterns {
            let Ok(pattern) = Pattern::try_new(&meta.pattern_str, ast_lang) else {
                // Fail-open: skip invalid patterns silently (default patterns should be validated by tests).
                continue;
            };

            compiled.push(PrecompiledPattern { pattern, meta });
        }

        if !compiled.is_empty() {
            out.insert(language, compiled);
        }
    }

    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::similar_names)] // `ast_matcher` vs `matches` is readable in test code
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn severity_blocking() {
        assert!(Severity::Critical.blocks_by_default());
        assert!(Severity::High.blocks_by_default());
        assert!(!Severity::Medium.blocks_by_default());
        assert!(!Severity::Low.blocks_by_default());
    }

    #[test]
    fn match_error_display() {
        let errors = vec![
            MatchError::UnsupportedLanguage(ScriptLanguage::Perl),
            MatchError::ParseError {
                language: ScriptLanguage::Python,
                detail: "syntax error".to_string(),
            },
            MatchError::Timeout {
                elapsed_ms: 25,
                budget_ms: 20,
            },
            MatchError::PatternError {
                pattern: "bad pattern".to_string(),
                detail: "invalid syntax".to_string(),
            },
        ];

        for err in errors {
            let display = format!("{err}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn matcher_default_has_patterns() {
        let ast_matcher = AstMatcher::new();
        assert!(!ast_matcher.patterns.is_empty());
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Python));
        assert!(
            ast_matcher
                .patterns
                .contains_key(&ScriptLanguage::JavaScript)
        );
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Ruby));
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Bash));
    }

    #[test]
    fn python_positive_match() {
        let ast_matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/tmp/test')";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match shutil.rmtree");
                assert_eq!(m[0].rule_id, "heredoc.python.shutil_rmtree");
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn python_negative_match() {
        let ast_matcher = AstMatcher::new();
        let code = "import os\nprint('hello world')";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    mod javascript_positive_fixtures {
        use super::*;

        #[test]
        fn child_process_calls_block_a_destructive_literal_on_any_receiver() {
            // .agent-config-crqi7: each new rule, aliased and bare, quoted and templated.
            let ast_matcher = AstMatcher::new();
            for (code, rule_id) in [
                (
                    "cp.execFileSync('rm', ['-rf', '/'])",
                    "heredoc.javascript.execfilesync.rm_rf_catastrophic",
                ),
                (
                    "execFileSync('rm', ['-rf', '/'])",
                    "heredoc.javascript.execfilesync.rm_rf_catastrophic",
                ),
                (
                    "cp.execFile('rm', ['-rf', '/'], () => {})",
                    "heredoc.javascript.execfile.rm_rf_catastrophic",
                ),
                (
                    "execFile('git', ['reset', '--hard'])",
                    "heredoc.javascript.execfile.git_reset_hard",
                ),
                (
                    "cp.spawn('rm', ['-rf', '/'])",
                    "heredoc.javascript.spawn.rm_rf_catastrophic",
                ),
                (
                    "spawn(`rm`, [`-rf`, `/`])",
                    "heredoc.javascript.spawn.rm_rf_catastrophic",
                ),
                // exec is gated to a child_process binding, so its rows bind one.
                (
                    "const cp = require('child_process');\ncp.exec('rm -rf /')",
                    "heredoc.javascript.exec.rm_rf_catastrophic",
                ),
                (
                    "const { exec } = require('child_process');\nexec(`rm -rf /`)",
                    "heredoc.javascript.exec.rm_rf_catastrophic",
                ),
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::JavaScript)
                    .unwrap();
                let ids: Vec<&str> = matches.iter().map(|m| m.rule_id.as_str()).collect();
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == rule_id && m.severity.blocks_by_default()),
                    "{code} should block as {rule_id}, got {ids:?}"
                );
            }
        }

        #[test]
        fn fs_rmsync_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "catastrophic fs.rmSync should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }

        #[test]
        fn fs_rmsync_non_catastrophic_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('./dist', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync"),
                "non-catastrophic recursive rmSync should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync")
                .unwrap();
            assert!(!hit.severity.blocks_by_default());
        }

        #[test]
        fn execsync_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git reset --hard');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        #[test]
        fn execsync_rm_rf_non_catastrophic_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('rm -rf ./build');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches.iter().any(|m| m.rule_id.ends_with(".rm_rf")),
                "execSync('rm -rf ./build') should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id.ends_with(".rm_rf"))
                .unwrap();
            assert!(!hit.severity.blocks_by_default());
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('rm', ['-rf', '/']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn fs_rmsync_path_traversal_escapes_tmp_blocks() {
            // Path traversal from /tmp to /etc should be detected as catastrophic
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/tmp/../etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "path traversal /tmp/../etc should be detected as catastrophic"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }
    }

    mod javascript_negative_fixtures {
        use super::*;

        #[test]
        fn child_process_calls_block_nothing_benign_commented_or_quoted() {
            // .agent-config-crqi7: benign and non-catastrophic literals, a quote
            // inside a comment in the argv, a commented-out call, a call in a string.
            let ast_matcher = AstMatcher::new();
            for code in [
                "cp.execFileSync('git', ['status'])",
                "execFile('ls', ['-la'])",
                "cp.spawn('rm', ['-rf', './build'])",
                "const cp = require('child_process');\ncp.exec('echo hi')",
                "const cp = require('child_process');\ncp.exec(`rm -rf ${dir}`)",
                "/a+/.exec('aaa')",
                // exec is gated to a child_process binding: a RegExp's exec is not
                // a command, whatever its argument reads like.
                "/x/.exec('rm -rf /')",
                "cp.spawnSync('rm', [\n  '-rf', // never `/` here\n  './build',\n])",
                "cp.spawnSync('git', [\n  'reset', /* not '--hard' */\n  '--soft',\n])",
                "// cp.exec('rm -rf /')",
                "const s = \"cp.spawn('rm', ['-rf', '/'])\";",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::JavaScript)
                    .unwrap();
                let ids: Vec<&str> = matches.iter().map(|m| m.rule_id.as_str()).collect();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "{code} should not block, got {ids:?}"
                );
            }
        }

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git status');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('./file.txt');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_tmp_dotdot_in_filename_does_not_block() {
            // Filenames with consecutive dots are NOT path traversal
            let ast_matcher = AstMatcher::new();
            let code =
                "const fs = require('fs');\nfs.rmSync('/tmp/foo..bar', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            // Should match as medium severity (warn), NOT as catastrophic
            assert!(
                !matches.iter().any(|m| m.rule_id.contains("catastrophic")),
                "foo..bar is a filename, not path traversal"
            );
        }
    }

    #[test]
    fn unsupported_language_returns_error() {
        let ast_matcher = AstMatcher::new();
        let code = "print 'hello perl';";

        let result = ast_matcher.find_matches(code, ScriptLanguage::Unknown);
        assert!(matches!(result, Err(MatchError::UnsupportedLanguage(_))));
    }

    #[test]
    fn has_blocking_match_returns_first_blocker() {
        let ast_matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/danger')";

        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "heredoc.python.shutil_rmtree");
    }

    #[test]
    fn has_blocking_match_returns_none_for_safe_code() {
        let ast_matcher = AstMatcher::new();
        let code = "x = 1 + 2";

        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_none());
    }

    #[test]
    fn has_blocking_match_fails_open_on_error() {
        let ast_matcher = AstMatcher::new();
        let code = "some perl code";

        // Unknown is unsupported - should fail open (return None, not panic)
        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Unknown);
        assert!(result.is_none());
    }

    mod perl_positive_fixtures {
        use super::*;

        #[test]
        fn perl_system_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "system(\"rm -rf /\");\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_system_rm_rf_non_catastrophic_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "system('rm -rf ./build');\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(!matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_backticks_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "`git reset --hard`;\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("git_reset_hard"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_qx_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "qx/rm -rf \\/etc/;\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_file_path_rmtree_warns_by_default() {
            // Use longer timeout for test reliability (default 20ms can be flaky under load)
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            let code = "use File::Path;\nFile::Path::rmtree(\"/tmp/test\");\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run within 100ms");
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.perl.file_path.rmtree"),
                "should match File::Path::rmtree"
            );
            let rmtree = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.perl.file_path.rmtree")
                .expect("rmtree match present");
            assert!(!rmtree.severity.blocks_by_default());
        }
    }

    mod perl_negative_fixtures {
        use super::*;

        #[test]
        fn perl_comments_do_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "# system(\"rm -rf /\")\nprint \"ok\";\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                matches.is_empty(),
                "commented-out dangerous code is not executed"
            );
        }

        #[test]
        fn perl_printing_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "print \"rm -rf /\";\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                matches.is_empty(),
                "printed strings are data, not execution"
            );
        }
    }

    #[test]
    fn match_includes_line_number() {
        let ast_matcher = AstMatcher::new();
        let code = "x = 1\ny = 2\nshutil.rmtree('/test')";

        let matches = ast_matcher
            .find_matches(code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].line_number, 3); // shutil.rmtree is on line 3
    }

    #[test]
    fn match_preview_truncates_long_text() {
        let ast_matcher = AstMatcher::new();
        // Create code with a very long argument
        let long_path = "/very/long/path/".repeat(10);
        let code = format!("import shutil\nshutil.rmtree('{long_path}')");

        let results = ast_matcher
            .find_matches(&code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!results.is_empty());
        // Preview should be truncated
        assert!(results[0].matched_text_preview.len() <= 63);
        assert!(results[0].matched_text_preview.ends_with("..."));
    }

    #[test]
    fn empty_code_returns_no_matches() {
        let ast_matcher = AstMatcher::new();

        let results = ast_matcher
            .find_matches("", ScriptLanguage::Python)
            .expect("should parse empty code");
        assert!(results.is_empty());
    }

    #[test]
    fn default_matcher_is_lazy_initialized() {
        // Just verify it can be accessed without panic
        let _ = &*DEFAULT_MATCHER;
        assert!(!DEFAULT_MATCHER.patterns.is_empty());
    }

    #[test]
    fn default_patterns_all_precompile() {
        let raw = default_patterns();
        let expected: HashMap<ScriptLanguage, usize> =
            raw.iter().map(|(lang, pats)| (*lang, pats.len())).collect();

        let compiled = precompile_patterns(raw);

        for (lang, expected_len) in expected {
            let got = compiled.get(&lang).map_or(0, std::vec::Vec::len);
            assert_eq!(
                got, expected_len,
                "all default patterns should compile for {lang:?}"
            );
        }
    }

    #[test]
    fn truncate_preview_handles_utf8_safely() {
        // Test with ASCII
        assert_eq!(truncate_preview("hello", 10), "hello");
        assert_eq!(truncate_preview("hello world!", 8), "hello...");

        // Test with multi-byte UTF-8 (emojis are 4 bytes each)
        let emojis = "🎉🎊🎁🎄🎅";
        assert_eq!(truncate_preview(emojis, 10), emojis); // 5 chars, fits
        assert_eq!(truncate_preview(emojis, 4), "🎉..."); // truncates to 1 emoji + ...

        // Test with CJK characters (3 bytes each)
        let cjk = "你好世界";
        assert_eq!(truncate_preview(cjk, 10), cjk); // 4 chars, fits
        assert_eq!(truncate_preview(cjk, 4), cjk); // exactly 4 chars, fits
        assert_eq!(truncate_preview(cjk, 3), "..."); // 4 > 3, truncates (no room for even 1 char + "...")

        // Edge cases
        assert_eq!(truncate_preview("", 10), "");
        assert_eq!(truncate_preview("ab", 3), "ab");
        assert_eq!(truncate_preview("abc", 3), "abc");
        assert_eq!(truncate_preview("abcd", 3), "...");
    }

    mod ruby_positive_fixtures {
        use super::*;

        #[test]
        fn fileutils_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'fileutils'\nFileUtils.rm_rf('/')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic FileUtils.rm_rf should block"
            );
        }

        #[test]
        fn fileutils_rm_rf_non_catastrophic_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'fileutils'\nFileUtils.rm_rf('./tmp')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf"
                        && !m.severity.blocks_by_default()),
                "non-catastrophic FileUtils.rm_rf should warn only"
            );
        }

        #[test]
        fn system_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "system('rm -rf /')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "system('rm -rf /') should block"
            );
        }

        #[test]
        fn backticks_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "`rm -rf /`";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "backticks `rm -rf /` should block"
            );
        }

        #[test]
        fn exec_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "exec('git reset --hard HEAD~1')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "exec('git reset --hard ...') should block"
            );
        }

        #[test]
        fn open3_capture3_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'open3'\nOpen3.capture3('rm -rf /')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "Open3.capture3('rm -rf /') should block"
            );
        }

        #[test]
        fn open3_popen3_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "Open3.popen3('git reset --hard') { |i,o,e,t| }";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "Open3.popen3('git reset --hard') should block"
            );
        }
    }

    mod ruby_negative_fixtures {
        use super::*;

        #[test]
        fn puts_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "puts 'rm -rf /'";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn system_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "system('git status')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn open3_capture3_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "Open3.capture3('git status')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches.is_empty(),
                "Open3.capture3 with safe payload should not match"
            );
        }

        #[test]
        fn backticks_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "`echo hello`";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_only_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'fileutils'";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn file_delete_under_tmp_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "File.delete('/tmp/test.txt')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.file_delete"
                        && !m.severity.blocks_by_default()),
                "File.delete under /tmp should warn only"
            );
        }
    }

    mod typescript_positive_fixtures {
        use super::*;

        #[test]
        fn child_process_calls_block_a_destructive_literal_on_any_receiver() {
            // .agent-config-crqi7: each new rule, aliased and bare.
            let ast_matcher = AstMatcher::new();
            for (code, rule_id) in [
                (
                    "cp.execFileSync('rm', ['-rf', '/'] as string[]);",
                    "heredoc.typescript.execfilesync.rm_rf_catastrophic",
                ),
                (
                    "execFile('rm', ['-rf', '/']);",
                    "heredoc.typescript.execfile.rm_rf_catastrophic",
                ),
                (
                    "spawn('rm', ['-rf', '/']);",
                    "heredoc.typescript.spawn.rm_rf_catastrophic",
                ),
                (
                    "import * as cp from 'node:child_process';\ncp.exec('rm -rf /');",
                    "heredoc.typescript.exec.rm_rf_catastrophic",
                ),
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::TypeScript)
                    .unwrap();
                let ids: Vec<&str> = matches.iter().map(|m| m.rule_id.as_str()).collect();
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == rule_id && m.severity.blocks_by_default()),
                    "{code} should block as {rule_id}, got {ids:?}"
                );
            }
        }

        #[test]
        fn fs_rmsync_catastrophic_blocks_with_type_assertion() {
            let ast_matcher = AstMatcher::new();
            let code =
                "import * as fs from 'fs';\nfs.rmSync('/etc' as string, { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic fs.rmSync should block"
            );
        }

        #[test]
        fn fs_rmsync_non_catastrophic_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./dist', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync"
                        && !m.severity.blocks_by_default()),
                "non-catastrophic recursive rmSync should warn only"
            );
        }

        #[test]
        fn execsync_git_reset_hard_blocks_inside_decorated_class() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\n@sealed\nclass Danger {\n  run(): void {\n    require('child_process').execSync('git reset --hard');\n  }\n}\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks_in_generic_function() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nfunction go<T extends string>(x: T): void {\n  child_process.spawnSync('rm', ['-rf', '/']);\n}\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn deno_remove_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "type Path = string;\nconst p: Path = '/etc';\nDeno.remove('/etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches.iter().any(
                    |m| m.rule_id == "heredoc.typescript.deno_remove.catastrophic"
                        && m.severity.blocks_by_default()
                ),
                "catastrophic Deno.remove should block"
            );
        }
    }

    mod typescript_negative_fixtures {
        use super::*;

        #[test]
        fn child_process_calls_block_nothing_benign_commented_or_quoted() {
            // .agent-config-crqi7
            let ast_matcher = AstMatcher::new();
            for code in [
                "cp.execFileSync('git', ['status']);",
                "spawn('ls', ['-la'] as string[]);",
                "import * as cp from 'child_process';\ncp.exec('echo hi');",
                "const m: RegExpExecArray | null = /x/.exec('rm -rf /');",
                "// execFile('rm', ['-rf', '/']);",
                "const s: string = \"cp.exec('rm -rf /')\";",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::TypeScript)
                    .unwrap();
                let ids: Vec<&str> = matches.iter().map(|m| m.rule_id.as_str()).collect();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "{code} should not block, got {ids:?}"
                );
            }
        }

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process').execSync('git status');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./file.txt' as string);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }
    }

    #[test]
    fn bash_positive_match() {
        let ast_matcher = AstMatcher::new();
        let code = "rm -rf /tmp/dangerous";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match rm -rf");
                assert!(m[0].rule_id.contains("bash"));
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn bash_negative_match() {
        let ast_matcher = AstMatcher::new();
        let code = "echo 'hello world'";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // =========================================================================
    // Python Fixture Tests (git_safety_guard-beq)
    // =========================================================================

    /// Positive fixtures: patterns that MUST match (Critical/High severity = blocks)
    mod python_positive_fixtures {
        use super::*;

        #[test]
        fn shutil_rmtree_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import shutil\nshutil.rmtree('/dangerous/path')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "shutil.rmtree must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.shutil_rmtree");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_remove_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.remove('/etc/passwd')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.remove must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_remove");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_rmdir_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.rmdir('/important/dir')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.rmdir must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_unlink_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.unlink('/critical/file')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.unlink must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_unlink_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/secret').unlink()";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().unlink() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_rmdir_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/danger/dir').rmdir()";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().rmdir() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn subprocess_run_warns() {
            // subprocess.run is Medium severity - warns but doesn't block by default
            // per bead: "Do not block on shell=True alone"
            let ast_matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.run(['ls', '-la'])";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.run must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.subprocess_run");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }

        #[test]
        fn os_system_warns() {
            // os.system is Medium severity - warns but doesn't block by default
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.system('echo hello')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.system must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_system");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }

        /// The same call is Medium or Critical depending on the argv it was
        /// handed, so the rule reads the list rather than the call
        /// (.agent-config-ei4it).
        #[test]
        fn a_destructive_argv_list_is_critical() {
            let ast_matcher = AstMatcher::new();
            let code = format!(
                "import subprocess\nsubprocess.run(['{}', '{}', '/srv/data'])",
                "r\u{6d}", "-r\u{66}"
            );
            let matches = ast_matcher
                .find_matches(&code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.run must still match");
            assert_eq!(
                matches[0].rule_id,
                "heredoc.python.subprocess_run.rm_rf_catastrophic"
            );
            assert_eq!(matches[0].severity, Severity::Critical);
            assert!(matches[0].severity.blocks_by_default());
        }

        /// An argv list goes to execve, not to a shell. A separator inside an
        /// ELEMENT is a character in one argument and starts no second
        /// command, so the list must never be re-joined and re-split.
        #[test]
        fn a_separator_inside_an_argv_element_starts_no_second_command() {
            let ast_matcher = AstMatcher::new();
            let code = format!(
                "import subprocess\nsubprocess.run(['echo', 'hi; {} -r{} /tmp/x'])",
                "r\u{6d}", "\u{66}"
            );
            let matches = ast_matcher
                .find_matches(&code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.run must still match");
            assert_eq!(
                matches[0].rule_id, "heredoc.python.subprocess_run",
                "echo prints this argument; it does not run it"
            );
            assert!(
                !matches[0].severity.blocks_by_default(),
                "an argument of echo is not a delete"
            );
        }
    }

    /// Negative fixtures: patterns that must NOT match (safe code)
    mod python_negative_fixtures {
        use super::*;

        #[test]
        fn print_statement_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // String containing destructive command text is NOT executed
            let code = "print('rm -rf /')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "print statement must not match");
        }

        #[test]
        fn import_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // Just importing doesn't execute anything dangerous
            let code = "import shutil\nimport os\nimport subprocess";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "imports alone must not match");
        }

        #[test]
        fn comment_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // Comments mentioning dangerous operations are not executed
            let code = "# shutil.rmtree('/') would be dangerous\nx = 1";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "comments must not match");
        }

        #[test]
        fn safe_file_operations_do_not_match() {
            let ast_matcher = AstMatcher::new();
            // Safe file operations should not trigger
            let code = r"
import os
os.path.exists('/tmp/test')
os.path.isfile('/tmp/test')
os.listdir('/tmp')
with open('/tmp/log.txt', 'w') as f:
    f.write('hello')
";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "safe file operations must not match");
        }

        #[test]
        fn string_variable_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // String that looks like dangerous code but is just data
            let code = r#"
dangerous_cmd = "shutil.rmtree('/')"
docs = "Example: os.remove(path)"
"#;
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "string literals must not match");
        }

        #[test]
        fn docstring_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = r#"
def cleanup():
    """
    Warning: Do not call shutil.rmtree('/') as it will delete everything.
    Use os.remove() for single files only.
    """
    pass
"#;
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "docstrings must not match");
        }

        #[test]
        fn safe_tmp_cleanup_in_context() {
            let ast_matcher = AstMatcher::new();
            // This tests structural matching - the pattern matches but this is
            // about whether we match at all (we do), not about path safety
            // NOTE: This test verifies the pattern DOES match (as expected)
            // Path-based filtering would be a separate concern
            let code = "import shutil\nshutil.rmtree('/tmp/build_artifacts')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            // Pattern matching finds this - path filtering is separate policy
            assert!(!matches.is_empty(), "shutil.rmtree matches structurally");
        }
    }

    mod git_global_options {
        use super::*;

        fn suffix(line: &str) -> Option<&'static str> {
            detect_command_words(line.split_whitespace()).map(|hit| hit.rule_suffix)
        }

        #[test]
        fn the_subcommand_is_read_after_global_options() {
            for line in [
                "git -C /repo reset --hard",
                "git -c core.pager=cat reset --hard",
                "git --git-dir /r/.git --work-tree /r reset --hard",
                "git --attr-source HEAD --shallow-file f reset --hard",
                "git --no-pager -P reset --hard",
            ] {
                assert_eq!(suffix(line), Some("git_reset_hard"), "{line}");
            }
            assert_eq!(suffix("git -C . clean -fd"), Some("git_clean_fd"));
        }

        #[test]
        fn a_value_taking_option_is_read_both_ways() {
            // A non-literal argv value is dropped before the detector reads it.
            assert_eq!(suffix("git -C reset --hard"), Some("git_reset_hard"));
            assert_eq!(suffix("git -C -c k=v reset --hard"), Some("git_reset_hard"));
            assert_eq!(suffix("git -C . status"), None);
            assert_eq!(suffix("git -C"), None);
            // Only a word the option skip reaches is a subcommand.
            assert_eq!(suffix("git -C . log --grep reset --hard"), None);
            // A flag-only option owns no word, so `--grep` is never reached.
            assert_eq!(suffix("git --no-pager log --grep reset --hard"), None);
        }
    }

    /// `subprocess.run` / `.call` / `.Popen` are read on whatever the body binds
    /// the module to (`.agent-config-dcg-subprocess-module-binding-ehxrb`), the
    /// way `shutil.rmtree` is.
    ///
    /// Matcher level, so it pins the binding with no refiner involved: a benign
    /// argv stays Medium either way, and the hook verdict for a destructive one
    /// is `tests/repro_subprocess_module_binding.rs`.
    mod python_subprocess_binding {
        use super::*;

        fn subprocess_rules(code: &str) -> Vec<String> {
            AstMatcher::new()
                .find_matches(code, ScriptLanguage::Python)
                .unwrap()
                .into_iter()
                .map(|m| m.rule_id)
                .filter(|id| id.starts_with("heredoc.python.subprocess_"))
                .collect()
        }

        #[test]
        fn every_bound_spelling_is_one_match_under_its_rule() {
            for (code, rule) in [
                ("import subprocess\nsubprocess.run(['ls'])", "run"),
                ("subprocess.run(['ls'])", "run"),
                ("import subprocess as sp\nsp.run(['ls'])", "run"),
                ("from subprocess import run\nrun(['ls'])", "run"),
                ("from subprocess import *\nrun(['ls'])", "run"),
                ("import subprocess as sp\nsp.call(['ls'])", "call"),
                ("from subprocess import call\ncall(['ls'])", "call"),
                ("import subprocess as sp\nsp.Popen(['ls'])", "popen"),
                ("from subprocess import Popen\nPopen(['ls'])", "popen"),
                // Both bindings in one body, one call: still one match.
                (
                    "import subprocess\nfrom subprocess import run\nsubprocess.run(['ls'])",
                    "run",
                ),
                // The name aliased AND plainly imported: either may be live, so
                // the plain import keeps it subprocess.
                (
                    "try:\n    import subprocess32 as subprocess\nexcept ImportError:\n    import subprocess\nsubprocess.run(['ls'])",
                    "run",
                ),
                (
                    "import json as subprocess\nimport subprocess\nsubprocess.Popen(['ls'])",
                    "popen",
                ),
            ] {
                assert_eq!(
                    subprocess_rules(code),
                    vec![format!("heredoc.python.subprocess_{rule}")],
                    "code: {code:?}"
                );
            }
        }

        #[test]
        fn what_the_imports_do_not_explain_is_not_subprocess() {
            for code in [
                "import asyncio\nasyncio.run(main())",
                "app.run(debug=True)",
                "import json as sp\nsp.run(['ls'])",
                "def run(cmd):\n    print(cmd)\nrun(['ls'])",
                "from asyncio import run\nrun(main())",
                "from subprocess import check_output as run\nrun(['ls'])",
                "from subprocess import run\ncall(['ls'])",
                "call(['ls'])",
                "from unittest import mock\nmock.call(['ls'])",
                "self.call(['ls'])",
                "pool.Popen(['ls'])",
                "Popen(['ls'])",
                "class Popen:\n    pass\nPopen(['ls'])",
                // The bare twin must not take an attribute call: `run` is
                // bound here, `runner.run` is not it.
                "from subprocess import run\nrunner.run(['ls'])",
                "from subprocess import Popen\npool.Popen(['ls'])",
                // A name bound ONLY to another module is that module; the plain
                // import is what keeps the name subprocess, not the spelling.
                "import json as subprocess\nsubprocess.run(['ls'])",
                // ...and it keeps only that NAME: `sp` is still json.
                "import subprocess\nimport json as sp\nsp.run(['ls'])",
            ] {
                assert!(
                    subprocess_rules(code).is_empty(),
                    "must not match\ncode: {code:?}\ngot: {:?}",
                    subprocess_rules(code)
                );
            }
        }
    }

    mod catastrophic_paths {
        use super::*;

        #[test]
        fn test_is_catastrophic_path_loose_prefix() {
            // These should NOT be catastrophic
            assert!(!is_catastrophic_path("/bin_logs"));
            assert!(!is_catastrophic_path("/usr_local"));
            assert!(!is_catastrophic_path("/etc_backup"));
            assert!(!is_catastrophic_path("/home_page.html"));
        }

        #[test]
        fn test_is_catastrophic_path_strict_prefix() {
            // These SHOULD be catastrophic
            assert!(is_catastrophic_path("/bin"));
            assert!(is_catastrophic_path("/bin/"));
            assert!(is_catastrophic_path("/bin/sh"));
            assert!(is_catastrophic_path("/usr"));
            assert!(is_catastrophic_path("/usr/local"));
            assert!(is_catastrophic_path("/etc/passwd"));
        }

        #[test]
        fn test_is_catastrophic_path_var() {
            // /var should be catastrophic
            assert!(is_catastrophic_path("/var"));
            assert!(is_catastrophic_path("/var/www"));
            assert!(is_catastrophic_path("/var/log"));
        }

        #[test]
        fn test_is_catastrophic_path_tmp_backup_not_catastrophic() {
            // /tmp_backup should NOT be matched as /tmp (and thus fall through to sys_dirs check)
            // Since it's not in sys_dirs, it should return false.
            assert!(!is_catastrophic_path("/tmp_backup"));
        }
    }
}
