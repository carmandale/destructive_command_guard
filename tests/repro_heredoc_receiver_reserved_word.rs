//! `.agent-config-41wu8` — a reserved word before the receiver unmasked a data body.
//!
//! `extract_heredoc_target_command` walks the tokens before `<<` to find the command that
//! OWNS the heredoc. It skipped env assignments, flags, wrappers, quoted strings and file
//! paths — but not reserved words. So in `{ cat <<'EOF' ...; }` the receiver resolved to
//! `{`, `is_non_executing_heredoc_command` said false, `should_mask` went false, and a
//! pure data body was handed to every rule in every pack.
//!
//! This is the same root cause as the substitution scanner's `COMMAND_FOLLOWS` fix — the
//! first token is not the command word — on the false-positive side. The list is reused
//! rather than restated, so the two cannot drift apart.
//!
//! The bead was filed as "a markdown fence inside a heredoc body". It is not: every fenced
//! case here is asserted against its fence-free twin, and they agree. The fence was
//! incidental to the corpus rows that surfaced it.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// Assembled at runtime so this source file is not itself a payload.
fn trigger() -> String {
    format!("{} -rf /", "rm")
}

fn masked(command: &str) -> bool {
    !mask_non_executing_heredocs(command).contains(&trigger())
}

// ---------------------------------------------------------------------------
// The defect: a reserved word or group opener before the receiver.
// `cat` is a data sink. The body must be masked in every one of these.
// ---------------------------------------------------------------------------

#[test]
fn a_brace_group_does_not_hide_the_receiver() {
    let cmd = format!("{{ cat <<'EOF'\n{}\nEOF\n; }}", trigger());
    assert!(
        masked(&cmd),
        "a brace group owns its heredoc with `cat`, not with `{{`: {cmd}"
    );
}

#[test]
fn an_unclosed_brace_group_does_not_hide_the_receiver() {
    let cmd = format!("{{ cat <<'EOF'\n{}\nEOF\n", trigger());
    assert!(masked(&cmd), "the opening brace alone already defeated it");
}

#[test]
fn a_reserved_word_does_not_hide_the_receiver() {
    for word in ["then", "do", "else", "elif"] {
        let cmd = format!("if true; {word} cat <<'EOF'\n{}\nEOF\nfi\n", trigger());
        assert!(masked(&cmd), "`{word}` is not the command word: {cmd}");
    }
}

#[test]
fn a_bang_or_time_prefix_does_not_hide_the_receiver() {
    for word in ["!", "time"] {
        let cmd = format!("{word} cat <<'EOF'\n{}\nEOF\n", trigger());
        assert!(masked(&cmd), "`{word}` is not the command word: {cmd}");
    }
}

#[test]
fn a_redirection_before_the_command_word_does_not_hide_the_receiver() {
    // `>/dev/null` is NOT the interesting spelling: it contains a slash, so the
    // file-path branch below already skipped it before this fix existed. A test
    // that only used it would pass either way and pin nothing. `>out` carries its
    // own target and has no slash, so it reached the `return Some(token)` line.
    for redirect in [">out", ">>out", "2>out", "&>out", ">/dev/null"] {
        let cmd = format!("{redirect} cat <<'EOF'\n{}\nEOF\n", trigger());
        assert!(
            masked(&cmd),
            "a leading redirection is legal in a simple command: {cmd}"
        );
    }
}

#[test]
fn a_bare_redirection_operator_consumes_its_target_not_the_receiver() {
    // `> out cat` is one simple command: stdout to `out`, running `cat`. The
    // operator and its target are two tokens, so skipping only the operator
    // resolves the receiver to the FILENAME.
    for redirect in ["> out", "2> out", ">> out"] {
        let cmd = format!("{redirect} cat <<'EOF'\n{}\nEOF\n", trigger());
        assert!(
            masked(&cmd),
            "the redirect target is not the command word: {cmd}"
        );
    }
}

// ---------------------------------------------------------------------------
// The fence is NOT a cause. Each fenced case is asserted against its
// fence-free twin so a future change cannot "fix the fence" and miss the point.
// ---------------------------------------------------------------------------

#[test]
fn a_markdown_fence_changes_nothing_in_either_direction() {
    let fenced = format!("cat <<'EOF'\n```diff\n-{}\n```\nEOF\n", trigger());
    let plain = format!("cat <<'EOF'\n-{}\nEOF\n", trigger());
    assert_eq!(
        masked(&fenced),
        masked(&plain),
        "the fence must not decide masking; it never did"
    );
    assert!(masked(&plain), "a quoted data body is masked either way");
}

// ---------------------------------------------------------------------------
// Guard rails. Making the receiver resolvable in MORE cases means MORE masking,
// which is exactly how this fix could reopen a bypass. These pin the direction.
// ---------------------------------------------------------------------------

#[test]
fn a_reserved_word_prefix_still_does_not_mask_a_real_executor() {
    let cmd = format!("{{ bash <<'EOF'\n{}\nEOF\n; }}", trigger());
    assert!(
        !masked(&cmd),
        "`bash` executes its heredoc; a brace group must not make it look like data"
    );
}

#[test]
fn a_reserved_word_prefix_still_does_not_mask_a_pipe_into_a_shell() {
    // The pipe belongs on the FIRST line. Written as `EOF\n| bash` the heredoc has
    // already ended and `| bash` is a syntax error, so the earlier spelling of this
    // test asserted a property of a string that could never run — it went red against
    // a correct fix. A guard rail written in invalid shell guards nothing.
    let cmd = format!("{{ cat <<'EOF' | bash\n{}\nEOF\n; }}", trigger());
    assert!(
        !masked(&cmd),
        "the pipeline gate must still see through a brace group"
    );
}

#[test]
fn a_reserved_word_prefix_still_does_not_mask_a_substitution_into_eval() {
    let cmd = format!("{{ eval \"$(cat <<'EOF'\n{}\nEOF\n)\"; }}", trigger());
    assert!(
        !masked(&cmd),
        "the substitution gate must still see through a brace group"
    );
}

// ---------------------------------------------------------------------------
// The deliberate trade, pinned so a later change cannot flip it and call it a
// fix. u06z-replay-summary.md rules that denying an UNQUOTED heredoc carrying a
// literal destructive body is a false positive BY CONSTRUCTION and accepted:
// an unquoted body is subject to expansion, and 0 of 92 safe-class corpus rows
// are unquoted-only. Nothing pinned it until now.
// ---------------------------------------------------------------------------

#[test]
fn an_unquoted_delimiter_is_deliberately_not_masked() {
    let cmd = format!("cat <<EOF\n{}\nEOF\n", trigger());
    assert!(
        !masked(&cmd),
        "unquoted bodies expand, so the gate declines to mask them — \
         this is the recorded trade, not an oversight. If you are changing this, \
         change u06z-replay-summary.md and re-measure the safe-class corpus first."
    );
}

#[test]
fn a_quoted_delimiter_is_masked_so_the_pair_above_means_something() {
    let cmd = format!("cat <<'EOF'\n{}\nEOF\n", trigger());
    assert!(
        masked(&cmd),
        "the quoted twin must mask, or the unquoted assertion proves nothing"
    );
}

// ---------------------------------------------------------------------------
// A COMPOUND'S PIPELINE APPLIES TO THE BODY INSIDE IT.
//
// Resolving the receiver through `{` created this: with `cat` correctly
// resolved the body was masked, and the `| bash` that belongs to the GROUP was
// never looked at, because heredoc_output_reaches_executor stops at the first
// newline. The subshell spelling had the same hole before any of this work --
// `(` was always a tokenizer break -- so it was live on the installed guard.
//
// EVERY SHAPE BELOW WAS CHECKED WITH `bash -n`. The earlier `{ ... ; }` rows in
// this file are SYNTAX ERRORS: a `;` cannot follow a heredoc terminator line and
// precede `}`. Text that cannot run cannot prove a guard works, which is the
// same trap the pipe-into-shell rail above already documents.
// ---------------------------------------------------------------------------

#[test]
fn a_group_piped_into_a_shell_still_reaches_the_body() {
    // `bash -n`: valid. The closing `}` is on its own line, no `;` before it.
    for closer in ["}", "} "] {
        let cmd = format!("{{ cat <<'EOF'\n{}\nEOF\n{closer}| bash", trigger());
        assert!(
            !masked(&cmd),
            "the group's pipe feeds the body to bash: {cmd}"
        );
    }
}

#[test]
fn a_subshell_piped_into_a_shell_still_reaches_the_body() {
    // This one was ALLOW on the pre-change binary too -- a bypass that predates
    // this bead and was live on the installed guard. Same root cause, so it is
    // closed here rather than left because it was not mine.
    let cmd = format!("( cat <<'EOF'\n{}\nEOF\n) | sh", trigger());
    assert!(
        !masked(&cmd),
        "the subshell's pipe feeds the body to sh: {cmd}"
    );
}

#[test]
fn a_reserved_word_compound_piped_into_a_shell_still_reaches_the_body() {
    let cmd = format!("if true; then cat <<'EOF'\n{}\nEOF\nfi | bash", trigger());
    assert!(!masked(&cmd), "`fi | bash` still pipes the body: {cmd}");
}

#[test]
fn a_group_that_only_writes_a_file_is_still_masked() {
    // The document-assembly shape this bead exists for. If the fix above denied
    // this it would have traded one false positive for another.
    let cmd = format!("{{ cat <<'EOF'\n{}\nEOF\n}} > out.md", trigger());
    assert!(
        masked(&cmd),
        "a group redirected to a file executes nothing: {cmd}"
    );
}

#[test]
fn a_later_unrelated_pipeline_does_not_unmask_the_body() {
    // The control that makes the four above mean something. `ls | wc -l` is a
    // SEPARATE command; nothing connects it to this heredoc. A scan that simply
    // resumed after the body would call this executing and invent a false
    // positive.
    let cmd = format!("cat <<'EOF'\n{}\nEOF\nls | wc -l", trigger());
    assert!(
        masked(&cmd),
        "an unrelated later pipeline is not this body's: {cmd}"
    );
}

#[test]
fn a_group_closing_without_a_pipeline_is_still_masked() {
    let cmd = format!("{{ cat <<'EOF'\n{}\nEOF\n}}", trigger());
    assert!(masked(&cmd), "a plain group executes nothing: {cmd}");
}

#[test]
fn a_group_around_a_here_string_piped_into_a_shell_still_reaches_the_content() {
    // A here-string is one line, so the group's `; } | bash` is on that same
    // line -- and the existing pipeline gate stops at the `;`, reading a group
    // separator as the end of the pipeline. `bash -n`: valid.
    let cmd = format!("{{ cat <<<'{}'; }} | bash", trigger());
    assert!(
        !masked(&cmd),
        "the group's pipe feeds the here-string to bash: {cmd}"
    );
}

#[test]
fn a_subshell_around_a_here_string_piped_into_a_shell_still_reaches_the_content() {
    let cmd = format!("( cat <<<'{}'; ) | bash", trigger());
    assert!(!masked(&cmd), "same, through a subshell: {cmd}");
}

#[test]
fn a_plain_here_string_to_a_data_sink_is_still_masked() {
    // The control. If the two above passed because here-strings stopped being
    // masked at all, this goes red.
    let cmd = format!("cat <<<'{}'", trigger());
    assert!(
        masked(&cmd),
        "a here-string into cat executes nothing: {cmd}"
    );
}

// ---------------------------------------------------------------------------
// ASSERTED ON THE EVALUATOR, NOT ON MASKING.
//
// `masked()` above calls mask_non_executing_heredocs. That is the right oracle
// for a heredoc and the WRONG one for a here-string: a here-string's content
// reaches the matcher through extraction (ExtractedContent), not through the
// masked command text, so the evaluator has its own copy of the
// receiver/pipeline gate at src/evaluator.rs. A fix applied only at the masking
// sites left `{ cat <<<'...'; } | bash` ALLOWing on the BINARY while
// a_group_around_a_here_string_piped_into_a_shell_still_reaches_the_content
// passed green. These rows are what caught that.
// ---------------------------------------------------------------------------

fn evaluate(cmd: &str) -> destructive_command_guard::evaluator::EvaluationResult {
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    config.packs.enabled = vec!["core".to_string()];
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    evaluate_command(cmd, &config, &keywords, &overrides, &allowlists)
}

#[test]
fn a_compound_piped_into_a_shell_is_denied_by_the_evaluator() {
    for cmd in [
        format!("{{ cat <<'A'\n{}\nA\n}} | bash", trigger()),
        format!("( cat <<'A'\n{}\nA\n) | sh", trigger()),
        format!("{{ true; cat <<'A'\n{}\nA\n}} | bash", trigger()),
        format!("if true; then cat <<'A'\n{}\nA\nfi | bash", trigger()),
        format!("{{ cat <<<'{}'; }} | bash", trigger()),
        format!("( cat <<<'{}'; ) | bash", trigger()),
        format!("{{ true; cat <<<'{}'; }} | bash", trigger()),
    ] {
        assert!(
            evaluate(&cmd).is_denied(),
            "the compound's pipe hands this to an interpreter: {cmd:?}"
        );
    }
}

#[test]
fn a_compound_that_does_not_pipe_is_still_allowed_by_the_evaluator() {
    // The control. Denying everything would satisfy the test above.
    for cmd in [
        format!("{{ cat <<'A'\n{}\nA\n}} > out.md", trigger()),
        format!("{{ cat <<'A'\n{}\nA\n}}", trigger()),
        format!("( cat <<'A'\n{}\nA\n) > out.md", trigger()),
        format!("cat <<'A'\n{}\nA\n", trigger()),
        format!("cat <<<'{}'", trigger()),
        format!("cat <<'A'\n{}\nA\nls | wc -l", trigger()),
    ] {
        assert!(
            !evaluate(&cmd).is_denied(),
            "nothing executes this body: {cmd:?}"
        );
    }
}
