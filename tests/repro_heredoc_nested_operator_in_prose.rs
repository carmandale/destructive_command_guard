//! A heredoc/here-string operator QUOTED inside an inert body is prose
//! (`.agent-config-v5f37`).
//!
//! Measured 2026-09-05, twice, on real commands this fleet actually ran. An
//! agent writing a commit message ABOUT the heredoc gate had the commit denied,
//! because the message quoted a here-string pipeline as an example:
//!
//! ```text
//! git commit -q -m "$(cat <<'EOF'
//! ... makes the binary ALLOW `cat <<<'rm -rf /' | bash`, ...
//! EOF
//! )" -- tests/repro_heredoc_pipe_to_shell.rs
//!
//! BLOCKED by dcg -- core.filesystem:rm-rf-root-home (line 1 of heredoc)
//! ```
//!
//! Masking was never the leak. `mask_non_executing_heredocs` blanked the whole
//! outer body correctly. The leak is EXTRACTION: `extract_herestrings` and
//! `extract_heredocs` scan the raw command with `captures_iter` and have no
//! notion of nesting, so the inner operator became a second `ExtractedContent`
//! whose resolved "receiver" was the English word `makes`. Judged on its own
//! terms that entry is a data sink piping into bash, so the veto set denied it
//! -- and denied a command whose real receiver is `cat` with nothing downstream.
//!
//! That is precisely the documentation-text false positive spec 333 exists to
//! prevent, one level of nesting down. It costs this repo pair constantly: the
//! whole vocabulary of spec 333 IS here-strings, so any spec, receipt, test
//! fixture or commit message discussing the gate can trip it.
//!
//! Written from both sides, like its neighbours. The PROSE group pins that
//! quoting an operator inside data no longer denies; the CODE group pins that
//! the fix is scoped by INERTNESS and not by nesting alone -- when the enclosing
//! body really does reach an interpreter, the text inside it really is code.
//!
//! Which row does which, measured rather than asserted (2026-09-05):
//!
//! - Deleting the fix turns exactly FOUR rows red: the three prose rows plus
//!   `the_same_python_body_handed_to_cat_is_data_again`. The two remaining
//!   prose-side rows were green before the fix and are floors, not proof; each
//!   says so on itself.
//! - Widening the fix to nesting-alone turns exactly ONE row red:
//!   `a_here_string_inside_a_python_heredoc_...`. The other code rows cannot
//!   see that mutant, because the enclosing entry's own text trips the same
//!   rule and denies first. That single row is the whole earned keep of the
//!   `heredoc_body_is_inert` call, so do not delete it as a duplicate of its
//!   neighbours -- it is the only one that is not.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases on purpose, so a
/// verdict difference can only come from the nesting, never from the payload.
const TRIGGER: &str = "rm -rf /";

/// The prose line that actually got a commit blocked, kept verbatim in shape:
/// an operator quoted inside running text, with an English word in front of it.
fn prose_quoting_a_here_string() -> String {
    format!("makes the binary ALLOW `cat <<<'{TRIGGER}' | bash`, and")
}

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

fn assert_denied(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_denied(),
        "should be DENIED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

fn assert_allowed(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        !result.is_denied(),
        "should be ALLOWED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

fn assert_body_masked(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        !masked.contains(TRIGGER),
        "body should stay masked ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

fn assert_body_visible(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        masked.contains(TRIGGER),
        "body was masked away, so no rule can read it ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

// ---------------------------------------------------------------------------
// PROSE — an operator quoted inside an inert body. All of these were DENIED
// before the fix.
// ---------------------------------------------------------------------------

#[test]
fn prose_quoting_a_here_string_pipeline_is_still_data() {
    let cmd = format!("cat <<'EOF'\n{}\nEOF", prose_quoting_a_here_string());
    assert_allowed(&cmd, "the outer receiver is cat and nothing consumes it");
    assert_body_masked(&cmd, "masking was never the leak here");
}

#[test]
fn the_commit_message_that_was_actually_blocked() {
    // The real 2026-09-05 shape: the message arrives through a command
    // substitution, which is how every agent in this fleet writes one.
    let cmd = format!(
        "git commit -q -m \"$(cat <<'EOF'\n{}\nEOF\n)\" -- tests/repro_heredoc_pipe_to_shell.rs",
        prose_quoting_a_here_string()
    );
    assert_allowed(
        &cmd,
        "git commit -m stores its argument, it does not run it",
    );
}

#[test]
fn a_multi_line_message_is_the_same_case() {
    // Nothing about the fix depends on the body being one line.
    let body = format!(
        "test(heredoc): the here-string cases assert the verdict\n\n\
         Mutant M8 -- all five vetoes whole at both masking sites --\n\
         {}\nand both tests reported GREEN under it.",
        prose_quoting_a_here_string()
    );
    let cmd = format!("git commit -q -m \"$(cat <<'EOF'\n{body}\nEOF\n)\" -- f.rs");
    assert_allowed(&cmd, "a longer message is the same shape");
}

#[test]
fn a_nested_heredoc_operator_is_the_same_case_as_a_nested_here_string() {
    // HONEST LABEL: this row was ALREADY green before the fix -- measured, not
    // assumed. A quoted `<<` needs its delimiter to terminate before
    // `extract_heredocs` yields anything, and prose never spells the closing
    // `INNER`, so no second content is produced and there is nothing to judge.
    // The `<<<` spelling has no such requirement, which is why only it broke.
    //
    // Kept as a control, not as proof: the two operators have separate
    // extractors, and if `extract_heredocs` ever learns to recover an
    // unterminated body this row is where that shows up as a new denial.
    let quoted = format!("run `cat <<'INNER' | bash` with {TRIGGER} in the body");
    let cmd = format!("cat <<'EOF'\n{quoted}\nEOF");
    assert_allowed(&cmd, "the inner << is quoted inside data");
}

#[test]
fn documentation_prose_without_an_operator_never_regressed() {
    // Spec 333's own canonical case, kept here as the floor: this one was
    // ALLOWED before the fix too, so if it ever goes red the fix broke masking
    // rather than extraction.
    let cmd = format!("cat <<'EOF'\nnever run {TRIGGER} on a laptop\nEOF");
    assert_allowed(&cmd, "documentation text was always allowed");
    assert_body_masked(&cmd, "spec 333's masking");
}

// ---------------------------------------------------------------------------
// CODE — the fix is scoped by INERTNESS. Every row here was DENIED before the
// fix and must stay DENIED after it.
// ---------------------------------------------------------------------------

#[test]
fn a_real_here_string_pipeline_is_untouched() {
    // Not nested in anything. The fix must not reach it.
    let cmd = format!("cat <<<'{TRIGGER}' | bash");
    assert_denied(&cmd, "this is the real thing, not a quotation of it");
}

#[test]
fn an_operator_inside_a_body_that_reaches_bash_is_still_code() {
    // Same prose, but the enclosing heredoc pipes into bash, so the body IS
    // executed and the operator inside it is not prose at all. This is the row
    // that fails if the fix is widened to "any nested operator".
    let cmd = format!("cat <<'EOF' | bash\n{}\nEOF", prose_quoting_a_here_string());
    assert_denied(&cmd, "the enclosing body is executed, so its text is code");
    assert_body_visible(&cmd, "a body that reaches bash is never masked");
}

#[test]
fn an_operator_inside_a_substitution_into_an_executor_is_still_code() {
    // The substitution gate's own case. The capture is spliced into `bash -c`,
    // so the enclosing body is not inert and the nesting rule does not apply.
    let cmd = format!(
        "bash -c \"$(cat <<'EOF'\n{}\nEOF\n)\"",
        prose_quoting_a_here_string()
    );
    assert_denied(&cmd, "bash -c runs what the substitution produced");
}

#[test]
fn a_here_string_inside_a_python_heredoc_is_the_row_that_earns_the_inertness_clause() {
    // THE case that makes `heredoc_body_is_inert` load-bearing rather than
    // decorative, and the only one in this file that does. Measured 2026-09-05:
    // with the clause, DENIED; with the clause widened to nesting-alone,
    // ALLOWED. Every other CODE row below stays green under that mutant,
    // because the enclosing entry's own text trips the same rule and denies
    // first -- so they cannot tell the two versions apart.
    //
    // Why this one can: the enclosing body is PYTHON, so Tier 2.5's recursive
    // shell analysis (Bash only) never reads it, and the nested here-string is
    // the sole entry that sees `rm -rf /` as a command. Skip it on nesting
    // alone and the guard opens a real under-block.
    let cmd = format!("python3 <<'EOF'\nimport os\nos.system(\"cat <<<'{TRIGGER}' | bash\")\nEOF");
    assert_denied(
        &cmd,
        "python3 executes the body, so the nested entry must be judged",
    );
}

#[test]
fn the_same_python_body_handed_to_cat_is_data_again() {
    // The mirror of the row above, differing in one token: the receiver. This
    // pair is what the inertness clause actually decides.
    let cmd = format!("cat <<'EOF'\nimport os\nos.system(\"cat <<<'{TRIGGER}' | bash\")\nEOF");
    assert_allowed(&cmd, "cat does not execute the body, so its text is data");
}

#[test]
fn a_bare_payload_inside_a_body_that_reaches_bash_is_still_code() {
    // The plainest control: no nested operator anywhere, enclosing body
    // executed. Pins that the fix did not disturb the ordinary path.
    let cmd = format!("cat <<'EOF' | bash\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the body is piped into bash");
}
