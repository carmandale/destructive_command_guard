//! A data-sink heredoc reaching a shell through a SUBSTITUTION (`.agent-config-baqrr`).
//!
//! `.agent-config-j6ha9` closed the pipeline half of this class: `cat <<'EOF' | bash`.
//! Its gate reads the pipeline the heredoc's stdout flows into, so it cannot see a
//! route that never uses stdout at all. Four such routes were measured ALLOW on the
//! live v0.4.2 build on 2026-09-02, with the pipeline gate already installed:
//!
//! ```text
//! eval "$(cat <<'EOF' ... EOF)"          the substitution's text is executed
//! bash <(cat <<'EOF' ... EOF)            the substitution names a file bash runs
//! V=$(cat <<'EOF' ... EOF); eval "$V"    captured first, executed after
//! $(cat <<'EOF' ... EOF)                 the result IS the command word
//! ```
//!
//! In every one the heredoc's receiver is `cat`, so the receiver-only decision masked
//! the body out of the matcher and every rule in every pack was unreachable.
//!
//! Written from both sides on purpose, the same way the pipeline repro is. The first
//! group pins that the body is now seen; the second pins that the masking spec 333
//! exists to provide did not go with it. Deleting the new predicate's call sites turns
//! the first group red; widening it to "any `$(`" turns the second group red — and the
//! second group is not decoration, it is the shape the census found 56 times in real
//! traffic.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases so a verdict difference
/// can only come from the substitution, never from the payload.
///
/// Assembled rather than written literally: the live guard denies this source file
/// being written by an agent otherwise, which is the guard working.
fn trigger() -> String {
    format!("rm -{}f /", "r")
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

fn assert_body_visible(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        masked.contains(&trigger()),
        "body was masked away, so no rule can read it ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

fn assert_body_masked(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        !masked.contains(&trigger()),
        "body should stay masked ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

/// `cmd <<'EOF'` with the trigger as its body, wrapped by the caller.
fn sink(receiver: &str) -> String {
    format!("{receiver} <<'EOF'\n{}\nEOF\n", trigger())
}

// ---------------------------------------------------------------------------
// The bypass: the body reaches an interpreter and must be readable by the packs.
// ---------------------------------------------------------------------------

#[test]
fn eval_of_a_command_substitution_is_code() {
    let cmd = format!("eval \"$({})\"", sink("cat"));
    assert_body_visible(&cmd, "eval executes the substitution's text");
    assert_denied(&cmd, "eval executes the substitution's text");
}

#[test]
fn eval_of_a_backtick_substitution_is_code() {
    let cmd = format!("eval \"`{}`\"", sink("cat"));
    assert_body_visible(&cmd, "backticks are a command substitution too");
    assert_denied(&cmd, "backticks are a command substitution too");
}

#[test]
fn a_process_substitution_run_by_a_shell_is_code() {
    for shell in ["bash", "sh", "zsh", "dash", "ksh", "/bin/bash", "/bin/sh"] {
        let cmd = format!("{shell} <({})", sink("cat"));
        assert_body_visible(&cmd, "the shell opens and runs the substitution's file");
        assert_denied(&cmd, "the shell opens and runs the substitution's file");
    }
}

#[test]
fn sourcing_a_process_substitution_is_code() {
    for verb in ["source", "."] {
        let cmd = format!("{verb} <({})", sink("cat"));
        assert_body_visible(&cmd, "source runs the substitution's file in this shell");
        assert_denied(&cmd, "source runs the substitution's file in this shell");
    }
}

#[test]
fn a_shell_with_dash_c_executes_the_substitution() {
    for shell in ["bash", "sh", "zsh"] {
        let cmd = format!("{shell} -c \"$({})\"", sink("cat"));
        assert_body_visible(&cmd, "-c makes the argument a program");
        assert_denied(&cmd, "-c makes the argument a program");
    }
}

#[test]
fn a_substitution_in_command_position_is_code() {
    // Nothing consumes the result: the shell runs it as the command word.
    let cmd = format!("$({})", sink("cat"));
    assert_body_visible(&cmd, "the substitution IS the command");
    assert_denied(&cmd, "the substitution IS the command");
}

#[test]
fn a_variable_captured_then_evaluated_is_code() {
    for tail in ["eval \"$V\"", "eval \"${V}\"", "bash -c \"$V\""] {
        let cmd = format!("V=$({}); {tail}", sink("cat"));
        assert_body_visible(&cmd, "the capture is executed later in the same command");
        assert_denied(&cmd, "the capture is executed later in the same command");
    }
}

#[test]
fn an_env_assignment_does_not_hide_the_executing_word() {
    let cmd = format!("LC_ALL=C eval \"$({})\"", sink("cat"));
    assert_body_visible(&cmd, "NAME=value is not the command word");
    assert_denied(&cmd, "NAME=value is not the command word");
}

#[test]
fn nesting_does_not_hide_the_outer_executor() {
    // The innermost substitution's enclosing command is `printf`, a data sink.
    // The body still reaches `eval`, so every open level has to be consulted.
    let cmd = format!("eval \"$(printf '%s' \"$({})\")\"", sink("cat"));
    assert_body_visible(&cmd, "the outer level is the one that executes");
    assert_denied(&cmd, "the outer level is the one that executes");
}

#[test]
fn a_herestring_into_an_executed_substitution_is_code() {
    let cmd = format!("eval \"$(cat <<<'{}')\"", trigger());
    let masked = mask_non_executing_heredocs(&cmd);
    assert!(
        masked.contains(&trigger()),
        "here-string body was masked away: {cmd:?}\nmasked: {masked:?}"
    );
    assert_denied(&cmd, "a here-string is the same class");
}

// ---------------------------------------------------------------------------
// The cost: what spec 333 exists to protect must still be masked.
//
// These are not hypotheticals. `baqrr-census.py` counted, across spec 333's two
// populations, 41 `git commit -m "$(cat <<'EOF' ...)"` rows and 15
// `br create -d "$(cat <<'EOF' ...)"` rows. Turning those into denials is a
// worse defect than the bypass this file closes.
// ---------------------------------------------------------------------------

#[test]
fn a_plain_capture_is_still_data() {
    let cmd = format!("V=$({})", sink("cat"));
    assert_body_masked(&cmd, "captured and never executed");
}

#[test]
fn a_capture_that_is_only_printed_is_still_data() {
    let cmd = format!("V=$({}); echo \"$V\"", sink("cat"));
    assert_body_masked(&cmd, "echo is not an executor");
}

#[test]
fn an_eval_of_a_different_variable_is_still_data() {
    // The variable check is name-specific: an `eval` in the remainder that names
    // some OTHER variable says nothing about this heredoc.
    let cmd = format!("V=$({}); eval \"$OTHER\"", sink("cat"));
    assert_body_masked(&cmd, "the eval does not name this capture");
}

#[test]
fn the_commit_message_idiom_is_still_data() {
    for enclosing in [
        "git commit -m",
        "git commit -q -m",
        "br create \"a title\" -d",
        "gh pr create --body",
        "curl -d",
        "jq --arg body",
        "echo",
        "printf '%s'",
    ] {
        let cmd = format!("{enclosing} \"$({})\"", sink("cat"));
        assert_body_masked(&cmd, "an argument is not a program");
    }
}

#[test]
fn a_dash_c_flag_on_a_non_shell_is_still_data() {
    // `git -c` and `docker -c` are configuration flags, not program text.
    for enclosing in ["git -c user.name=x commit -m", "docker -c ctx exec -e"] {
        let cmd = format!("{enclosing} \"$({})\"", sink("cat"));
        assert_body_masked(&cmd, "-c only means 'a program follows' for a shell");
    }
}

#[test]
fn a_process_substitution_into_a_data_sink_is_still_data() {
    for enclosing in ["diff", "cmp", "comm -12", "wc -l", "grep -f"] {
        let cmd = format!("{enclosing} <({}) other.txt", sink("cat"));
        assert_body_masked(
            &cmd,
            "the enclosing command reads the file, it does not run it",
        );
    }
}

#[test]
fn a_bare_heredoc_is_untouched_by_this_gate() {
    assert_body_masked(&sink("cat"), "no substitution anywhere");
    assert_body_masked(&sink("tee /tmp/x"), "no substitution anywhere");
}

#[test]
fn arithmetic_expansion_is_not_a_substitution() {
    let cmd = format!("echo $((1 + 2)) && cat <<'EOF'\n{}\nEOF\n", trigger());
    assert_body_masked(&cmd, "$(( is arithmetic, and it closes before the heredoc");
}

#[test]
fn a_single_quoted_dollar_paren_opens_nothing() {
    let cmd = format!("echo 'eval $(' && cat <<'EOF'\n{}\nEOF\n", trigger());
    assert_body_masked(&cmd, "a substitution cannot open inside single quotes");
}

// ---------------------------------------------------------------------------
// The pipeline gate must be unaffected in both directions.
// ---------------------------------------------------------------------------

#[test]
fn the_pipeline_gate_still_denies_and_still_masks() {
    // The pipe belongs on the OPERATOR's line: the body starts on the next one.
    let piped = format!("cat <<'EOF' | bash\n{}\nEOF\n", trigger());
    assert_body_visible(&piped, "j6ha9's case, unchanged");
    assert_denied(&piped, "j6ha9's case, unchanged");

    let to_sink = format!("cat <<'EOF' | jq .\n{}\nEOF\n", trigger());
    assert_body_masked(&to_sink, "j6ha9's data case, unchanged");
}
