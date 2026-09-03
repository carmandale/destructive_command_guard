//! Three seams BETWEEN the pipeline gate and the substitution gate
//! (`.agent-config-tuw7m`).
//!
//! Neither gate is wrong. `heredoc_output_reaches_executor` owns "whose stdin
//! does the body land on", scoped to the heredoc's own command line.
//! `heredoc_substitution_result_is_executed` owns "does a substitution splice
//! the body into something that runs it". Nothing owned the COMPOSITION: what
//! happens to the enclosing command's stdout once a substitution has already
//! carried the body out, and what happens to a captured variable's value once it
//! is expanded again.
//!
//! All three rows below were measured ALLOW on the installed `069e4634`, on
//! `1e113950` and on pinned `v0.3.0` by the `.agent-config-y6cd` cold reviewer
//! (2026-09-02), each verified to really execute with a benign marker payload.
//! They are pre-existing, not opened by the substitution gate.
//!
//! Written from both sides, like its two neighbours. The bypass group pins that
//! the body is now seen; the data group pins that spec 333's masking did not go
//! with it. Widening any of the three fixes to "any pipe at all", "any quote at
//! all" or "any later expansion at all" turns the data group red.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases on purpose, so a
/// verdict difference can only come from the plumbing, never from the payload.
const TRIGGER: &str = "rm -rf /";

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

fn assert_body_visible(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        masked.contains(TRIGGER),
        "body was masked away, so no rule can read it ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

fn assert_body_masked(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        !masked.contains(TRIGGER),
        "body should stay masked ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

// ---------------------------------------------------------------------------
// Seam 1 — a substitution's RESULT is piped into a shell.
//
// The pipe is not on the heredoc's line (it is after the closing paren, two
// lines down), so the pipeline gate never sees it. The enclosing word is `echo`,
// which is in neither EXECUTES_STRING_ARGUMENT nor SHELL_INTERPRETERS, so the
// substitution gate declines. Marker COLDREV_RAN_C1.
// ---------------------------------------------------------------------------

#[test]
fn substitution_result_piped_into_a_shell_is_not_data() {
    for (enclosing, shell) in [
        ("echo", "bash"),
        ("printf %s", "sh"),
        ("echo", "/bin/sh"),
        ("cat", "zsh"),
    ] {
        let cmd = format!("{enclosing} \"$(cat <<'EOF'\n{TRIGGER}\nEOF\n)\" | {shell}");
        assert_body_visible(&cmd, "the shell after the pipe runs the spliced body");
        assert_denied(&cmd, "the shell after the pipe runs the spliced body");
    }
}

#[test]
fn unquoted_substitution_result_piped_into_a_shell_is_not_data() {
    // Without the surrounding double quotes the scan resumes outside a quoted
    // span. Same seam, different quote state at the resume point.
    let cmd = format!("echo $(cat <<'EOF'\n{TRIGGER}\nEOF\n) | bash");
    assert_body_visible(&cmd, "the pipe is still downstream of the substitution");
    assert_denied(&cmd, "the pipe is still downstream of the substitution");
}

#[test]
fn process_substitution_read_then_piped_into_a_shell_is_not_data() {
    // `cat` opens the substitution's file and copies it to stdout; `bash` is on
    // the far side of the pipe. Neither gate alone connects those two facts.
    let cmd = format!("cat <(cat <<'EOF'\n{TRIGGER}\nEOF\n) | bash");
    assert_body_visible(&cmd, "cat forwards the substitution's file to bash");
    assert_denied(&cmd, "cat forwards the substitution's file to bash");
}

#[test]
fn substitution_result_into_a_data_sink_stays_data() {
    // The control for seam 1. `wc`, `tee` and a redirect execute nothing, and
    // widening the composition to "any pipe" turns this red.
    for tail in [
        "| wc -l",
        "| tee /tmp/tuw7m-notes.md",
        "> /tmp/tuw7m-notes.md",
    ] {
        let cmd = format!("echo \"$(cat <<'EOF'\n{TRIGGER}\nEOF\n)\" {tail}");
        assert_body_masked(&cmd, "nothing downstream executes the body");
        assert_allowed(&cmd, "nothing downstream executes the body");
    }
}

#[test]
fn substitution_result_with_no_pipeline_at_all_stays_data() {
    let cmd = format!("echo \"$(cat <<'EOF'\n{TRIGGER}\nEOF\n)\"");
    assert_body_masked(&cmd, "echo prints it and the command ends");
    assert_allowed(&cmd, "echo prints it and the command ends");
}

// ---------------------------------------------------------------------------
// Seam 2 — an escaped quote after the operator swallows the pipe.
//
// The pipeline scanner's quote arm skipped from one quote byte to the next
// matching one without honouring a backslash, while its `\\` arm sat OUTSIDE
// that span. The escaped quote closed the span early, the next quote opened one
// that never closed, and the scan ran off the end reporting "no executor
// downstream" with the pipe still sitting there. The substitution scanner
// handles the backslash BEFORE its quote arms; that asymmetry is the defect.
// Marker COLDREV_RAN_J1.
// ---------------------------------------------------------------------------

#[test]
fn escaped_quote_in_a_redirect_target_does_not_hide_the_pipe() {
    let cmd = format!("cat <<'EOF' 2>\"/private/tmp/a\\\"b\" | bash\n{TRIGGER}\nEOF");
    assert_body_visible(&cmd, "the escaped quote is inside the span, not its end");
    assert_denied(&cmd, "the escaped quote is inside the span, not its end");
}

#[test]
fn escaped_quote_anywhere_on_the_line_does_not_hide_the_pipe() {
    for prefix in [
        "cat <<'EOF' 2>\"a\\\"b\"",
        "cat <<'EOF' >\"x\\\"y\"",
        "tee \"o\\\"p\" <<'EOF'",
    ] {
        let cmd = format!("{prefix} | bash\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "a backslash inside a double-quoted span is an escape");
        assert_denied(&cmd, "a backslash inside a double-quoted span is an escape");
    }
}

#[test]
fn a_backslash_inside_single_quotes_is_literal() {
    // POSIX: single quotes have no escapes at all, so `'a\'` ENDS at the second
    // quote. Treating the backslash as an escape there would run the scan past
    // the real end of the span and invent a stage that is not in the command.
    let cmd = format!("cat <<'EOF' 2>'a\\' | bash\n{TRIGGER}\nEOF");
    assert_body_visible(&cmd, "the single-quoted span ends at the second quote");
    assert_denied(&cmd, "the single-quoted span ends at the second quote");
}

#[test]
fn escaped_quote_without_a_pipe_stays_data() {
    // The control for seam 2: honouring the escape must not conjure a stage.
    let cmd = format!("cat <<'EOF' 2>\"/private/tmp/a\\\"b\"\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "there is no pipeline, only a redirect");
    assert_allowed(&cmd, "there is no pipeline, only a redirect");
}

#[test]
fn a_pipe_inside_the_quoted_span_is_still_not_a_pipeline() {
    let cmd = format!("cat <<'EOF' 2>\"/private/tmp/a\\\"b|bash\"\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "the pipe is part of a file name");
    assert_allowed(&cmd, "the pipe is part of a file name");
}

// ---------------------------------------------------------------------------
// Seam 3 — capture, then pipe the expansion into a bare shell.
//
// `captured_variable_is_executed` cleared a shell word only when the remainder
// also held a literal `-c`. Piping into a bare `sh` has no `-c`, so the route
// was open. Marker COLDREV_RAN_I3.
// ---------------------------------------------------------------------------

#[test]
fn captured_body_piped_into_a_bare_shell_is_not_data() {
    for tail in [
        "printf %s \"$V\" | sh",
        "echo \"$V\" | bash",
        "printf %s \"${V}\" | /bin/sh",
        "echo $V | zsh",
    ] {
        let cmd = format!("V=$(cat <<'EOF'\n{TRIGGER}\nEOF\n); {tail}");
        assert_body_visible(&cmd, "the expansion is piped into a shell with no -c");
        assert_denied(&cmd, "the expansion is piped into a shell with no -c");
    }
}

#[test]
fn captured_body_piped_through_a_data_stage_into_a_shell_is_not_data() {
    let cmd = format!("V=$(cat <<'EOF'\n{TRIGGER}\nEOF\n); printf %s \"$V\" | grep -v '^#' | sh");
    assert_body_visible(&cmd, "grep passes the value on to sh");
    assert_denied(&cmd, "grep passes the value on to sh");
}

#[test]
fn captured_body_piped_into_a_data_sink_stays_data() {
    // The control for seam 3, and the shape this fleet actually writes.
    for tail in [
        "printf %s \"$V\" | wc -l",
        "printf %s \"$V\" > /tmp/tuw7m-notes.md",
        "echo \"$V\" | rg trigger",
        "br create --slug source-truth -d \"$V\"",
    ] {
        let cmd = format!("V=$(cat <<'EOF'\n{TRIGGER}\nEOF\n); {tail}");
        assert_body_masked(&cmd, "nothing downstream of the expansion executes it");
        assert_allowed(&cmd, "nothing downstream of the expansion executes it");
    }
}

#[test]
fn a_different_variable_downstream_of_a_shell_is_not_this_capture() {
    // `variable_mention_ends` already refuses `$VERBOSE` for `V`; the composition
    // must not reintroduce the substring match through the back door.
    let cmd = format!("V=$(cat <<'EOF'\n{TRIGGER}\nEOF\n); printf %s \"$VERBOSE\" | sh");
    assert_body_masked(&cmd, "the piped variable is a different one");
    assert_allowed(&cmd, "the piped variable is a different one");
}
