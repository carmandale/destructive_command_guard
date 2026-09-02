//! A data-sink heredoc whose stdout feeds a shell interpreter (`.agent-config-j6ha9`).
//!
//! `cat <<'EOF' | bash` was ALLOW on pinned v0.3.0, on the live v0.4.2 build, and
//! on the spec-333 candidate, measured 2026-09-02 with no `DCG_CONFIG` override.
//! `mask_non_executing_heredocs` resolved the heredoc RECEIVER (`cat`), saw a
//! non-executing command, and masked the body out of the matcher; the tier-2 skip
//! in `evaluate_heredoc` dropped the same body for the same reason. Neither looked
//! at what the pipeline did with `cat`'s stdout, so the shell on the right of the
//! pipe executed a body no rule in any pack had been allowed to read.
//!
//! These tests are written from both sides on purpose. The bypass cases pin that
//! the body is now seen; the data cases pin that the masking spec 333 exists to
//! protect did not go with it. Deleting `heredoc_output_reaches_executor`'s two
//! call sites turns the first group red; widening the gate to "any pipe at all"
//! turns the second group red.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Kept identical across cases so a verdict
/// difference can only come from the pipeline, never from the payload.
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
// The bypass: the body reaches a shell.
// ---------------------------------------------------------------------------

#[test]
fn pipe_to_shell_interpreter_is_not_data() {
    for shell in ["bash", "sh", "zsh", "dash", "ksh", "/bin/bash", "/bin/sh"] {
        let cmd = format!("cat <<'EOF' | {shell}\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "the shell on the right of the pipe runs it");
        assert_denied(&cmd, "the shell on the right of the pipe runs it");
    }
}

#[test]
fn pipe_to_shell_denies_for_every_data_sink_receiver() {
    // The receiver is irrelevant once the pipe is there. `tee` and `printf` are
    // as non-executing as `cat`, and just as incapable of stopping `| bash`.
    for receiver in ["cat", "tee /tmp/j6ha9-notes.txt", "grep -v x", "sed -n p"] {
        let cmd = format!("{receiver} <<'EOF' | bash\n{TRIGGER}\nEOF");
        assert_denied(&cmd, "a data-sink receiver does not make the pipe safe");
    }
}

#[test]
fn pipe_through_data_stages_into_a_shell_is_not_data() {
    // The shell is the last stage, not the first. A gate that only inspects the
    // stage immediately after the heredoc misses this.
    let cmd = format!("cat <<'EOF' | grep -v '^#' | bash\n{TRIGGER}\nEOF");
    assert_body_visible(&cmd, "grep passes the body on to bash");
    assert_denied(&cmd, "grep passes the body on to bash");
}

#[test]
fn pipe_to_an_unknown_consumer_is_not_assumed_to_be_data() {
    // Unknown counts as executing. An allowlist of data sinks cannot be defeated
    // by a spelling nobody enumerated; a denylist of interpreters can.
    let cmd = format!("cat <<'EOF' | ssh somehost bash\n{TRIGGER}\nEOF");
    assert_body_visible(&cmd, "ssh is not a known data sink");
}

#[test]
fn line_continuation_does_not_hide_the_pipe() {
    // The heredoc body does not start until the newline that actually ends the
    // command line. A gate that stops at the first physical newline reads the
    // pipeline as absent and masks the body.
    let cmd = format!("cat <<'EOF' \\\n  | bash\n{TRIGGER}\nEOF");
    assert_body_visible(&cmd, "the escaped newline continues the same command line");
}

#[test]
fn here_string_piped_to_a_shell_is_not_data() {
    let cmd = format!("cat <<<'{TRIGGER}' | bash");
    let masked = mask_non_executing_heredocs(&cmd);
    assert!(
        masked.contains(TRIGGER),
        "here-string body was masked away despite the pipe into bash: {masked:?}"
    );
}

// ---------------------------------------------------------------------------
// The masking spec 333 exists to protect: no pipe, or every consumer is data.
// ---------------------------------------------------------------------------

#[test]
fn heredoc_with_no_pipeline_is_still_data() {
    let cmd = format!("cat <<'EOF'\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "nothing downstream consumes it");
    assert_allowed(&cmd, "nothing downstream consumes it");
}

#[test]
fn pipeline_of_data_sinks_is_still_data() {
    for downstream in ["tee /tmp/j6ha9-notes.txt", "grep -v x", "wc -l", "cat"] {
        let cmd = format!("cat <<'EOF' | {downstream}\n{TRIGGER}\nEOF");
        assert_body_masked(&cmd, "every stage is a known data sink");
        assert_allowed(&cmd, "every stage is a known data sink");
    }
}

#[test]
fn multi_stage_pipeline_of_data_sinks_is_still_data() {
    let cmd =
        format!("cat <<'EOF' | grep -v '^#' | sed -n p | tee /tmp/j6ha9-notes.txt\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "three stages, all data sinks");
    assert_allowed(&cmd, "three stages, all data sinks");
}

#[test]
fn env_assignment_before_a_data_sink_is_still_data() {
    // `NAME=value` is the one token bash allows before a stage's command word.
    let cmd = format!("cat <<'EOF' | LC_ALL=C sort\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "the command word is sort, not LC_ALL=C");
}

#[test]
fn or_list_is_not_a_pipe() {
    // `||` runs the right side only on failure, and does not hand it stdin.
    let cmd = format!("cat <<'EOF' || echo failed\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "|| is an or-list, not a pipeline");
}

#[test]
fn a_separator_ends_the_pipeline() {
    for separator in [";", "&&"] {
        let cmd = format!("cat <<'EOF' {separator} bash /tmp/other.sh\n{TRIGGER}\nEOF");
        assert_body_masked(&cmd, "the heredoc's own pipeline ended at the separator");
    }
}

#[test]
fn a_pipe_inside_quotes_is_not_a_pipe() {
    let cmd = format!("grep -E 'a|bash' <<'EOF'\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "the pipe is inside a quoted pattern");
}

// ---------------------------------------------------------------------------
// Found by the cold review of this patch (session 23fd1a42), all measured on a
// build of the first draft. Each one is a character that looks like a pipeline
// separator and is not, or a data sink the allowlist had never heard of.
// ---------------------------------------------------------------------------

#[test]
fn a_redirection_ampersand_does_not_end_the_pipeline() {
    // `2>&1 | bash` is one keystroke from the bead's own case. The first draft
    // read the `&` of the redirection as the `&` that backgrounds a command,
    // stopped scanning, and allowed it.
    for redirect in ["2>&1", ">&2", "2>/dev/null", "1>&2 2>&1"] {
        let cmd = format!("cat <<'EOF' {redirect} | bash\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "a redirection operator is not a separator");
        assert_denied(&cmd, "a redirection operator is not a separator");
    }
}

#[test]
fn a_separator_inside_a_substitution_belongs_to_the_inner_list() {
    // The `;` in `$(true;)` ends the substitution's command list, not this
    // pipeline. The first draft ended its scan there and allowed the `| bash`.
    for substitution in [
        "$(true;)",
        "$(echo a; echo b)",
        "$(echo $(true;))",
        "`true`",
    ] {
        let cmd = format!("cat <<'EOF' {substitution} | bash\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "the separator is inside a substitution");
        assert_denied(&cmd, "the separator is inside a substitution");
    }
}

#[test]
fn a_substitution_does_not_swallow_the_rest_of_the_line() {
    // The mirror of the case above: skipping the `$(...)` span must stop at its
    // closing paren, or every pipeline written after one reads as absent.
    let cmd = format!("cat <<'EOF' $(date) | tee /tmp/j6ha9-notes.txt\n{TRIGGER}\nEOF");
    assert_body_masked(&cmd, "tee is a data sink, and the substitution ended");
}

#[test]
fn a_trailing_pipe_continues_onto_the_next_line() {
    // A line ending in `|` continues, so the stage is the first word of the next
    // line. The first draft saw an empty stage, called it unknown, and denied a
    // legal pipeline of data sinks.
    let data = format!("cat <<'EOF' |\nwc -l\n{TRIGGER}\nEOF");
    assert_body_masked(&data, "wc is the stage, and it is a data sink");

    let code = format!("cat <<'EOF' |\nbash\n{TRIGGER}\nEOF");
    assert_body_visible(&code, "bash is the stage");
}

#[test]
fn modern_data_sinks_are_data_sinks() {
    // The allowlist predates all of these. Denying them is a false positive of
    // exactly the class spec 333 exists to remove, and `rg` is the one AGENTS.md
    // mandates as the search tool.
    for sink in [
        "rg foo", "jq .", "pbcopy", "less", "bat", "yq .a", "tac", "strings",
    ] {
        let cmd = format!("cat <<'EOF' | {sink}\n{TRIGGER}\nEOF");
        assert_body_masked(&cmd, "a known data sink under a newer name");
        assert_allowed(&cmd, "a known data sink under a newer name");
    }
}

// ---------------------------------------------------------------------------
// Cold review round 2 (session 23fd1a42). Round 1's fixes were about the span
// BEFORE the pipe; these are about what is after it, and about not fitting the
// fix to the two examples that produced it.
// ---------------------------------------------------------------------------

#[test]
fn a_process_substitution_beside_a_data_sink_still_gets_the_body() {
    // `tee` is as good a data sink as it ever was. `>(bash)` next to it is what
    // runs the body, and the stage's command word cannot see that.
    for stage in [
        "tee >(bash) >/dev/null",
        "tee >(sh) /tmp/j6ha9-notes.txt",
        "cat >(bash)",
    ] {
        let cmd = format!("cat <<'EOF' | {stage}\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "the process substitution receives the body");
        assert_denied(&cmd, "the process substitution receives the body");
    }

    // Redirected straight into one, with no pipeline at all.
    let redirected = format!("cat <<'EOF' > >(bash)\n{TRIGGER}\nEOF");
    assert_body_visible(&redirected, "redirected into a process substitution");

    // And the mirror: a process substitution into a data sink is still data.
    let sink = format!("cat <<'EOF' | tee >(gzip) /tmp/j6ha9-notes.txt\n{TRIGGER}\nEOF");
    assert_body_masked(&sink, "gzip does not execute what it compresses");
}

#[test]
fn the_here_string_path_is_gated_too() {
    // A distinct call site, and it took the same `&` bug. Pinned separately so a
    // fix to one path cannot silently leave the other open.
    for tail in ["| bash", "2>&1 | bash", "$(true;) | bash"] {
        let cmd = format!("cat <<<'{TRIGGER}' {tail}");
        let masked = mask_non_executing_heredocs(&cmd);
        assert!(
            masked.contains(TRIGGER),
            "here-string body masked away despite `{tail}`: {masked:?}"
        );
    }
}

#[test]
fn more_spellings_of_a_separator_that_is_not_one() {
    // Fitting the fix to `2>&1` and `$(true;)` alone would leave these.
    for prefix in [
        "1>&2 2>&1",
        "3>&1",
        "`true;`",
        "$(echo a; echo b)",
        "2>&1 >/dev/null",
    ] {
        let cmd = format!("cat <<'EOF' {prefix} | bash\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "none of these end the pipeline");
    }
}

#[test]
fn skipping_a_substitution_does_not_stop_the_scan() {
    // The trap in the round-1 fix: implementing "skip `$(...)`" as "give up at
    // `$(`" trades one bypass for another. This case DENIES before the fix and
    // must keep denying after it.
    for prefix in ["$(echo x)", "$(date)", "`hostname`", "$(echo $(echo y))"] {
        let cmd = format!("cat <<'EOF' {prefix} | bash\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "the scan must continue past the substitution");
        assert_denied(&cmd, "the scan must continue past the substitution");
    }
}

#[test]
fn unknown_downstream_stays_executing() {
    // The strongest part of the gate, and the part that is easiest to trade away
    // when a false positive shows up. None of these is an enumerated interpreter
    // name; every one of them is caught by "not a known data sink".
    for stage in [
        "bash -s",
        "timeout 5 bash",
        "nohup bash",
        "( bash )",
        "{ bash; }",
        "perl",
        "ruby",
        "node",
        "tee /tmp/j6ha9-notes.txt | sh",
        "while read l; do eval $l; done",
        "bash 2>/dev/null",
        "sudo bash",
        "tee -a /tmp/j6ha9-notes.txt | some-tool-nobody-enumerated",
    ] {
        let cmd = format!("cat <<'EOF' | {stage}\n{TRIGGER}\nEOF");
        assert_body_visible(&cmd, "unknown downstream counts as executing");
    }
}

#[test]
fn every_listed_receiver_masks_its_body_including_the_new_entries() {
    // The list makes exactly one promise: a command on it does not execute its
    // stdin, so its heredoc body is data. Measured 2026-09-02, that promise
    // holds for every entry probed, including the ones added with this gate.
    //
    // It is NOT the promise "and therefore the command is allowed". `grep <<EOF`
    // and `rg <<EOF` mask correctly here and are still DENIED end to end, by a
    // context-aware path that reads the unmasked command — pre-existing on
    // unpatched main, unrelated to the pipeline, and filed separately. This test
    // pins the masking half, which is the half the gate is built on.
    for receiver in [
        "cat",
        "tee /tmp/j6ha9-notes.txt",
        "grep",
        "egrep",
        "fgrep",
        "sed",
        "awk",
        "sort",
        "wc",
        "base64",
        "gzip",
        "diff",
        "curl",
        "dd",
        // added with the gate
        "rg",
        "ag",
        "ack",
        "jq",
        "yq",
        "less",
        "more",
        "bat",
        "pbcopy",
        "pbpaste",
        "xclip",
        "xsel",
        "tac",
        "shuf",
        "pr",
        "split",
        "csplit",
        "strings",
        "iconv",
        "sponge",
        "pv",
        "base32",
        "basenc",
        "shasum",
        "md5",
        "b2sum",
        "zstd",
        "unzstd",
        "zstdcat",
    ] {
        let cmd = format!("{receiver} <<'EOF'\n{TRIGGER}\nEOF");
        assert_body_masked(&cmd, "a receiver on the non-executing list");
    }
}

#[test]
fn an_executing_receiver_is_unaffected() {
    // The gate only ever removes masking. A heredoc into `bash` was never masked
    // and must still be denied.
    let cmd = format!("bash <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the receiver itself executes the body");
}
