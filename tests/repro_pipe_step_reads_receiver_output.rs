//! The pipeline step of `heredoc_language` must not name the body's language
//! from a program that consumes the RECEIVER'S OUTPUT (`.agent-config-y031o`).
//!
//! `heredoc_language` asks three readers in order: the receiver's own name, the
//! first `|`-separated stage on the operator's line, then the wrapper-aware
//! `detect` chain. Step 2 assumes whatever follows the operator RECEIVES the
//! body, which holds for `cat <<'EOF' | python3` -- `cat` writes the body to
//! its stdout, so the pipe destination really is the interpreter.
//!
//! It does not hold when the receiver EXECUTES the body. Then the receiver has
//! already consumed stdin, and the pipe destination reads the interpreter's
//! OUTPUT. `sudo -u root python3 <<'PY' | sh` resolves its receiver to `root`
//! (the reader skips `sudo` and the `-u` flag but not the flag's argument), so
//! step 1 returns Unknown, step 2 reads `sh`, and the body -- python -- is
//! matched as bash. Every `heredoc.python:*` rule is skipped. `| node fmt.js`
//! reads it as javascript the same way. `python3 <<'PY' | sh`, python printing
//! shell for sh to run, is an ordinary idiom and not a corner.
//!
//! The fix asks step 2 only when the receiver PASSES ITS STDIN THROUGH: no
//! receiver at all, or one `is_non_executing_heredoc_command` already
//! recognises as a data sink (`cat`, `tee`, `grep`, ...). That reuses the
//! allowlist this repository already maintains for masking rather than adding
//! a second list of interpreters, and it is the conservative direction: when
//! step 2 is skipped the reading falls to `detect`, whose own Priority 1b
//! still consults pipe destinations, so `foo <<'EOF' | python3` with an
//! unrecognised producer keeps the language it had.
//!
//! FOUND 2026-09-18 by cold review 4 of `.agent-config-7vu4q` (finding B3,
//! `thoughts/shared/handoffs/20260918-7vu4q-herestring-language/lanes/cold-review-4.md`).
//! A regression on `main` since `heredoc_language` (`.agent-config-w7xjw`,
//! `88777c5c`): before it, these commands reached `detect` and denied.
//!
//! SCOPE. Here-strings are `ScriptLanguage::Bash` unconditionally on this tree
//! (`extract_herestrings`), so their twins cannot deny by a python rule here.
//! Routing them through this reader is `.agent-config-7vu4q`, unlanded; when it
//! lands they inherit this fix because they inherit this function.
//!
//! WHICH ROW IS A KILL, and THE MUTANTS: see the tables appended below, each
//! measured on this tree.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The rule every kill row must deny by.
///
/// Named, not merely "some deny": a denial by the fallback sweep or by an outer
/// `core.*` pattern would also be a non-zero-noise "blocked" and would prove
/// nothing about which language the body was read as. This ruleId can only come
/// from the heredoc AST matcher reading python it actually holds.
const PYTHON_RMTREE: &str = "heredoc.python:shutil_rmtree";

/// The destructive python body, assembled at run time.
///
/// Spelled in parts because this repository's own guard is installed on the
/// machine that edits it: a literal `shutil` + `.rmtree(` pair in a file an
/// agent writes through a shell is the thing dcg exists to stop, and a probe
/// that cannot be written is a probe that never runs.
fn rmtree_body() -> String {
    format!("import shutil; shutil.{}('/srv/data')", "rmtree")
}

fn run_hook(command: &str) -> (String, String, i32) {
    let (mut cmd, sandbox) = spawn::dcg();
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");
    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }
    let output = child.wait_with_output().expect("failed to wait for dcg");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn assert_denied_by(command: &str, rule_id: &str, why: &str) {
    let (stdout, stderr, exit_code) = run_hook(command);
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(rule_id),
        "expected a deny by {rule_id} ({why})\ncommand: {command:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (stdout, stderr, exit_code) = run_hook(command);
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("\"permissionDecision\":\"deny\""),
        "expected an allow ({why})\ncommand: {command:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------- kill rows

#[test]
fn an_output_consumer_does_not_name_the_language_of_an_executing_receiver() {
    let command = format!("sudo -u root python3 <<'PY' | sh\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "sh reads python's OUTPUT; the body is still python",
    );
}

#[test]
fn an_output_consumer_naming_another_interpreter_does_not_win_either() {
    let command = format!(
        "sudo -u root python3 <<'PY' | node fmt.js\n{}\nPY",
        rmtree_body()
    );
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "node formats python's OUTPUT; the body is still python",
    );
}

#[test]
fn a_redirection_before_the_output_consumer_does_not_change_that() {
    let command = format!(
        "sudo -u root python3 <<'PY' 2>&1 | node fmt.js\n{}\nPY",
        rmtree_body()
    );
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "2>&1 does not make node the body's reader",
    );
}

// ------------------------------------------------- the pipe step still works

#[test]
fn a_data_sink_receiver_still_takes_the_pipe_destinations_language() {
    let command = format!("cat <<'PY' | python3\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "cat passes its stdin through, so python3 really does read the body",
    );
}

#[test]
fn a_tee_receiver_still_takes_the_pipe_destinations_language() {
    let command = format!("tee saved.py <<'PY' | python3\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "tee passes its stdin through as well as writing it",
    );
}

// ------------------------------------------------------------ fail-open guards

#[test]
fn a_resolvable_receiver_is_unaffected() {
    let command = format!("python3 <<'PY' | sh\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "step 1 resolves python3, so step 2 was never reached for this row",
    );
}

#[test]
fn a_versioned_receiver_is_unaffected() {
    let command = format!("python3.11 <<'PY' | node fmt.js\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "from_command matches version suffixes, so step 1 resolves python3.11",
    );
}

#[test]
fn an_executing_receiver_with_no_pipe_is_unchanged() {
    let command = format!("sudo -u root python3 <<'PY'\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "no pipeline stage at all; the detect fallback already found python3",
    );
}

// ------------------------------------------------ no-false-positive guards

#[test]
fn a_benign_body_under_an_output_consumer_still_allows() {
    assert_allowed(
        "sudo -u root python3 <<'PY' | sh\nprint('hi')\nPY",
        "the fix must not buy its green by denying every piped heredoc",
    );
}

#[test]
fn a_benign_body_behind_a_data_sink_still_allows() {
    assert_allowed(
        "cat <<'PY' | python3\nprint(1)\nPY",
        "the pipe step's own legitimate case must stay quiet on benign bodies",
    );
}
