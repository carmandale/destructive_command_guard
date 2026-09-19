//! The pipeline step of `heredoc_language` must not name the body's language
//! from a program that consumes the RECEIVER'S OUTPUT (`.agent-config-y031o`).
//!
//! `heredoc_language` asks three readers in order: the receiver's own name, the
//! first `|`-separated stage of the operator's pipeline, then the `detect`
//! chain. Step 2 assumes that stage RECEIVES the body, which holds for
//! `cat <<'EOF' | python3`: `cat` writes the body to python's stdin.
//!
//! It does not hold when the receiver EXECUTES the body. Then the receiver has
//! already consumed stdin and the stage after it reads that program's OUTPUT.
//! `python3 <<'PY' | sh` -- python emitting shell for `sh` to run -- is an
//! ordinary idiom, and it was being matched as bash, skipping every
//! `heredoc.python` rule. `| node fmt.js` read the same body as javascript.
//!
//! WHY THE GUARD IS `is_some_and` AND NOT `is_none_or`. `extract_heredoc_target_command`
//! returns None for a receiver it cannot resolve, and None is UNKNOWN, not
//! "nothing consumes the body". `python3.11` is exactly that: `from_command`
//! does match a digits-and-dots version suffix, but the receiver reader does not
//! hand it over, so step 1 returns nothing and step 2 decided. Treating None as
//! pass-through would have left every row below allowing.
//!
//! Nothing is lost when step 2 declines, and that is measured, not assumed: the
//! fallback runs `detect`, whose Priority 1 is the wrapper-aware head reader --
//! it resolves `python3.11` AND `sudo -u root python3`, which is why both deny
//! with no pipeline at all -- and whose Priority 1b still consults pipe
//! destinations, which is why `<<'PY' | python3` with no receiver keeps its
//! language.
//!
//! FOUND 2026-09-18 by cold review 4 of `.agent-config-7vu4q` (finding B3).
//! A regression since `heredoc_language` (`.agent-config-w7xjw`, `88777c5c`).
//! Here-strings reach the same reader since `.agent-config-7vu4q` (`7f51cca9`),
//! so their twins are pinned here too.
//!
//! WHICH ROW IS A KILL, measured on `origin/main` 71b04bbd by mutant M2 below,
//! which restores the unconditional step 2 and is therefore byte-equivalent to
//! unfixed main. Hook mode via `spawn::dcg()`.
//!
//! ```text
//!   row                                                   | unfixed | fixed
//!   -------------------------------------------------------|---------|------
//!   a_versioned_receiver_is_not_overridden_by_a_consumer    | RED     | green
//!   a_versioned_herestring_twin_is_not_overridden_either    | RED     | green
//!   an_output_consumer_does_not_name_the_language_...       | green   | green
//!   an_output_consumer_naming_another_interpreter_...       | green   | green
//!   a_redirection_before_the_output_consumer_...            | green   | green
//!   a_herestring_twin_is_not_overridden_either              | green   | green
//!   a_data_sink_receiver_still_takes_...                    | green   | green
//!   a_tee_receiver_still_takes_...                          | green   | green
//!   a_receiverless_heredoc_still_takes_...                  | green   | green
//!   a_resolvable_receiver_is_unaffected                     | green   | green
//!   an_executing_receiver_with_no_pipe_is_unchanged         | green   | green
//!   a_benign_body_under_an_output_consumer_still_allows     | green   | green
//!   a_benign_body_behind_a_data_sink_still_allows           | green   | green
//! ```
//!
//! ONLY TWO ROWS ARE KILLS TODAY, and saying otherwise would overstate this
//! change. The four `sudo -u root python3` rows WERE red -- measured on
//! `7f51cca9`, before `.agent-config-a09gf` landed, where M2 turned six rows
//! red. a09gf taught the receiver reader to resolve THROUGH a wrapper's
//! options, so `sudo -u root python3` now resolves at step 1 and never reaches
//! step 2. Those four rows are kept as REGRESSION GUARDS, not as evidence for
//! this fix: they go red again the moment that resolution regresses, and they
//! are the only rows that would notice.
//!
//! What a09gf could not reach is a receiver the reader returns None for.
//! `python3.11` is that case, and it is why this bead stayed open after a09gf:
//! the two surviving kill rows are both versioned-interpreter rows.
//!
//! The three `still_takes` rows are the control that matters most: they prove
//! step 2 still fires where it is earned, so a green kill row means the reader
//! changed and not that step 2 was deleted.
//! `a_receiverless_heredoc_still_takes_...` pins the guard from the other side
//! -- it passes only because `detect`'s Priority 1b still consults pipe
//! destinations. The two benign rows are the fail-open guards: the fix must not
//! buy its green by denying every piped heredoc.
//!
//! THE MUTANTS, each run on `origin/main` 71b04bbd and each restored after:
//!
//! ```text
//!   mutant                                    | rows it turns red
//!   -------------------------------------------|-------------------------------
//!   M1  `is_some_and` -> `is_none_or`          | the two versioned rows (2)
//!   M2  delete the guard (unconditional        | the two versioned rows (2)
//!         step 2, i.e. unfixed main)           |
//! ```
//!
//! M1 and M2 are caught by the same two rows on this tree, so M1 adds no
//! discriminating power HERE -- it is kept because it is the mutant a reviewer
//! would expect to be equivalent and is not. On the pre-a09gf tree the two
//! differ: M2 turned all six red while M1 turned only these two, because
//! `sudo -u root python3` resolved its receiver to `Some("root")` and
//! `is_none_or` still returned false for it. That is the measurement that chose
//! `is_some_and`: treating a None receiver as pass-through would have shipped a
//! fix that left both surviving kill rows open.
//!
//! A NOTE THAT WAS HERE IS GONE, and why, because the trap it fell into is the
//! one `rmtree_body_dq` below exists to prevent. It claimed
//! `cat <<< BODY | python3` was an unfixed data-sink hole, from a probe row
//! that spelled the body single-quoted INSIDE a single-quoted here-string.
//! Bash dequotes that to `shutil.rmtree(/srv/data)` -- a SyntaxError, not a
//! call -- so the ALLOW was correct and measured nothing. With the
//! double-quoted body that row denies, and
//! `receivers_the_word_reader_misses_are_read_like_their_heredoc_twins` in
//! `repro_herestring_language_from_receiver.rs` already pins it.
//! Caught by the `.agent-config-dcg-herestring-datasink-pipe-veto-mv3na` lane
//! and re-measured here before removal.

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

/// The same body with DOUBLE quotes, for use inside a single-quoted here-string.
///
/// `<<< '...'` ends at the first single quote, so the single-quoted spelling
/// would truncate the body to `import shutil; shutil.rmtree(` -- which matches
/// no rule. The row would then pass for the wrong reason before the fix and
/// fail for the wrong reason after it; measured, it failed exactly that way.
fn rmtree_body_dq() -> String {
    format!("import shutil; shutil.{}(\"/srv/data\")", "rmtree")
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
fn a_versioned_receiver_is_not_overridden_by_a_consumer() {
    let command = format!("python3.11 <<'PY' | node fmt.js\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "the receiver reader yields nothing for python3.11, so step 2 must decline",
    );
}

#[test]
fn a_herestring_twin_is_not_overridden_either() {
    let command = format!("sudo -u root python3 <<< '{}' | sh", rmtree_body_dq());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "here-strings reach this reader since 7vu4q, so they inherit the fix",
    );
}

#[test]
fn a_versioned_herestring_twin_is_not_overridden_either() {
    let command = format!("python3.11 <<< '{}' | node fmt.js", rmtree_body_dq());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "the here-string twin of the versioned row",
    );
}

#[test]
fn a_receiverless_heredoc_still_takes_the_pipe_destinations_language() {
    let command = format!("<<'PY' | python3\n{}\nPY", rmtree_body());
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "no receiver at all: detect's Priority 1b must still find python3",
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
