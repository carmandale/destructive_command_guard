//! An argv list whose command HEAD is an absolute path or not a literal
//! (`.agent-config-dcg-argv-command-head-dxnfo`).
//!
//! An argv list is invisible to the outer `core.filesystem` pack: its words
//! are separate string literals and never form contiguous shell text, so the
//! python argv reader (`.agent-config-ei4it`) is the only thing that judges
//! it. That reader hands the list to the shared command reader, which is also
//! the reader for every other payload language. Two spellings of the head
//! were in question:
//!
//! * **An absolute path** (`/bin/<rm>`). The shared reader compares the
//!   command, and every wrapper it skips, by BASENAME (`.agent-config-w9pvb`),
//!   so `/bin/<rm>` is `<rm>` in every language at once. These tests pin that
//!   for the python list; `a_spawn_sync_of_rm_by_path_denies` in
//!   `repro_js_child_process_receiver.rs` pins the same basename for a node
//!   argv.
//! * **A non-literal head** (`[tool, ...]`). DECIDED: the unread head is
//!   skipped and the literal words after it are judged -- the verdict the
//!   outer shell pack already gives the same words as shell text, where
//!   `"$TOOL" <rm> <-rf> /srv/data` denies and `"$TOOL" <-rf> /srv/data`
//!   allows. Bailing out on an unreadable head was rejected: it would allow
//!   `[tool, <rm>, <-rf>, /srv/data]` while its string spelling denies, making
//!   the list spelling of a command the weaker one again -- the defect ei4it
//!   exists to fix. Each non-literal row below is paired with its shell-text
//!   control, so the pair is what is pinned, not a verdict in isolation.
//!   The known cost is the shell pack's too: `[GIT, <rm>, -r, -f, --cached,
//!   /opt/app]` reads as a delete, as `"$GIT" <rm> -r -f --cached /opt/app`
//!   does. Python only: a node `spawnSync(tool, [...])` still takes no verdict
//!   from its argv (`.agent-config-yfi78`).
//!
//! Measured in hook mode, sandboxed by `tests/common/spawn.rs`. The first
//! column is the installed release that the bead measured (no argv reader at
//! all); the second is this commit.
//!
//! ```text
//!   row                                                     | release | here
//!   --------------------------------------------------------|---------|------
//!   python  [/bin/<rm>, <-rf>, /srv/data]                    | ALLOW   | DENY
//!   python  [/usr/bin/<rm>, <-rf>, /srv/data]                | ALLOW   | DENY
//!   python  [/usr/bin/sudo, /bin/<rm>, <-rf>, /srv/data]     | ALLOW   | DENY
//!   python  [/usr/bin/git, reset, --hard]                    | ALLOW   | DENY
//!   python  [tool, <rm>, <-rf>, /srv/data]                   | ALLOW   | DENY
//!   control: shell  "$TOOL" <rm> <-rf> /srv/data             | DENY    | DENY
//!   python  [tool, <-rf>, /srv/data]         (bead row)      | ALLOW   | ALLOW
//!   control: shell  "$TOOL" <-rf> /srv/data                  | ALLOW   | ALLOW
//!   python  [/bin/ls, -la, /srv/data]                        | ALLOW   | ALLOW
//!   python  [/bin/<rm>, <-rf>, /tmp/build]  (not catastrophic) | ALLOW  | ALLOW
//!   python  [tool, --version] / [tool, status]               | ALLOW   | ALLOW
//!   accepted gap: python  [git_bin, reset, --hard]           | ALLOW   | ALLOW
//!   control: shell  "$GIT" reset --hard                      | ALLOW   | ALLOW
//! ```
//!
//! The accepted gap is the decision's other face: an unread head that IS the
//! command leaves words that name none, in a list as in shell text.
//!
//! `<rm>` and `<-rf>` stand for the argv strings that name a recursive force
//! delete. Spelled out, this file would be a payload, and the live guard would
//! refuse to let anyone edit it.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Assembled at runtime so this source file is not itself a payload.
fn rm() -> &'static str {
    "r\u{6d}"
}

fn recursive_force() -> &'static str {
    "-r\u{66}"
}

/// A python string literal.
fn lit(s: &str) -> String {
    format!("'{s}'")
}

/// `python3 -c` running `subprocess.run` over a list whose items are python
/// EXPRESSIONS, so a test can put a name where a literal would be.
fn python_run(items: &[String]) -> String {
    format!(
        "python3 -c \"import subprocess; subprocess.run([{}])\"",
        items.join(", ")
    )
}

/// `(ruleId, stdout, stderr)` from the hook; `ruleId` is `None` when it
/// allowed. Default policy, `core` packs, as `tests/common/spawn.rs` sets them.
fn hook(command: &str) -> (Option<String>, String, String) {
    let (mut cmd, sandbox) = spawn::dcg();
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");
    child
        .stdin
        .as_mut()
        .expect("failed to get stdin")
        .write_all(input.as_bytes())
        .expect("failed to write to stdin");
    let output = child.wait_with_output().expect("failed to wait for dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook mode exits 0 whatever the verdict\nstderr: {stderr}"
    );
    if stdout.trim().is_empty() {
        return (None, stdout, stderr);
    }
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hook stdout is not JSON ({e}): {stdout}"));
    let hook = &json["hookSpecificOutput"];
    assert_eq!(
        hook["permissionDecision"].as_str(),
        Some("deny"),
        "a printed verdict is a deny\nstdout: {stdout}"
    );
    let rule = hook["ruleId"]
        .as_str()
        .unwrap_or_else(|| panic!("deny without a ruleId: {stdout}"))
        .to_string();
    (Some(rule), stdout, stderr)
}

fn assert_denied_by(command: &str, rule: &str, why: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got.as_deref(),
        Some(rule),
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got, None,
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

const RM_RF_CATASTROPHIC: &str = "heredoc.python:subprocess_run.rm_rf_catastrophic";

// ---------------------------------------------------------------------------
// An absolute-path head is read by its basename.
// ---------------------------------------------------------------------------

#[test]
fn an_absolute_path_head_is_read_by_its_basename() {
    for dir in ["/bin", "/usr/bin"] {
        let cmd = python_run(&[
            lit(&format!("{dir}/{}", rm())),
            lit(recursive_force()),
            lit("/srv/data"),
        ]);
        assert_denied_by(
            &cmd,
            RM_RF_CATASTROPHIC,
            "an absolute path is the same command as its basename",
        );
    }
}

#[test]
fn an_absolute_path_wrapper_is_skipped_by_its_basename() {
    let cmd = python_run(&[
        lit("/usr/bin/sudo"),
        lit(&format!("/bin/{}", rm())),
        lit(recursive_force()),
        lit("/srv/data"),
    ]);
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "/usr/bin/sudo is a wrapper exactly as sudo is",
    );
}

#[test]
fn an_absolute_path_git_is_read_by_its_basename() {
    let cmd = python_run(&[lit("/usr/bin/git"), lit("reset"), lit("--hard")]);
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_run.git_reset_hard",
        "/usr/bin/git is git",
    );
}

// ---------------------------------------------------------------------------
// A non-literal head: the words that ARE there are judged, as shell text is.
// ---------------------------------------------------------------------------

#[test]
fn a_non_literal_head_is_skipped_and_the_words_after_it_are_judged() {
    let cmd = python_run(&[
        "tool".to_string(),
        lit(rm()),
        lit(recursive_force()),
        lit("/srv/data"),
    ]);
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "an unreadable head must not hide the command after it -- the string spelling denies",
    );
}

#[test]
fn control_the_same_words_as_shell_text_deny() {
    // The parity the row above is held to: the outer pack judges the words
    // after an unknown head.
    let cmd = format!("\"$TOOL\" {} {} /srv/data", rm(), recursive_force());
    assert_denied_by(
        &cmd,
        "core.filesystem:rm-rf-root-home",
        "shell text with an unknown head is judged by the words after it",
    );
}

#[test]
fn a_non_literal_head_before_a_bare_flag_names_no_command() {
    // The bead's row: after the unread head, `<-rf> /srv/data` names no
    // command, so nothing in the argv can deny the call.
    let cmd = python_run(&["tool".to_string(), lit(recursive_force()), lit("/srv/data")]);
    assert_allowed(
        &cmd,
        "a flag after an unread head is an argument of an unknown program",
    );
}

#[test]
fn control_the_same_words_as_shell_text_allow() {
    let cmd = format!("\"$TOOL\" {} /srv/data", recursive_force());
    assert_allowed(
        &cmd,
        "shell text with an unknown head and no command word allows",
    );
}

// ---------------------------------------------------------------------------
// What must still be allowed.
// ---------------------------------------------------------------------------

#[test]
fn a_harmless_absolute_path_argv_still_allows() {
    let cmd = python_run(&[lit("/bin/ls"), lit("-la"), lit("/srv/data")]);
    assert_allowed(&cmd, "reading the basename must not make ls destructive");
}

#[test]
fn an_absolute_path_delete_of_a_build_dir_still_allows() {
    let cmd = python_run(&[
        lit(&format!("/bin/{}", rm())),
        lit(recursive_force()),
        lit("/tmp/build"),
    ]);
    assert_allowed(
        &cmd,
        "a non-catastrophic target does not deny, however the head is spelled",
    );
}

#[test]
fn a_non_literal_head_with_harmless_arguments_still_allows() {
    for arg in ["--version", "status"] {
        let cmd = python_run(&["tool".to_string(), lit(arg)]);
        assert_allowed(&cmd, "an unread head with harmless words is not a finding");
    }
}
