//! A heredoc body is read in the language of the command that RECEIVES it
//! (`.agent-config-w7xjw`).
//!
//! `extract_heredocs` handed the whole command to `ScriptLanguage::detect`,
//! whose Priority 1 is the command's first word. So every heredoc took the
//! language of whatever interpreter started the input, not of its receiver:
//! a python body behind `node -e '1';` was read as javascript and met no python
//! rule. `echo hi;` in the same place denied, because `echo` names no language
//! and content heuristics found the `import` -- which is what made the hole
//! look like it depended on the prefix's spelling.
//!
//! Measured 2026-09-18 in hook mode, sandboxed like this file (dcg main
//! 76d93747 against the fix):
//!
//! ```text
//!   row                                              | main 76d93747 | fixed
//!   -------------------------------------------------|---------------|------
//!   bash -c 'echo hi'; python3 <<'PY'                | ALLOW         | DENY
//!   node -e '1'; python3 <<'PY'                      | ALLOW         | DENY
//!   node -e '1' NEWLINE python3 <<'PY'               | ALLOW         | DENY
//!   node -e '1'; cat <<'EOF' | python3  (no import)  | ALLOW         | DENY
//!   echo hi; python3 <<'PY'                          | DENY          | DENY
//!   python3 <<'PY' alone                             | DENY          | DENY
//!   sudo -u root python3 <<'PY'  (no import)         | DENY          | DENY
//!   node -e '1' NEWLINE sudo -u root python3 <<'PY'  | ALLOW         | DENY
//!   python3 -c ..; cat <<'EOF' > notes.md            | ALLOW         | ALLOW
//! ```
//!
//! Every DENY is `heredoc.python:shutil_rmtree`, the rule the body itself
//! names, so a deny from some other reader cannot pass a row here.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

const RULE: &str = "heredoc.python:shutil_rmtree";

/// Assembled at runtime so this source file is not itself a payload.
fn rmtree() -> String {
    format!("shutil.{}('/srv/data')", "rmtree")
}

/// A python body WITH an import line, so content heuristics alone name python.
fn imported() -> String {
    format!("import shutil; {}", rmtree())
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

fn assert_denied_by_the_body(command: &str, why: &str) {
    let (rule, stdout, stderr) = hook(command);
    assert_eq!(
        rule.as_deref(),
        Some(RULE),
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The defect: another command's interpreter decided the body's language.
// ---------------------------------------------------------------------------

#[test]
fn a_bash_c_prefix_does_not_make_a_python_body_bash() {
    let cmd = format!("bash -c 'echo hi'; python3 <<'PY'\n{}\nPY", imported());
    assert_denied_by_the_body(&cmd, "python3 receives this body, not bash");
}

#[test]
fn a_node_e_prefix_does_not_make_a_python_body_javascript() {
    let cmd = format!("node -e '1'; python3 <<'PY'\n{}\nPY", imported());
    assert_denied_by_the_body(&cmd, "python3 receives this body, not node");
}

#[test]
fn an_interpreter_on_an_earlier_line_does_not_decide_either() {
    let cmd = format!("node -e '1'\npython3 <<'PY'\n{}\nPY", imported());
    assert_denied_by_the_body(&cmd, "no earlier line can hold the receiver");
}

#[test]
fn the_pipe_destination_decides_before_the_command_head() {
    // No import line: only the pipe destination names python here.
    let cmd = format!("node -e '1'; cat <<'EOF' | python3\n{}\nEOF", rmtree());
    assert_denied_by_the_body(&cmd, "python3 reads cat's output, not node");
}

// ---------------------------------------------------------------------------
// Controls that already denied, so the rows above are not carried by a
// change that denies everything.
// ---------------------------------------------------------------------------

#[test]
fn a_prefix_that_names_no_language_still_denies() {
    let cmd = format!("echo hi; python3 <<'PY'\n{}\nPY", imported());
    assert_denied_by_the_body(&cmd, "the row that always denied");
}

#[test]
fn the_heredoc_alone_still_denies() {
    let cmd = format!("python3 <<'PY'\n{}\nPY", imported());
    assert_denied_by_the_body(&cmd, "the body at top level");
}

#[test]
fn a_receiver_the_reader_cannot_resolve_still_finds_the_interpreter() {
    // `extract_heredoc_target_command` resolves this receiver to `root`: it
    // skips `sudo` and `-u` but not the flag's argument. No import line, so
    // only the wrapper-aware head reader in the fallback names python. This row
    // is why that fallback exists instead of plain content heuristics.
    let cmd = format!("sudo -u root python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "the fallback reads through sudo -u");
}

#[test]
fn the_fallback_starts_at_the_operator_line_not_the_input() {
    // The same unresolvable receiver, with a different interpreter one line up.
    // The fallback must not reach back to it.
    let cmd = format!("node -e '1'\nsudo -u root python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "node is on another line");
}

#[test]
fn a_data_body_after_an_interpreter_prefix_stays_data() {
    let cmd = format!(
        "python3 -c 'print(1)'; cat <<'EOF' > notes.md\n{}\nEOF",
        imported()
    );
    let (rule, stdout, stderr) = hook(&cmd);
    assert_eq!(
        rule, None,
        "cat writes this body to a markdown file; nothing runs it\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}
