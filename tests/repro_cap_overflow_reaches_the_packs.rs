//! A construct past `max_heredocs` is still read by the packs
//! (`.agent-config-dcg-cap-overflow-fallback-lacks-packs-nvs11`).
//!
//! The cap bounds the per-language AST pass. It used to end the reading too: a
//! construct past it met only the fallback sweep, a short fixed pattern list
//! with no `git clean` in it. The ordinary pack scan does not see the payload
//! either -- it is quoted data in the raw command. So ten harmless here-strings
//! in front of `bash <<< 'git clean -fdx'` ALLOWED, while the same payload on
//! its own denies by `core.git:clean-force`.
//!
//! Now the constructs past the cap are located again and each gets everything
//! but the AST pass: the inert and nested-in-inert skips, and for shell content
//! the Tier 2.5 pack reading. Their text stays unjudged, so the sweep still
//! reads it (the python floor row).
//!
//! FOUND 2026-09-18 by the cold review of `.agent-config-bjjic` (finding M1):
//! the hole predates bjjic, which made the padding's quoting irrelevant by
//! reading here-strings in source order.
//!
//! WHICH ROW KILLS WHICH MUTANT is recorded in the bead's close reason with the
//! raw runner output, not here.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Assembled at run time: this repository's guard runs on the machine that
/// edits it, and a probe that cannot be written never runs.
fn clean() -> String {
    format!("git {} -fdx", "clean")
}

fn push_force() -> String {
    format!("git {} --force origin main", "push")
}

/// The padding: ten constructs, which fill the default cap.
fn pad(one: &str) -> String {
    one.repeat(10)
}

/// The deny's rule id, or `None` for an allow (empty hook output).
fn hook(command: &str) -> Option<(String, String)> {
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
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write hook input");
    let output = child.wait_with_output().expect("wait for dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // dcg exits 0 for an allow AND for a deny, so a non-zero status is dcg
    // failing to answer at all. Without this, a crash reads as an allow.
    assert!(
        output.status.success(),
        "dcg exited {:?} on {command:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    if stdout.trim().is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hook output is JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "non-empty hook output must be a deny: {stdout}"
    );
    let rule = json["hookSpecificOutput"]["ruleId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Some((rule, stdout))
}

fn assert_denied_by(command: &str, rule_id: &str, why: &str) {
    match hook(command) {
        Some((rule, stdout)) => assert_eq!(
            rule, rule_id,
            "denied, but by the wrong rule ({why}): {command:?}\n{stdout}"
        ),
        None => panic!("ALLOWED, want a deny by {rule_id} ({why}): {command:?}"),
    }
}

fn assert_allowed(command: &str, why: &str) {
    if let Some((rule, stdout)) = hook(command) {
        panic!("DENIED as {rule:?}, want allow ({why}): {command:?}\n{stdout}");
    }
}

// ---------------------------------------------------------------------------
// The kill rows
// ---------------------------------------------------------------------------

/// The bead's rows: ten pads of every quoting, then the payload.
#[test]
fn a_payload_past_the_cap_is_read_by_the_packs() {
    let payload = format!("bash <<< '{}'", clean());
    assert_denied_by(
        &payload,
        "core.git:clean-force",
        "control: the payload alone denies by this rule",
    );
    for padding in [
        "cat <<< 'x'; ",
        "cat <<< \"x\"; ",
        "cat <<< x; ",
        "cat <<< $'x'; ",
    ] {
        assert_denied_by(
            &format!("{}{payload}", pad(padding)),
            "core.git:clean-force",
            "ten constructs before it do not stop the packs reading it",
        );
    }
    assert_denied_by(
        &format!("{}bash <<< \"{}\"", pad("cat <<< \"x\"; "), clean()),
        "core.git:clean-force",
        "the double-quoted payload after double-quoted pads",
    );
}

/// A heredoc past the cap, with a pack rule the fallback list never spelled.
#[test]
fn a_heredoc_past_the_cap_is_read_by_the_packs() {
    let heredoc = format!("bash <<'E'\n{}\nE", push_force());
    assert_denied_by(
        &heredoc,
        "core.git:push-force-long",
        "control: the heredoc alone denies by this rule",
    );
    assert_denied_by(
        &format!("{}{heredoc}", pad("cat <<< x; ")),
        "core.git:push-force-long",
        "ten constructs before it do not stop the packs reading it",
    );
}

// ---------------------------------------------------------------------------
// Guards: what the overflow reader must not change
// ---------------------------------------------------------------------------

/// Benign shell past the cap: the packs read it and find nothing.
#[test]
fn benign_shell_past_the_cap_still_allows() {
    assert_allowed(
        &format!("{}bash <<< 'echo hi'", pad("cat <<< x; ")),
        "the packs prove `echo hi` safe",
    );
}

/// A data sink past the cap is data.
#[test]
fn a_data_sink_past_the_cap_still_allows() {
    assert_allowed(
        &format!("{}cat <<< '{}'", pad("cat <<< x; "), clean()),
        "cat prints its here-string",
    );
}

/// Benign python past the cap: no AST pass there, and the sweep finds nothing.
///
/// Inline pads, because inline scripts are read before here-strings: a
/// `python3 -c` after ten here-strings is still inside the cap.
#[test]
fn benign_python_past_the_cap_still_allows() {
    assert_allowed(
        &format!("{}python3 -c 'print(2)'", pad("python3 -c 'print(1)'; ")),
        "print(2) is harmless",
    );
}

/// Destructive python past the cap is still caught by the sweep, which reads
/// the overflow's text exactly as before.
///
/// By the sweep and not by the python AST rule: the cap still bounds the AST
/// pass, which is the cost it exists for. A deny carrying
/// `heredoc.python:shutil_rmtree` here would mean every construct past the cap
/// now pays for a full parse.
#[test]
fn destructive_python_past_the_cap_still_denies() {
    let command = format!(
        "{}python3 -c 'import shutil; shutil.{}(\"/srv/data\")'",
        pad("python3 -c 'print(1)'; "),
        "rmtree"
    );
    assert_denied_by(
        &command,
        "",
        "the sweep (no ruleId) reads python past the cap; the AST pass does not",
    );
}

/// Here-strings spelled inside a file-writing `cat` heredoc are text, even
/// when there are more of them than the cap: the heredoc past the cap still
/// marks its body inert for the constructs spelled inside it.
#[test]
fn text_in_a_file_writing_heredoc_stays_text() {
    let line = format!("bash <<< '{}'\n", clean());
    let command = format!("cat > notes.txt <<'EOF'\n{}EOF", line.repeat(11));
    assert_allowed(
        &command,
        "cat writes the lines to notes.txt; nothing runs them",
    );
}
