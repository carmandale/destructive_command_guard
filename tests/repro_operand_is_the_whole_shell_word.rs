//! A here-string or `-c` operand is the whole shell WORD, dequoted the way bash
//! hands it to the receiver (`.agent-config-bjjic`), and a `$'...'` segment is
//! decoded (`.agent-config-fmeow`).
//!
//! Bash builds one word from adjacent segments and removes each one's quoting:
//! `'a'\''b'` -- the standard way to put a `'` inside single quotes -- is `a'b`.
//! The here-string and inline-script patterns captured ONE segment, so:
//!
//! - the body was cut at the first closing quote, and the fragment the matcher
//!   read (`import shutil; p=`) met no rule;
//! - the pipeline reader started at the first `|` after that early end, which
//!   can still be inside the real operand;
//! - an unquoted operand kept the backslashes bash removes;
//! - `<<< $'...'` matched no pattern at all, so its body was never read.
//!
//! Each of those ALLOWED while the same python as a heredoc denied by
//! `heredoc.python:shutil_rmtree`. Found by cold review 5 of
//! `.agent-config-7vu4q` (finding B1) and by its first cold review (fmeow).
//!
//! Every kill row is asserted next to its heredoc twin: the twin proves this
//! rule, pack and harness do deny that python, so a green kill row means the
//! operand was read whole, not that the probe went blind. The extractor rows
//! pin what the hook rows cannot: a decoded escape the python matcher would
//! have matched anyway still has to arrive decoded. The allow rows are the
//! fail-open guards: the wider word must not buy its denies by reading data
//! or harmless code as more than it is.
//!
//! WHICH ROW KILLS WHICH MUTANT is recorded in the bead's close reason with the
//! raw runner output, not here, so this header cannot drift from a run nobody
//! repeated.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

use destructive_command_guard::{
    ExtractedContent, ExtractionLimits, ExtractionResult, ScriptLanguage, extract_content,
};

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The rule every kill row must deny by. Named, not merely "some deny": only
/// the python matcher holding the whole body can produce it.
const PYTHON_RMTREE: &str = "heredoc.python:shutil_rmtree";

/// `shutil.rmtree`, assembled at run time: this repository's own guard runs on
/// the machine that edits it, and a probe that cannot be written never runs.
fn rmtree() -> String {
    format!("shutil.{}", "rmtree")
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

/// The kill row and its heredoc twin, twin first: a twin that does not deny
/// means the harness cannot produce the positive, and the kill row would then
/// say nothing.
fn assert_denied_like_its_heredoc_twin(command: &str, twin: &str, why: &str) {
    assert_denied_by(
        twin,
        PYTHON_RMTREE,
        "control: the heredoc twin carries what python runs",
    );
    assert_denied_by(command, PYTHON_RMTREE, why);
}

/// Every entry extraction produced, whether the run was `Extracted` or
/// `Partial`.
fn extracted_entries(command: &str) -> Vec<ExtractedContent> {
    match extract_content(command, &ExtractionLimits::default()) {
        ExtractionResult::Extracted(contents) => contents,
        ExtractionResult::Partial { extracted, .. } => extracted,
        other => panic!("extraction produced no entries for {command:?}: {other:?}"),
    }
}

/// The here-string's readings, sorted by language, asserted non-empty.
fn herestring_readings(command: &str) -> Vec<ExtractedContent> {
    let mut readings: Vec<_> = extracted_entries(command)
        .into_iter()
        .filter(|e| e.heredoc_type.is_some())
        .collect();
    assert!(
        !readings.is_empty(),
        "no here-string entry extracted for {command:?}"
    );
    readings.sort_by_key(|e| format!("{:?}", e.language));
    readings
}

// ---------------------------------------------------------------------------
// The kill rows
// ---------------------------------------------------------------------------

/// The bead's first row: a `'` put inside single quotes the standard way.
#[test]
fn a_here_string_joined_around_an_escaped_quote_is_read_whole() {
    let r = rmtree();
    assert_denied_like_its_heredoc_twin(
        &format!("python3 <<< 'import shutil; p='\\''/srv/data'\\''; {r}(p)'"),
        &format!("python3 <<'PY'\nimport shutil; p='/srv/data'; {r}(p)\nPY"),
        "'...'\\''...' is one word; the operand does not end at the first closing quote",
    );
}

/// A `|` quoted in a later segment is not a pipe, so `node` names nothing.
#[test]
fn a_pipe_quoted_in_a_later_segment_does_not_pick_the_language() {
    let r = rmtree();
    assert_denied_like_its_heredoc_twin(
        &format!("sudo -u root python3 <<< '{r}(\"/srv/data\")'' # | node x'"),
        &format!("sudo -u root python3 <<'PY'\n{r}(\"/srv/data\") # | node x\nPY"),
        "the pipeline reader starts after the whole word, not inside it",
    );
}

/// An unquoted operand loses the backslashes bash removes.
#[test]
fn an_unquoted_escaped_here_string_is_read_without_its_backslashes() {
    let r = rmtree();
    assert_denied_like_its_heredoc_twin(
        &format!("python3 <<< {r}\\(\\\"/srv/data\\\"\\)"),
        &format!("python3 <<'PY'\n{r}(\"/srv/data\")\nPY"),
        "an unquoted backslash quotes the next character and is removed",
    );
}

/// The inline-script half of the same capture defect.
#[test]
fn a_dash_c_operand_joined_around_an_escaped_quote_is_read_whole() {
    let r = rmtree();
    assert_denied_like_its_heredoc_twin(
        &format!("python3 -c 'import shutil; p='\\''/srv/data'\\''; {r}(p)'"),
        &format!("python3 <<'PY'\nimport shutil; p='/srv/data'; {r}(p)\nPY"),
        "'...'\\''...' is one word after -c too",
    );
}

/// `.agent-config-fmeow`'s row: an ANSI-C here-string was never extracted.
#[test]
fn an_ansi_c_here_string_is_read() {
    let r = rmtree();
    assert_denied_like_its_heredoc_twin(
        &format!("python3 <<< $'import shutil; {r}(\"/srv/data\")'"),
        &format!("python3 <<'PY'\nimport shutil; {r}(\"/srv/data\")\nPY"),
        "<<< $'...' is a here-string like any other",
    );
}

// ---------------------------------------------------------------------------
// What the word reads as, one layer below the hook
// ---------------------------------------------------------------------------

/// Both readings hold the joined body, and the span covers the whole word.
#[test]
fn both_readings_hold_the_joined_body_and_the_span_covers_the_word() {
    let r = rmtree();
    let command = format!("python3 <<< 'import shutil; p='\\''/srv/data'\\''; {r}(p)'");
    let readings = herestring_readings(&command);
    let languages: Vec<_> = readings.iter().map(|e| e.language).collect();
    assert_eq!(
        languages,
        [ScriptLanguage::Bash, ScriptLanguage::Python],
        "want the bash and the python reading: {readings:?}"
    );
    for reading in &readings {
        assert_eq!(
            reading.content,
            format!("import shutil; p='/srv/data'; {r}(p)"),
            "the {:?} reading must hold the whole dequoted word",
            reading.language
        );
    }
    let bash = &readings[0];
    let range = bash
        .content_range
        .clone()
        .expect("the bash reading carries the word's span");
    assert_eq!(
        &command[range],
        format!("import shutil; p='\\''/srv/data'\\''; {r}(p)"),
        "the span runs from the first segment's content to the last's"
    );
}

/// Every segment kind, joined: single, double, ANSI-C, escape, bare.
#[test]
fn every_segment_kind_is_dequoted_in_place() {
    let readings = herestring_readings(r#"cat <<< "a"'b'$'\x63'\d"e"f"#);
    assert_eq!(readings[0].content, "abcdef");
    assert!(readings[0].quoted);
}

/// The ANSI-C escapes fmeow names, and bash's others.
#[test]
fn ansi_c_escapes_are_decoded() {
    let readings = herestring_readings(r"cat <<< $'t\tn\nq\'b\\o\101x\x41u\u00e9c\cA'");
    assert_eq!(readings[0].content, "t\tn\nq'b\\oAxAu\u{e9}c\u{1}");
}

/// The word ends at a metacharacter, not at the end of a quoted segment.
#[test]
fn the_word_ends_at_a_metacharacter() {
    let readings = herestring_readings("cat <<< 'a'b;echo c");
    assert_eq!(readings[0].content, "ab");
    let readings = herestring_readings("cat <<< 'a'b| tr a b");
    assert_eq!(readings[0].content, "ab");
    // A backtick after the operand closes the enclosing substitution.
    let entries = extracted_entries("x=`python3 -c 'import os'`");
    let inline = entries
        .iter()
        .find(|e| e.heredoc_type.is_none())
        .unwrap_or_else(|| panic!("no inline-script entry: {entries:?}"));
    assert_eq!(inline.content, "import os");
}

/// The `-c` word is dequoted like a here-string's.
#[test]
fn a_dash_c_word_is_dequoted() {
    let entries = extracted_entries("python3 -c 'a'\\''b'\"c\"");
    let inline = entries
        .iter()
        .find(|e| e.heredoc_type.is_none())
        .unwrap_or_else(|| panic!("no inline-script entry: {entries:?}"));
    assert_eq!(inline.content, "a'bc");
}

/// A one-segment word keeps the span it always had -- the inside of its
/// quotes -- so the caret under a match still lands (`map_heredoc_span`
/// compares the span's bytes with the content).
#[test]
fn a_one_segment_word_keeps_its_span() {
    for command in [
        "python3 <<< 'import os'",
        "python3 <<< \"import os\"",
        "python3 <<< import",
        "python3 -c 'import os'",
    ] {
        let entries = extracted_entries(command);
        let first = entries
            .first()
            .unwrap_or_else(|| panic!("no entry for {command:?}"));
        let range = first
            .content_range
            .clone()
            .unwrap_or_else(|| panic!("no span for {command:?}"));
        assert_eq!(&command[range], first.content, "{command:?}");
    }
}

// ---------------------------------------------------------------------------
// Fail-open guards
// ---------------------------------------------------------------------------

/// Harmless python in a joined word is still harmless.
#[test]
fn a_benign_joined_body_still_allows() {
    assert_allowed(
        "python3 <<< 'print('\\''hello'\\'')'",
        "a joined word around harmless code is not destructive",
    );
    assert_allowed("python3 -c 'print('\\''hello'\\'')'", "the same after -c");
}

/// A data sink's joined word is still data.
#[test]
fn a_joined_word_to_a_data_sink_still_allows() {
    assert_allowed(
        "cat <<< 'rm -rf /srv/data'\\'' is a command'",
        "cat prints its here-string; it does not run it",
    );
}
