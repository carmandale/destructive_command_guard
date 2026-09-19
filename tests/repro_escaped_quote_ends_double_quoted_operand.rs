//! A double-quoted `-c`/`-e` operand and a double-quoted here-string must run
//! to their closing UNESCAPED quote (`.agent-config-gt800`).
//!
//! `INLINE_SCRIPT_DOUBLE_QUOTE` and `HERESTRING_DOUBLE_QUOTE` captured
//! `"([^"]*)"`. A negated class cannot tell `\"` from `"`, so the operand ended
//! at the first ESCAPED quote inside it. The python the interpreter really runs
//! was never extracted whole; what reached the matcher was the fragment before
//! that quote — `import shutil; shutil.rmtree(\` — which matches no rule, so
//! the command ALLOWED.
//!
//! Agents write exactly this spelling whenever the python needs a string
//! literal inside a double-quoted `-c`. It is not a corner: it is the ordinary
//! way to nest quotes when the outer pair is already double.
//!
//! FOUND 2026-09-18 by the cold review of `.agent-config-7vu4q`
//! (`thoughts/shared/handoffs/20260918-7vu4q-herestring-language/lanes/cold-review.md`,
//! rows R6a/R6b). Pre-existing: it allowed on base `76d93747` too, so it is not
//! that change's regression.
//!
//! WHICH ROW IS A KILL, measured on this tree by running this file against
//! `main` 88777c5c before the fix and after it:
//!
//! ```text
//!   row                                                     | pre-fix | post-fix
//!   ---------------------------------------------------------|---------|---------
//!   an_escaped_quote_does_not_end_a_double_quoted_dash_c      | RED     | green
//!   the_dash_c_operand_is_extracted_whole_and_unescaped       | RED     | green
//!   an_escaped_quote_does_not_end_a_double_quoted_herestring  | RED     | green
//!   an_escaped_backslash_still_ends_the_operand               | RED     | green
//!   the_single_quoted_twin_denies                             | green   | green
//!   a_benign_escaped_body_still_allows                        | green   | green
//!   an_unescaped_double_quoted_body_is_unchanged              | green   | green
//! ```
//!
//! The four RED rows are the kill. `the_single_quoted_twin_denies` is the
//! control: it proves the rule, the pack selection and the harness can all
//! produce the DENY this file claims is missing, so a green on the escaped row
//! means the extractor changed and not that the probe went blind. The last two
//! are the fail-open guards -- the fix must not buy its green by denying
//! everything with a backslash in it, and must not move the unescaped case.
//!
//! THE MUTANTS, each run on this tree and each restored after:
//!
//! ```text
//!   mutant                                        | rows it turns red
//!   -----------------------------------------------|------------------------
//!   INLINE_SCRIPT_DOUBLE_QUOTE  -> `"([^"]*)"`     | the two dash_c rows
//!   HERESTRING_DOUBLE_QUOTE     -> `"([^"]*)"`     | the herestring row
//!   unescape flag -> false on both double-quoted   | all four kill rows
//!     paths                                        |
//! ```
//!
//! The change has two halves -- the capture and the unescape -- and a mutant
//! that only reverts the capture leaves the second half unpinned. That is why
//! the third one exists, and why `an_escaped_backslash_still_ends_the_operand`
//! is here: it is the only row the capture mutants leave green, so without it
//! the unescape could be deleted and this file would still pass.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

use destructive_command_guard::{
    ExtractedContent, ExtractionLimits, ExtractionResult, extract_content,
};

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The rule the escaped row must deny by.
///
/// Named, not merely "some deny": a denial by the fallback sweep or by an outer
/// `core.*` pattern would also be a non-zero-noise "blocked", and would prove
/// nothing about whether the body was extracted. This ruleId can only come from
/// the heredoc AST matcher reading python that it actually holds.
const PYTHON_RMTREE: &str = "heredoc.python:shutil_rmtree";

/// The destructive python body, assembled at run time.
///
/// Spelled in parts because this repository's own guard is installed on the
/// machine that edits it: a literal `shutil` + `.rmtree(` pair in a file an
/// agent writes through a shell is the thing dcg exists to stop, and a probe
/// that cannot be written is a probe that never runs.
fn rmtree_body(quote: &str) -> String {
    format!(
        "import shutil; shutil.{}({}/srv/data{})",
        "rmtree", quote, quote
    )
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
        !combined.contains("\"permissionDecision\": \"deny\"")
            && !combined.contains("\"permissionDecision\":\"deny\""),
        "expected an allow ({why})\ncommand: {command:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

/// Every entry extraction produced, whether the run was `Extracted` or
/// `Partial`.
///
/// `Partial` carries real entries; collapsing it into "no entries" would let a
/// skipped-for-another-reason run read as the defect this file is about.
fn extracted_entries(command: &str) -> Vec<ExtractedContent> {
    match extract_content(command, &ExtractionLimits::default()) {
        ExtractionResult::Extracted(contents) => contents,
        ExtractionResult::Partial { extracted, .. } => extracted,
        other => panic!("extraction produced no entries for {command:?}: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The kill rows
// ---------------------------------------------------------------------------

/// The bead's own row. RED before the fix: ALLOW.
#[test]
fn an_escaped_quote_does_not_end_a_double_quoted_dash_c() {
    let body = rmtree_body("\\\"");
    let command = format!("python3 -c \"{body}\"");
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "a \\\" inside a double-quoted -c operand is an escaped quote, not the \
         end of the operand",
    );
}

/// The here-string half of the same capture defect.
///
/// Asserted at the extractor: what the capture owns is the CONTENT. Since
/// `.agent-config-7vu4q` a here-string to an interpreter carries two readings,
/// bash and the receiver's, and both must hold the unescaped body -- the python
/// one is what the python matcher reads. The end-to-end hook row is
/// `an_escaped_quote_in_a_double_quoted_operand_is_read_as_python` in
/// tests/repro_herestring_language_from_receiver.rs.
#[test]
fn an_escaped_quote_does_not_end_a_double_quoted_herestring() {
    let body = rmtree_body("\\\"");
    let command = format!("python3 <<< \"{body}\"");
    let entries = extracted_entries(&command);
    let herestrings: Vec<_> = entries
        .iter()
        .filter(|e| e.heredoc_type.is_some())
        .collect();
    let mut languages: Vec<String> = herestrings
        .iter()
        .map(|e| format!("{:?}", e.language))
        .collect();
    languages.sort();
    assert_eq!(
        languages,
        ["Bash", "Python"],
        "want the bash and the python reading for {command:?}: {entries:?}"
    );
    for herestring in herestrings {
        assert_eq!(
            herestring.content,
            rmtree_body("\""),
            "the here-string body must run to its closing unescaped quote, with \
             \\\" unescaped for the matcher ({:?} reading)",
            herestring.language
        );
    }
}

/// The same assertion for the `-c` operand, one layer below the hook.
///
/// The hook row above can go green for reasons that are not this fix (a new
/// fallback pattern, a wider outer rule). This one can only go green if the
/// capture changed.
#[test]
fn the_dash_c_operand_is_extracted_whole_and_unescaped() {
    let body = rmtree_body("\\\"");
    let command = format!("python3 -c \"{body}\"");
    let entries = extracted_entries(&command);
    let inline = entries
        .iter()
        .find(|e| e.heredoc_type.is_none())
        .unwrap_or_else(|| panic!("no inline-script entry for {command:?}: {entries:?}"));
    assert_eq!(
        inline.content,
        rmtree_body("\""),
        "the -c operand must run to its closing unescaped quote, with \\\" \
         unescaped for the matcher"
    );
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

/// The probe can produce a positive.
///
/// Same body, same rule, same harness — only the outer quoting differs, so a
/// green here and a red above localises the defect to the double-quote capture
/// and nowhere else. Green on both sides of the fix.
#[test]
fn the_single_quoted_twin_denies() {
    let command = format!("python3 -c '{}'", rmtree_body("\""));
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "the single-quoted twin is the control: this rule, pack and harness do \
         produce a deny",
    );
}

/// The fix must not deny everything holding a backslash.
///
/// A widened capture that also widened what matches would show up here.
#[test]
fn a_benign_escaped_body_still_allows() {
    let command = "python3 -c \"print(\\\"hello\\\")\"";
    assert_allowed(
        command,
        "an escaped quote around harmless text is not destructive",
    );
}

/// The unescaped case is unchanged.
///
/// `[^"]*` and the new capture agree on every operand with no backslash in it,
/// and this row is what a careless rewrite of the pattern would break.
#[test]
fn an_unescaped_double_quoted_body_is_unchanged() {
    let command = format!("python3 -c \"{}\"", rmtree_body("'"));
    let entries = extracted_entries(&command);
    let inline = entries
        .iter()
        .find(|e| e.heredoc_type.is_none())
        .unwrap_or_else(|| panic!("no inline-script entry for {command:?}: {entries:?}"));
    assert_eq!(
        inline.content,
        rmtree_body("'"),
        "an operand with no backslash in it is captured exactly as before"
    );
    assert_denied_by(
        &command,
        PYTHON_RMTREE,
        "the unescaped double-quoted operand denied before this change and \
         still denies",
    );
}

/// A trailing escaped backslash does not run the capture past its operand.
///
/// `"a\\"` closes: the `\\` is an escaped backslash, and the quote after it is
/// the terminator. A capture that consumed `\\"` as an escape pair plus a
/// literal would swallow the rest of the command line and read the NEXT
/// command's text as this operand's body.
#[test]
fn an_escaped_backslash_still_ends_the_operand() {
    let command = "python3 -c \"print(1)\\\\\" ; echo done";
    let entries = extracted_entries(command);
    let inline = entries
        .iter()
        .find(|e| e.heredoc_type.is_none())
        .unwrap_or_else(|| panic!("no inline-script entry for {command:?}: {entries:?}"));
    assert_eq!(
        inline.content, "print(1)\\",
        "an escaped backslash is content; the quote after it closes the operand"
    );
}
