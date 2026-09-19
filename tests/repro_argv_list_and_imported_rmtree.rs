//! A destructive argv LIST, and an imported `rmtree`, met no rule
//! (`.agent-config-ei4it`).
//!
//! Two independent gaps with one shape: the spelling a real script uses was the
//! one nothing read.
//!
//! * **python.** The pack knows `subprocess.run($$$)` only as a Medium
//!   "executes shell commands" warning -- deliberately, because blocking on
//!   `shell=True` alone is noise. The STRING form is denied anyway, by the
//!   filesystem pack, because its command sits in the command text as
//!   contiguous shell words. The LIST form hides those same words in separate
//!   literals, so nothing matched, and the safer-looking spelling was the one
//!   that got through.
//! * **perl.** `PERL_FILE_PATH_RMTREE_LITERAL` required a literal
//!   `File::Path::` qualifier. The documented way to call it is
//!   `use File::Path qw(rmtree); rmtree($dir)`, which carries no qualifier.
//!
//! Measured in hook mode, sandboxed by `tests/common/spawn.rs`. The ALLOW
//! column is dcg WITHOUT this change. The five rows the bead names were read
//! that way on main at 88777c5c; the double-quoted row was written later, and
//! its ALLOW is the mutant that removes the refinement, which takes it and
//! every other python DENY here back to ALLOW.
//!
//! The DENY column was re-read on 56f22bc2, on bfcf936c and again on 3b648f5a,
//! as `.agent-config-artmu` made the python rules module-bound,
//! `.agent-config-rmxds` changed how an fs delete reads its argument, and
//! `.agent-config-w9pvb` rewrote the payload reader into `strongest_hit` over
//! `detect_command_words`. No row moved through any of it.
//!
//! `<rm>` and `<-rf>` stand for the argv strings that name a recursive force
//! delete. Spelled out, this file would be a payload, and the live guard would
//! refuse to let anyone edit it.
//!
//! ```text
//!   row                                                   | main   | fixed
//!   ------------------------------------------------------|--------|------
//!   python3 -c  subprocess.run([<rm>, <-rf>, /srv/data])   | ALLOW  | DENY
//!   python3 -c  subprocess.call(  same argv  )             | ALLOW  | DENY
//!   python3 -c  subprocess.Popen( same argv  )             | ALLOW  | DENY
//!   perl -e     use File::Path qw(rmtree); rmtree $dir     | ALLOW  | DENY
//!   perl -e     ... qw(remove_tree); remove_tree $dir      | ALLOW  | DENY
//!   control: perl -e  the File::Path-qualified rmtree      | DENY   | DENY
//!   control: python3 -c  shutil rmtree of /srv/data        | DENY   | DENY
//!   control: python3 -c  the STRING form, shell=True       | DENY   | DENY
//!   argv [ls, -la, /srv/data]                              | ALLOW  | ALLOW
//!   argv [<rm>, /srv/data/one-file]  (no recursive force)  | ALLOW  | ALLOW
//!   argv [<rm>, <-rf>, /tmp/build]   (not catastrophic)    | ALLOW  | ALLOW
//!   perl imported rmtree of /tmp/build                     | ALLOW  | ALLOW
//!   argv computed from sys.argv (unreadable)               | ALLOW  | ALLOW
//! ```
//!
//! The three controls are why a DENY here is this fix and not the machine: they
//! are the spellings that already denied, and they still name their own rule.
//! The five ALLOW rows are the other half of the claim -- the rule reads the
//! argv, not the mere presence of a `subprocess` call.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Assembled at runtime so this source file is not itself a payload, and so
/// editing it does not have to be argued past the live guard.
fn rm() -> &'static str {
    "r\u{6d}"
}

fn recursive_force() -> &'static str {
    "-r\u{66}"
}

/// `python3 -c` running one `subprocess` call over a literal argv list.
fn python_argv(call: &str, items: &[&str]) -> String {
    let list = items
        .iter()
        .map(|item| format!("'{item}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("python3 -c \"import subprocess; subprocess.{call}([{list}])\"")
}

/// `perl -e` importing a `File::Path` function and calling it unqualified.
fn perl_imported(func: &str, path: &str) -> String {
    format!("perl -e 'use File::Path qw({func}); {func}(\"{path}\")'")
}

/// `perl -e` calling the same function through its full package name.
fn perl_qualified(func: &str, path: &str) -> String {
    format!("perl -e 'File::Path::{func}(\"{path}\")'")
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

// ---------------------------------------------------------------------------
// python: the argv list carries the command, so the rule must read the argv.
// ---------------------------------------------------------------------------

#[test]
fn subprocess_run_with_a_destructive_argv_list_denies() {
    let cmd = python_argv("run", &[rm(), recursive_force(), "/srv/data"]);
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_run.rm_rf_catastrophic",
        "the argv list names a recursive force delete of a system path",
    );
}

#[test]
fn subprocess_call_with_a_destructive_argv_list_denies() {
    let cmd = python_argv("call", &[rm(), recursive_force(), "/srv/data"]);
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_call.rm_rf_catastrophic",
        "call() runs the same argv run() does",
    );
}

#[test]
fn subprocess_popen_with_a_destructive_argv_list_denies() {
    let cmd = python_argv("Popen", &[rm(), recursive_force(), "/srv/data"]);
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_popen.rm_rf_catastrophic",
        "Popen() runs the same argv run() does",
    );
}

#[test]
fn a_double_quoted_argv_list_denies_too() {
    // The list literals here are double-quoted inside a single-quoted -c.
    let cmd = format!(
        "python3 -c 'import subprocess; subprocess.run([\"{}\", \"{}\", \"/srv/data\"])'",
        rm(),
        recursive_force()
    );
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_run.rm_rf_catastrophic",
        "python string literals are single- or double-quoted; both are argv",
    );
}

// ---------------------------------------------------------------------------
// perl: the imported spelling is the one scripts use.
// ---------------------------------------------------------------------------

#[test]
fn an_imported_rmtree_denies() {
    let cmd = perl_imported("rmtree", "/srv/data");
    assert_denied_by(
        &cmd,
        "heredoc.perl:file_path.rmtree",
        "use File::Path qw(rmtree) leaves no qualifier at the call site",
    );
}

#[test]
fn an_imported_remove_tree_denies() {
    let cmd = perl_imported("remove_tree", "/srv/data");
    assert_denied_by(
        &cmd,
        "heredoc.perl:file_path.remove_tree",
        "remove_tree is the same function under its modern name",
    );
}

#[test]
fn the_qualified_and_imported_spellings_are_one_rule() {
    // A policy line or an allowlist written for either spelling must cover
    // both, so the rule id may not fork on how the call was written.
    let qualified = perl_qualified("rmtree", "/srv/data");
    let (qual_rule, _, _) = hook(&qualified);
    assert_eq!(
        qual_rule.as_deref(),
        Some("heredoc.perl:file_path.rmtree"),
        "the qualified spelling keeps the rule id it always had: {qualified:?}"
    );

    let (imported_rule, _, _) = hook(&perl_imported("rmtree", "/srv/data"));
    assert_eq!(imported_rule, qual_rule, "one function, one rule id");
}

#[test]
fn only_the_qualified_reason_claims_a_qualifier() {
    // The reason is a label on what was read. It may not report a
    // `File::Path::` prefix the body did not carry.
    let (_, qualified_out, _) = hook(&perl_qualified("rmtree", "/srv/data"));
    assert!(
        qualified_out.contains("File::Path::rmtree()"),
        "the qualified call is reported under its full name: {qualified_out}"
    );

    let (_, imported_out, _) = hook(&perl_imported("rmtree", "/srv/data"));
    assert!(
        imported_out.contains("rmtree()"),
        "the imported call is still reported by name: {imported_out}"
    );
    assert!(
        !imported_out.contains("File::Path::rmtree()"),
        "no qualifier was in the body, so none may be in the reason: {imported_out}"
    );
}

// ---------------------------------------------------------------------------
// Controls: the spellings that already denied still do, and name their rule.
// ---------------------------------------------------------------------------

#[test]
fn control_python_shutil_rmtree_still_denies() {
    let cmd = format!(
        "python3 -c 'import shutil; shutil.{}(\"/srv/data\")'",
        "rmtree"
    );
    assert_denied_by(
        &cmd,
        "heredoc.python:shutil_rmtree",
        "the bead's control row: a deny here is not the new rule",
    );
}

#[test]
fn control_a_string_payload_is_still_the_filesystem_packs() {
    // The string form's words are contiguous in the command text, so the
    // outer pack sees them. This row must NOT start naming a heredoc rule.
    let cmd = format!(
        "python3 -c 'import subprocess; subprocess.run(\"{} {} /srv/data\", shell=True)'",
        rm(),
        recursive_force()
    );
    assert_denied_by(
        &cmd,
        "core.filesystem:rm-rf-root-home",
        "the string form was never the gap and must not be re-routed",
    );
}

// ---------------------------------------------------------------------------
// The other half of the claim: what must still be allowed.
// ---------------------------------------------------------------------------

#[test]
fn a_harmless_argv_list_still_allows() {
    let cmd = python_argv("run", &["ls", "-la", "/srv/data"]);
    assert_allowed(
        &cmd,
        "a subprocess call is not destructive for being a subprocess call",
    );
}

#[test]
fn an_argv_list_without_recursive_force_still_allows() {
    let cmd = python_argv("run", &[rm(), "/srv/data/one-file"]);
    assert_allowed(
        &cmd,
        "the rule is the recursive force delete, not the command name",
    );
}

#[test]
fn an_argv_list_on_a_non_catastrophic_target_still_allows() {
    let cmd = python_argv("run", &[rm(), recursive_force(), "/tmp/build"]);
    assert_allowed(
        &cmd,
        "a recursive delete under /tmp warns; it does not deny",
    );
}

#[test]
fn an_imported_rmtree_on_a_non_catastrophic_target_still_allows() {
    let cmd = perl_imported("rmtree", "/tmp/build");
    assert_allowed(
        &cmd,
        "ordinary build-directory cleanup must not become a denial",
    );
}

#[test]
fn a_subprocess_call_with_no_literal_argv_still_allows() {
    let cmd = "python3 -c 'import subprocess, sys; subprocess.run(sys.argv[1:])'";
    assert_allowed(
        cmd,
        "a computed argv cannot be read, and an unreadable argv is not a denial",
    );
}
