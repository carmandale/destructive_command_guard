//! An `fs` delete is judged by the argument of the call, not by the first
//! string in the match (`.agent-config-rmxds`).
//!
//! `refine_javascript_match` and its TypeScript twin asked
//! `JS_FIRST_STRING_ARG` -- `\(\s*("..."|'...')` -- for the target path. That
//! reads from the FIRST open paren anywhere in the matched text, so a receiver
//! carrying a string literal of its own answered for the call:
//!
//! ```text
//!   spelling                                                | before
//!   --------------------------------------------------------|---------------
//!   const fs=require("fs"); fs.rmSync("/etc",{recursive:1}) | DENY heredoc.javascript:fs_rmsync.catastrophic
//!   require("fs").rmSync("/etc",{recursive:true})           | ALLOW
//! ```
//!
//! `is_catastrophic_path` was being asked about `"fs"`, said no, and the match
//! refined to medium -- which the hook skips. The fix locates the call the rule
//! matched (`js_call_arguments`, keyed on the member the PATTERN names, so
//! there is no rule_id -> member table to drift) and reads the first string
//! literal inside its argument list.
//!
//! The reader stays LOOSE inside that list on purpose. Narrowing it to "the
//! literal must be the first argument" would make this a weakening, not a fix:
//! `fs.rmSync(path.join("/etc","x"), {recursive: true})` denies today and must
//! keep denying. That row is here, and the mutant runner turns it red by
//! applying exactly that narrowing.
//!
//! Every deny asserts the `ruleId`, so a deny from the regex sweep (which
//! carries none) or from another pack cannot pass for the rule reading it.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

fn hook(command: &str) -> serde_json::Value {
    let sandbox = spawn::sandbox();
    let mut cmd = spawn::dcg_in(&sandbox);
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
        "hook mode exits 0 whatever the verdict\ncommand: {command:?}\nstderr: {stderr}"
    );
    if stdout.trim().is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hook stdout is not JSON ({e}): {stdout}"))
}

fn node(body: &str) -> String {
    format!("node <<'JS'\n{body}\nJS")
}

fn ts(body: &str) -> String {
    format!("deno run - <<'TS'\n{body}\nTS")
}

fn assert_denied_by(command: &str, rule_id: &str) {
    let out = hook(command);
    let hso = &out["hookSpecificOutput"];
    assert_eq!(
        hso["permissionDecision"], "deny",
        "must deny\ncommand: {command:?}\noutput: {out}"
    );
    assert_eq!(
        hso["ruleId"], rule_id,
        "must be denied by the rule that read the call\ncommand: {command:?}\noutput: {out}"
    );
}

fn assert_allowed(command: &str) {
    let out = hook(command);
    assert!(
        out.is_null(),
        "must allow (empty hook stdout)\ncommand: {command:?}\noutput: {out}"
    );
}

const JS_RMSYNC: &str = "heredoc.javascript:fs_rmsync.catastrophic";
const JS_RMDIRSYNC: &str = "heredoc.javascript:fs_rmdirsync.catastrophic";
const JS_UNLINKSYNC: &str = "heredoc.javascript:fs_unlinksync.catastrophic";
const JS_FSP_RM: &str = "heredoc.javascript:fspromises_rm.catastrophic";
const TS_RMSYNC: &str = "heredoc.typescript:fs_rmsync.catastrophic";
const TS_DENO_REMOVE: &str = "heredoc.typescript:deno_remove.catastrophic";

// ---------------------------------------------------------------------------
// The fail-open: a receiver that carries a string literal of its own.
// ---------------------------------------------------------------------------

#[test]
fn an_inline_require_receiver_does_not_answer_for_the_call() {
    assert_denied_by(
        &node("require('fs').rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
    assert_denied_by(
        &node("require('node:fs').rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
}

#[test]
fn every_inline_require_fs_delete_is_read_on_its_own_argument() {
    assert_denied_by(
        &node("require('fs').rmdirSync('/srv', { recursive: true });"),
        JS_RMDIRSYNC,
    );
    assert_denied_by(
        &node("require('fs').unlinkSync('/etc/passwd');"),
        JS_UNLINKSYNC,
    );
    assert_denied_by(
        &node("require('fs/promises').rm('/etc', { recursive: true });"),
        JS_FSP_RM,
    );
}

#[test]
fn typescript_reads_the_call_argument_too() {
    assert_denied_by(
        &ts("require('fs').rmSync('/etc', { recursive: true });"),
        TS_RMSYNC,
    );
}

// ---------------------------------------------------------------------------
// What must NOT change. The old reader was loose on purpose; the fix moves
// WHERE it reads, not how loosely. These rows are the weakening check.
// ---------------------------------------------------------------------------

#[test]
fn a_literal_that_is_not_the_first_argument_still_denies() {
    // The bead's "measure first" row. `path.join` puts the catastrophic
    // literal behind another call; scoping to the argument list must not turn
    // that into an allow. The mutant that narrows to "first argument only"
    // reds exactly this.
    assert_denied_by(
        &node("const fs = require('fs');\nfs.rmSync(path.join('/etc', 'x'), { recursive: true });"),
        JS_RMSYNC,
    );
    assert_denied_by(
        &node("const fs = require('fs');\nfs.rmSync(resolve('/srv'), { recursive: true });"),
        JS_RMSYNC,
    );
}

#[test]
fn the_canonical_spellings_keep_their_verdict_and_rule_id() {
    assert_denied_by(
        &node("const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
    assert_denied_by(
        &node("const fs = require('fs');\nfs.unlinkSync('/etc/passwd');"),
        JS_UNLINKSYNC,
    );
    assert_denied_by(
        &ts("import * as fs from 'fs';\nfs.rmSync('/etc', { recursive: true });"),
        TS_RMSYNC,
    );
    // `Deno` is a global, not an import: its rule has no binding gate, and the
    // member the pattern names is still what gets read.
    assert_denied_by(
        &ts("Deno.remove('/etc', { recursive: true });"),
        TS_DENO_REMOVE,
    );
}

#[test]
fn a_benign_target_still_allows_through_every_receiver() {
    assert_allowed(&node(
        "const fs = require('fs');\nfs.rmSync('./build', { recursive: true });",
    ));
    assert_allowed(&node(
        "require('fs').rmSync('./build', { recursive: true });",
    ));
    assert_allowed(&node(
        "require('fs').rmdirSync('./dist', { recursive: true });",
    ));
}

#[test]
fn a_dynamic_target_still_allows() {
    // No literal to judge anywhere in the call. Reading a narrower slice must
    // not invent one.
    assert_allowed(&node(
        "const fs = require('fs');\nconst target = process.argv[2];\nfs.rmSync(target, { recursive: true });",
    ));
    assert_allowed(&node(
        "require('fs').rmSync(process.argv[2], { recursive: true });",
    ));
}

#[test]
fn a_non_recursive_delete_of_a_directory_still_allows() {
    // `fs.rmSync` without `recursive: true` and without a catastrophic literal
    // is medium, before and after.
    assert_allowed(&node(
        "const fs = require('fs');\nfs.rmSync('./notes.txt');",
    ));
}
