//! An `fs` / `shutil` / `os` call is read on whatever the body binds the module
//! to (`.agent-config-artmu`).
//!
//! The heredoc AST rules named the receiver literally -- `shutil.rmtree($$$)`,
//! `os.remove($$$)`, `fs.rmSync($$$)`. ast-grep matches that identifier as an
//! identifier, so an alias, a destructure or a from-import was never read.
//! Measured on the installed binary before the fix (hook mode, sandbox as here,
//! each body in a terminated heredoc):
//!
//! ```text
//!   spelling                                                   | before
//!   -----------------------------------------------------------|--------
//!   import shutil; shutil.rmtree("/etc")                        | DENY heredoc.python:shutil_rmtree
//!   import shutil as sh; sh.rmtree("/etc")                      | ALLOW
//!   from shutil import rmtree; rmtree("/etc")                   | ALLOW
//!   const fs=require("fs"); fs.rmSync("/etc",{recursive:true})  | DENY heredoc.javascript:fs_rmsync.catastrophic
//!   const {rmSync}=require("fs"); rmSync("/etc",{recursive:1})  | ALLOW
//! ```
//!
//! Widening the receiver to `$M` the way `.agent-config-w9pvb` widened
//! `child_process` is NOT enough here, and would be worse than the bug: those
//! rules refine to a blocking severity only on a destructive LITERAL payload,
//! while `shutil.rmtree` and `os.remove` block on ANY argument. An ungated
//! `$M.remove($$$)` would deny `items.remove(x)` in every Python heredoc on the
//! machine.
//!
//! So the widened pattern is gated on the body's own imports: the receiver is
//! the module, a local name this body binds to that module, or an inline
//! `require("fs")`. What the imports do not explain is not a match -- the
//! control rows below are that gate, and they fail if it is removed.
//!
//! One call is one match. A name the body binds resolves to exactly one module,
//! so `const fsp = require("fs/promises")` reaches the `fsPromises` rule and not
//! also the `fs` rule; two matches on one call would split its rule id and leave
//! an allowlist for the id the deny names still denying (`.agent-config-w9pvb`
//! review round 1, pinned below).
//!
//! Still NOT read, recorded rather than claimed: a local name that differs from
//! the member the pattern spells (`from shutil import rmtree as rt; rt(..)`,
//! `const { rmSync: r } = require("fs")`), a receiver that is itself an
//! expression (`fs.promises.rm(..)`), a computed or optional member
//! (`fs?.rmSync`, `fs["rmSync"]`), `import fs = require("fs")`, and an inline
//! `require("fs").rmSync(..)` whose target the payload refinement misreads
//! (`.agent-config-rmxds`). Catching
//! those needs a pattern compiled per body, which the hook budget does not
//! have. An UNTERMINATED body is read only by the fallback regex sweep, which
//! names receivers too; that is this bead's second half and is pinned by
//! `fallback_sweep_reads_an_aliased_call` below.
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

fn hook_with_allowlist(command: &str, allowlist: Option<&str>) -> serde_json::Value {
    let sandbox = spawn::sandbox();
    if let Some(allowlist) = allowlist {
        let dir = sandbox.dcg_config_dir();
        std::fs::create_dir_all(&dir).expect("create dcg config dir");
        std::fs::write(dir.join("allowlist.toml"), allowlist).expect("write allowlist");
    }
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

fn hook(command: &str) -> serde_json::Value {
    hook_with_allowlist(command, None)
}

fn py(body: &str) -> String {
    format!("python3 <<'PY'\n{body}\nPY")
}

fn node(body: &str) -> String {
    format!("node <<'JS'\n{body}\nJS")
}

fn ts(body: &str) -> String {
    // `deno` / `bun` are the heads `ScriptLanguage::from_command` reads as TypeScript.
    format!("deno run - <<'TS'\n{body}\nTS")
}

fn assert_verdict_denied_by(out: &serde_json::Value, command: &str, rule_id: &str) {
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

fn assert_denied_by(command: &str, rule_id: &str) {
    assert_verdict_denied_by(&hook(command), command, rule_id);
}

fn assert_denied(command: &str) {
    let out = hook(command);
    assert_eq!(
        out["hookSpecificOutput"]["permissionDecision"], "deny",
        "must deny\ncommand: {command:?}\noutput: {out}"
    );
}

fn assert_allowed(command: &str) {
    let out = hook(command);
    assert!(
        out.is_null(),
        "must allow (empty hook stdout)\ncommand: {command:?}\noutput: {out}"
    );
}

const PY_RMTREE: &str = "heredoc.python:shutil_rmtree";
const PY_REMOVE: &str = "heredoc.python:os_remove";
const PY_UNLINK: &str = "heredoc.python:os_unlink";
const PY_RMDIR: &str = "heredoc.python:os_rmdir";
const JS_RMSYNC: &str = "heredoc.javascript:fs_rmsync.catastrophic";
const JS_FSP_RM: &str = "heredoc.javascript:fspromises_rm.catastrophic";
const TS_RMSYNC: &str = "heredoc.typescript:fs_rmsync.catastrophic";

// ---------------------------------------------------------------------------
// Python: the three rows the bead measured ALLOW.
// ---------------------------------------------------------------------------

#[test]
fn an_aliased_shutil_rmtree_denies() {
    assert_denied_by(&py("import shutil as sh\nsh.rmtree('/etc')"), PY_RMTREE);
}

#[test]
fn a_from_imported_rmtree_denies() {
    assert_denied_by(&py("from shutil import rmtree\nrmtree('/etc')"), PY_RMTREE);
}

#[test]
fn a_wildcard_imported_rmtree_denies() {
    assert_denied_by(&py("from shutil import *\nrmtree('/etc')"), PY_RMTREE);
}

#[test]
fn an_aliased_os_module_denies_its_delete_calls() {
    assert_denied_by(&py("import os as o\no.remove('/etc/passwd')"), PY_REMOVE);
    assert_denied_by(&py("import os as o\no.unlink('/etc/passwd')"), PY_UNLINK);
    assert_denied_by(&py("import os as o\no.rmdir('/etc')"), PY_RMDIR);
}

#[test]
fn a_from_imported_os_delete_denies() {
    assert_denied_by(
        &py("from os import unlink\nunlink('/etc/passwd')"),
        PY_UNLINK,
    );
    assert_denied_by(
        &py("from os import remove\nremove('/etc/passwd')"),
        PY_REMOVE,
    );
}

#[test]
fn an_aliased_pathlib_unlink_denies() {
    assert_denied_by(
        &py("import pathlib as pl\npl.Path('/etc/passwd').unlink()"),
        "heredoc.python:pathlib_unlink",
    );
}

// ---------------------------------------------------------------------------
// Python: the spellings the rules already read keep their verdict and id.
// ---------------------------------------------------------------------------

#[test]
fn the_canonical_python_spellings_keep_their_rule_ids() {
    assert_denied_by(&py("import shutil\nshutil.rmtree('/etc')"), PY_RMTREE);
    assert_denied_by(&py("import os\nos.remove('/etc/passwd')"), PY_REMOVE);
    assert_denied_by(
        &py("import pathlib\npathlib.Path('/etc/passwd').unlink()"),
        "heredoc.python:pathlib_unlink",
    );
    assert_denied_by(
        &py("from pathlib import Path\nPath('/etc/passwd').unlink()"),
        "heredoc.python:pathlib_unlink",
    );
}

#[test]
fn a_canonical_call_with_no_import_at_all_still_denies() {
    // The gate must not require an import that the old pattern never required:
    // the receiver IS the module name, so the body explains itself.
    assert_denied_by(&py("shutil.rmtree('/etc')"), PY_RMTREE);
    assert_denied_by(&py("os.remove('/etc/passwd')"), PY_REMOVE);
}

// ---------------------------------------------------------------------------
// Python controls: the gate is what keeps `$M` from meaning "anything".
// Each of these denies if the binding check is deleted.
// ---------------------------------------------------------------------------

#[test]
fn an_unexplained_receiver_is_not_a_module() {
    assert_allowed(&py("items = ['/etc/passwd']\nitems.remove('/etc/passwd')"));
    assert_allowed(&py("cache = Cache()\ncache.rmtree('/etc')"));
    assert_allowed(&py("q = Q()\nq.unlink('/etc/passwd')"));
}

#[test]
fn an_unimported_bare_call_is_not_a_module_call() {
    assert_allowed(&py("def rmtree(p):\n    print(p)\nrmtree('/etc')"));
    assert_allowed(&py("def remove(p):\n    print(p)\nremove('/etc/passwd')"));
}

#[test]
fn a_local_name_bound_to_a_harmless_member_allows() {
    // `rmtree` here IS `shutil.copy`. The binding records the member that was
    // imported, not just the module, so the name alone does not convict.
    assert_allowed(&py("from shutil import copy as rmtree\nrmtree('/etc')"));
}

#[test]
fn an_alias_of_another_module_does_not_borrow_os_rules() {
    assert_allowed(&py("import json as o\no.remove('/etc/passwd')"));
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript.
// ---------------------------------------------------------------------------

#[test]
fn a_destructured_rm_sync_denies() {
    // The bead's third row.
    assert_denied_by(
        &node("const { rmSync } = require('fs');\nrmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
}

#[test]
fn an_aliased_fs_module_denies() {
    assert_denied_by(
        &node("const f = require('fs');\nf.rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
    assert_denied_by(
        &node("const f = require('node:fs');\nf.rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
}

#[test]
fn an_inline_require_is_recorded_as_unread_not_claimed() {
    // NOT a fix, and not a gate failure: the receiver `require('fs')` IS
    // resolvable, but the payload refinement reads the FIRST string literal in
    // the matched text as the target path, which for this spelling is `'fs'`.
    // Admitting it in the gate would add a code path that changes no verdict.
    // Measured 2026-09-18 and filed as `.agent-config-rmxds`; this row is the
    // record, and it flips to a deny the moment that bead lands.
    assert_allowed(&node("require('fs').rmSync('/etc', { recursive: true });"));
}

#[test]
fn the_canonical_fs_spelling_keeps_its_rule_id() {
    assert_denied_by(
        &node("const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });"),
        JS_RMSYNC,
    );
}

#[test]
fn a_bound_fs_promises_name_reaches_the_fs_promises_rule_only() {
    // `fsp` resolves to `fs/promises`, so the `fs.rm` rule must NOT also claim
    // it. `allowlisting_the_id_the_deny_names_allows_it` is the other half.
    assert_denied_by(
        &node("const fsp = require('fs/promises');\nfsp.rm('/etc', { recursive: true });"),
        JS_FSP_RM,
    );
}

#[test]
fn typescript_imports_bind_the_same_way() {
    assert_denied_by(
        &ts("import * as nodefs from 'fs';\nnodefs.rmSync('/etc', { recursive: true });"),
        TS_RMSYNC,
    );
    assert_denied_by(
        &ts("import { rmSync } from 'node:fs';\nrmSync('/etc', { recursive: true });"),
        TS_RMSYNC,
    );
    assert_denied_by(
        &ts("import nodefs from 'fs';\nnodefs.rmSync('/etc', { recursive: true });"),
        TS_RMSYNC,
    );
}

// ---------------------------------------------------------------------------
// JS controls.
// ---------------------------------------------------------------------------

#[test]
fn a_benign_aliased_call_allows() {
    // The bead's own control: the canonical spelling allows this target, so the
    // aliased one must too. `fs.rmSync` blocks on a catastrophic literal path,
    // not on being called.
    assert_allowed(&node(
        "const { rmSync } = require('fs');\nrmSync('./build', { recursive: true });",
    ));
    assert_allowed(&node(
        "const f = require('fs');\nf.rmSync('./build', { recursive: true });",
    ));
}

#[test]
fn an_unexplained_js_receiver_allows() {
    assert_allowed(&node(
        "const tmp = makeTmp();\ntmp.rmSync('/etc', { recursive: true });",
    ));
    assert_allowed(&node("rmSync('/etc', { recursive: true });"));
}

#[test]
fn a_renamed_destructure_is_recorded_as_unread_not_claimed() {
    // NOT a fix: `r` is not the name the pattern spells, so nothing reads it.
    // Pinned so the next reader sees the hole instead of inferring coverage.
    assert_allowed(&node(
        "const { rmSync: r } = require('fs');\nr('/etc', { recursive: true });",
    ));
}

// ---------------------------------------------------------------------------
// One call is one match.
// ---------------------------------------------------------------------------

#[test]
fn allowlisting_the_id_the_deny_names_allows_it() {
    for (command, rule) in [
        (
            py("import os as o\no.remove('/etc/passwd')"),
            PY_REMOVE.to_string(),
        ),
        (
            py("from os import remove\nremove('/etc/passwd')"),
            PY_REMOVE.to_string(),
        ),
    ] {
        // Control: without the allowlist this denies under exactly that id, so
        // the ALLOW below is the allowlist working, not the rule never firing.
        assert_verdict_denied_by(&hook(&command), &command, &rule);

        let allowlist = format!("[[allow]]\nrule = \"{rule}\"\nreason = \"artmu fixture\"\n");
        let out = hook_with_allowlist(&command, Some(&allowlist));
        assert!(
            out.is_null(),
            "allowlisting the id the deny names must allow it\ncommand: {command:?}\noutput: {out}"
        );
    }
}

// ---------------------------------------------------------------------------
// The second reader: an UNTERMINATED body never reaches the AST, so only the
// fallback regex sweep reads it -- and it named receivers too.
// ---------------------------------------------------------------------------

#[test]
fn fallback_sweep_reads_an_aliased_call() {
    // No `PY` terminator: extraction skips the body, and the sweep runs over
    // what went unread. It carries no ruleId (it is not a rule), so this
    // asserts the verdict only.
    assert_denied("python3 <<'PY'\nimport shutil as sh\nsh.rmtree('/etc')");
    assert_denied(
        "node <<'JS'\nconst { rmSync } = require('fs');\nrmSync('/etc', { recursive: true });",
    );
}

#[test]
fn fallback_sweep_still_reads_the_canonical_call() {
    assert_denied("python3 <<'PY'\nimport shutil\nshutil.rmtree('/etc')");
}
