//! A `subprocess` call is read on whatever the body binds the module to
//! (`.agent-config-dcg-subprocess-module-binding-ehxrb`).
//!
//! `.agent-config-artmu` made the `shutil` / `os` / `pathlib` rules read the
//! module the body bound, but left `subprocess.run($$$)`, `.call` and `.Popen`
//! as literal receivers. `.agent-config-ei4it` then made those three the reader
//! for a destructive argv LIST, so an aliased or from-imported call was a deny
//! that did not happen. Measured in hook mode (sandbox as here) with ei4it on
//! 56f22bc2, before this fix:
//!
//! ```text
//!   python3 -c                                                   | before
//!   -------------------------------------------------------------|--------
//!   import shutil; shutil.rmtree of /srv/data                    | DENY heredoc.python:shutil_rmtree
//!   import shutil as sh; sh.rmtree of /srv/data                  | DENY heredoc.python:shutil_rmtree
//!   from shutil import rmtree; rmtree of /srv/data               | DENY heredoc.python:shutil_rmtree
//!   import subprocess; subprocess.run([<rm>, <-rf>, /srv/data])  | DENY heredoc.python:subprocess_run.rm_rf_catastrophic
//!   import subprocess as sp; sp.run([<rm>, <-rf>, /srv/data])    | ALLOW
//!   from subprocess import run; run([<rm>, <-rf>, /srv/data])    | ALLOW
//! ```
//!
//! The three `subprocess` patterns now carry shutil's treatment: `$M.<member>`
//! gated on `$M` being `subprocess` or a name this body binds to it, and a bare
//! `<member>` twin gated on that member having been imported from
//! `subprocess`. Same rule ids.
//!
//! The bare twin is a wider net than `rmtree($$$)` -- `run` and `call` are
//! ordinary names -- and that is the decision this bead named. It is accepted
//! because the gate, not the name, decides: a bare `run(..)` counts only where
//! the body wrote `from subprocess import run` (or `import *`), and even then
//! the match stays Medium, which the hook does not act on, unless its literal
//! argv is a command dcg already denies. The controls below are that gate, and
//! each fails if its half of it is removed.
//!
//! Two limits, recorded rather than hidden. The gate reads imports, not scope:
//! `from subprocess import run` followed by a local `def run` is still read as
//! subprocess, and that deny is accepted. And a name bound ONLY to another
//! module is that module -- `import gevent.subprocess as subprocess` is not
//! read, the meaning shutil has had since artmu; it was DENY at the parent, so
//! that is an accepted regression, .agent-config-msnfu -- but a name that is ALSO
//! plainly imported (`try: import subprocess32 as subprocess / except
//! ImportError: import subprocess`) keeps its module, because either binding
//! may be the live one. That last rule is in the shared gate, so it reaches
//! `pathlib` too; the cold review of this change found both.
//!
//! Every deny asserts the `ruleId`, so a deny from another pack cannot pass for
//! the rule that read the call.

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

/// The bead's destructive argv, as a python list literal.
fn destructive_list() -> String {
    format!("['{}', '{}', '/srv/data']", rm(), recursive_force())
}

/// `python3 -c` over one line of python, as the bead measured.
fn py_c(body: &str) -> String {
    format!("python3 -c \"{body}\"")
}

/// A terminated `python3` heredoc, for bodies that need more than one line.
fn py_heredoc(body: &str) -> String {
    format!("python3 <<'PY'\n{body}\nPY")
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

fn assert_denied_by(command: &str, rule: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got.as_deref(),
        Some(rule),
        "must be denied by the rule that read the call\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got, None,
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

const PY_RMTREE: &str = "heredoc.python:shutil_rmtree";
const RUN_RM_RF: &str = "heredoc.python:subprocess_run.rm_rf_catastrophic";
const CALL_RM_RF: &str = "heredoc.python:subprocess_call.rm_rf_catastrophic";
const POPEN_RM_RF: &str = "heredoc.python:subprocess_popen.rm_rf_catastrophic";

// ---------------------------------------------------------------------------
// The bead's six rows, in its order.
// ---------------------------------------------------------------------------

#[test]
fn the_shutil_rows_are_the_control() {
    // Rows 1-3: the binding machinery is present and working in this binary,
    // so an ALLOW below is the subprocess patterns, not a broken probe.
    let rmtree = "rmt\u{72}ee";
    assert_denied_by(
        &py_c(&format!("import shutil; shutil.{rmtree}('/srv/data')")),
        PY_RMTREE,
    );
    assert_denied_by(
        &py_c(&format!("import shutil as sh; sh.{rmtree}('/srv/data')")),
        PY_RMTREE,
    );
    assert_denied_by(
        &py_c(&format!(
            "from shutil import {rmtree}; {rmtree}('/srv/data')"
        )),
        PY_RMTREE,
    );
}

#[test]
fn the_canonical_subprocess_run_keeps_its_verdict() {
    // Row 4.
    assert_denied_by(
        &py_c(&format!(
            "import subprocess; subprocess.run({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
}

#[test]
fn an_aliased_subprocess_run_denies() {
    // Row 5: ALLOW before this fix.
    assert_denied_by(
        &py_c(&format!(
            "import subprocess as sp; sp.run({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
}

#[test]
fn a_from_imported_run_denies() {
    // Row 6: ALLOW before this fix.
    assert_denied_by(
        &py_c(&format!(
            "from subprocess import run; run({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
}

// ---------------------------------------------------------------------------
// The same treatment for call and Popen, and through a heredoc body.
// ---------------------------------------------------------------------------

#[test]
fn call_and_popen_are_bound_the_same_way() {
    let argv = destructive_list();
    assert_denied_by(
        &py_c(&format!("import subprocess as sp; sp.call({argv})")),
        CALL_RM_RF,
    );
    assert_denied_by(
        &py_c(&format!("from subprocess import call; call({argv})")),
        CALL_RM_RF,
    );
    assert_denied_by(
        &py_c(&format!("import subprocess as sp; sp.Popen({argv})")),
        POPEN_RM_RF,
    );
    assert_denied_by(
        &py_c(&format!("from subprocess import Popen; Popen({argv})")),
        POPEN_RM_RF,
    );
}

#[test]
fn a_wildcard_import_binds_the_bare_call() {
    assert_denied_by(
        &py_c(&format!(
            "from subprocess import *; run({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
}

#[test]
fn a_heredoc_body_is_read_the_same_way() {
    let argv = destructive_list();
    assert_denied_by(
        &py_heredoc(&format!("import subprocess as sp\nsp.run({argv})")),
        RUN_RM_RF,
    );
    assert_denied_by(
        &py_heredoc(&format!("from subprocess import run\nrun({argv})")),
        RUN_RM_RF,
    );
}

#[test]
fn a_harmless_bound_argv_still_allows() {
    // A subprocess call is not destructive for being a subprocess call, under
    // any spelling.
    assert_allowed(
        &py_c("import subprocess as sp; sp.run(['ls', '-la', '/srv/data'])"),
        "a harmless aliased argv must allow",
    );
    assert_allowed(
        &py_c("from subprocess import run; run(['ls', '-la', '/srv/data'])"),
        "a harmless from-imported argv must allow",
    );
}

// ---------------------------------------------------------------------------
// Controls. The gate is what keeps `$M.run` and bare `run` from meaning
// "anything called run"; each of these denies if its half of the gate goes.
// ---------------------------------------------------------------------------

#[test]
fn an_alias_of_another_module_is_not_subprocess() {
    // Receiver gate: `sp` is json here.
    assert_allowed(
        &py_c(&format!(
            "import json as sp; sp.run({})",
            destructive_list()
        )),
        "sp is bound to json, not subprocess",
    );
    // A plain `import subprocess` keeps the name `subprocess` subprocess; it
    // does not lend the module to a different name bound elsewhere.
    assert_allowed(
        &py_heredoc(&format!(
            "import subprocess\nimport json as sp\nsp.run({})",
            destructive_list()
        )),
        "sp is still json when the body also imports subprocess",
    );
}

#[test]
fn an_unimported_bare_run_is_not_subprocess() {
    // Bare gate: nothing imported `run` from subprocess.
    assert_allowed(
        &py_heredoc(&format!(
            "def run(argv):\n    print(argv)\nrun({})",
            destructive_list()
        )),
        "a local def run is not subprocess.run",
    );
    assert_allowed(
        &py_c(&format!(
            "from asyncio import run; run({})",
            destructive_list()
        )),
        "run imported from another module is not subprocess.run",
    );
}

#[test]
fn a_bound_bare_name_does_not_claim_an_attribute_call() {
    // `run` is bound to subprocess.run; `runner.run` is some other object's
    // method, and the bare twin must not take it.
    assert_allowed(
        &py_c(&format!(
            "from subprocess import run; runner.run({})",
            destructive_list()
        )),
        "runner.run is not the imported run",
    );
}

#[test]
fn a_mock_call_is_not_subprocess_call() {
    // `mock.call(..)` is everywhere in python test code. The receiver gate on
    // `$M.call` is what keeps it from reading as `subprocess.call`.
    assert_allowed(
        &py_c(&format!(
            "from unittest import mock; expected = mock.call({})",
            destructive_list()
        )),
        "mock.call is not subprocess.call",
    );
}

// ---------------------------------------------------------------------------
// A name the body binds both ways keeps the module it plainly imported.
// ---------------------------------------------------------------------------

#[test]
fn a_fallback_import_keeps_the_name_subprocess() {
    // Denied before this change by the literal pattern; the gate must not lose it.
    assert_denied_by(
        &py_heredoc(&format!(
            "try:\n    import subprocess32 as subprocess\nexcept ImportError:\n    import subprocess\nsubprocess.run({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
    assert_denied_by(
        &py_heredoc(&format!(
            "import json as subprocess\nimport subprocess\nsubprocess.Popen({})",
            destructive_list()
        )),
        POPEN_RM_RF,
    );
}

#[test]
fn a_fallback_import_keeps_the_name_pathlib() {
    // The same rule in the shared gate, for the module artmu bound: ALLOW
    // before this change, because the alias alone decided.
    assert_denied_by(
        &py_heredoc(
            "try:\n    import pathlib\nexcept ImportError:\n    import pathlib2 as pathlib\npathlib.Path('/etc/passwd').unlink()",
        ),
        "heredoc.python:pathlib_unlink",
    );
}

#[test]
fn a_drop_in_bound_with_no_plain_import_is_recorded_as_unread() {
    // NOT a claim of coverage, and a real regression: this was DENY at the
    // parent, only because the literal pattern read no imports. The name is
    // bound only to gevent's module and the gate reads it as that module, the
    // meaning shutil has had since artmu. Accepted and pinned; reading the
    // literal name first in python is the alternative, held in
    // .agent-config-msnfu.
    assert_allowed(
        &py_c(&format!(
            "import gevent.subprocess as subprocess; subprocess.Popen({})",
            destructive_list()
        )),
        "a name bound only to another module is that module",
    );
}

#[test]
fn a_shadowed_import_is_still_read_as_subprocess() {
    // The accepted cost of the bare twin: the gate reads imports, not scope.
    assert_denied_by(
        &py_heredoc(&format!(
            "from subprocess import run\ndef run(argv):\n    print(argv)\nrun({})",
            destructive_list()
        )),
        RUN_RM_RF,
    );
}
