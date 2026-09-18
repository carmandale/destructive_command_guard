//! A heredoc nested inside a bash heredoc body must be judged
//! (`.agent-config-0awpo`).
//!
//! Tier 2.5 reads a bash body by handing each simple command it contains back
//! to the evaluator. tree-sitter hangs a heredoc body off a sibling
//! `heredoc_redirect`, not off the `command` node, so `python3 <<'PY' ... PY`
//! inside a bash body reached the evaluator as a bare `python3`: the body met
//! no rule. The top-level extractor does not rescue it either -- an
//! unterminated nested body is skipped, and a terminated one takes the
//! language of the command's first word (`bash`), so python is read as bash.
//!
//! Before `.agent-config-dcg-fallback-scans-judged-content-zc6tb` the
//! unterminated spelling was still caught, by accident: extraction went
//! `Partial` and the fallback sweep read the raw text. zc6tb masks a body once
//! its matches are judged, which is right for what was read and wrong for a
//! nested body nobody read. The fix is to read it, not to unmask it: unmasking
//! brings back the false positive zc6tb closed, because a `$((1 << 4))` in a
//! bash body reads to the context-free extractor as an unterminated heredoc
//! too (the `a_warned_reset_hard_*` rows below).
//!
//! Measured 2026-09-18 in hook mode, sandboxed like this file:
//!
//! ```text
//!   row                                        | main 639a354b | fixed
//!   -------------------------------------------|---------------|------
//!   unterminated_nested_os_remove (A)          | ALLOW         | DENY os_remove
//!   unterminated_nested_rmtree (E)             | ALLOW         | DENY shutil_rmtree
//!   terminated_nested_os_remove (D)            | ALLOW         | DENY
//!   the same body at top level (C)             | DENY          | DENY
//!   warned reset-hard beside $((1 << 4)) (F)   | WARN          | WARN
//!   nested cat body quoting rm -rf (I)         | ALLOW         | ALLOW
//!   commit prose quoting `python3 <<'PY'`      | ALLOW         | ALLOW
//!   unterminated nested cat body               | ALLOW         | ALLOW
//! ```
//!
//! The last two rows were DENY on 97303189, the first cut of this fix, which
//! handed an unterminated nested statement back unterminated, so only the raw
//! fallback read it. Found by its cold review; bash runs such a body to the end
//! of input, so it is now written out terminated there.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

fn run_hook(
    mut cmd: std::process::Command,
    sandbox: &spawn::Sandbox,
    command: &str,
) -> (String, String, i32) {
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

/// Default policy, `core` packs: no rule downgrade is needed to show the hole.
fn run_default(command: &str) -> (String, String, i32) {
    let (cmd, sandbox) = spawn::dcg();
    run_hook(cmd, &sandbox, command)
}

/// The live config's shape: the two rules Dale actually downgrades.
fn run_with_warned_rules(command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(
        &config_path,
        "[policy.rules]\n\
         \"core.git:reset-hard\" = \"warn\"\n\
         \"heredoc.python:shutil_rmtree\" = \"warn\"\n",
    )
    .expect("write policy config");
    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem");
    run_hook(cmd, &sandbox, command)
}

/// The hook's `permissionDecision`, or `None` when it printed nothing (allow,
/// or a policy warning, which goes to stderr).
fn decision(stdout: &str) -> Option<String> {
    if stdout.trim().is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("hook stdout is not JSON ({e}): {stdout}"));
    Some(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_else(|| panic!("no permissionDecision in: {stdout}"))
            .to_string(),
    )
}

fn assert_denied(command: &str, (stdout, stderr, exit_code): (String, String, i32), why: &str) {
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    assert_eq!(
        decision(&stdout).as_deref(),
        Some("deny"),
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_only_warned(
    command: &str,
    (stdout, stderr, exit_code): (String, String, i32),
    why: &str,
) {
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    assert_eq!(
        decision(&stdout),
        None,
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("allowed by policy") && stderr.contains("git reset --hard"),
        "the warned rule must still be REPORTED, or `None` above is just an allow \
         ({why})\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The measured defect: every row here ALLOWED on main 639a354b.
// ---------------------------------------------------------------------------

/// Case A of the bead. bash runs an unterminated heredoc to the end of its
/// input, so python really does receive the `os.remove`.
const UNTERMINATED_OS_REMOVE: &str =
    "bash <<'EOF'\necho hi\npython3 <<'PY'\nimport os; os.remove('/etc/hosts')\nEOF";

/// Case E: the same shape with the other destructive python call the bead
/// names.
const UNTERMINATED_RMTREE: &str =
    "bash <<'EOF'\necho hi\npython3 <<'PY'\nimport shutil; shutil.rmtree('/srv/data')\nEOF";

/// Case D: the nested heredoc TERMINATED. Older than zc6tb, and the deeper
/// root: no fallback was ever reached here, because extraction is complete.
const TERMINATED_OS_REMOVE: &str =
    "bash <<'EOF'\necho hi\npython3 <<'PY'\nimport os; os.remove('/etc/hosts')\nPY\nEOF";

/// The unterminated rows are judged by the python RULE, not by the regex sweep:
/// bash runs the body to the end of input, so it is read as if terminated there.
/// A sweep-only deny here would also hard-deny prose (the commit-message rows).
#[test]
fn an_unterminated_nested_python_heredoc_in_a_bash_body_is_denied() {
    let (stdout, stderr, exit_code) = run_default(UNTERMINATED_OS_REMOVE);
    assert!(
        stdout.contains("os_remove"),
        "judged by the python rule\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_denied(
        UNTERMINATED_OS_REMOVE,
        (stdout, stderr, exit_code),
        "the nested body reaches python; something must read it",
    );
}

#[test]
fn an_unterminated_nested_rmtree_in_a_bash_body_is_denied() {
    let (stdout, stderr, exit_code) = run_default(UNTERMINATED_RMTREE);
    assert!(
        stdout.contains("shutil_rmtree"),
        "judged by the python rule\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_denied(
        UNTERMINATED_RMTREE,
        (stdout, stderr, exit_code),
        "the nested body reaches python; something must read it",
    );
}

/// Cold review of 97303189 (false-positive lens): prose that dcg guesses is
/// bash, quoting an unterminated heredoc operator, was swept by the fallback
/// and hard-denied. main 639a354b allows both rows.
const COMMIT_PROSE_QUOTING_A_HEREDOC: &str = "git commit -F - <<'MSG'\n\
     fix(dcg): judge nested heredoc bodies\n\
     \n\
     The guard skipped the python3 <<'PY' body nested in a bash body,\n\
     for example one that calls os.remove on a scratch file.\n\
     MSG";

#[test]
fn commit_prose_quoting_an_unterminated_heredoc_is_allowed() {
    let (stdout, stderr, exit_code) = run_default(COMMIT_PROSE_QUOTING_A_HEREDOC);
    assert_eq!(exit_code, 0, "stderr: {stderr}");
    assert_eq!(
        decision(&stdout),
        None,
        "prose is not swept as unjudged code\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn a_warned_reset_hard_in_prose_quoting_a_heredoc_only_warns() {
    let cmd = "git commit -F - <<'MSG'\n\
         fix: judge ${nested} bodies\n\
         A python3 <<'PY' body nested in bash was read by nothing.\n\
         The test pins git reset --hard as a warning.\n\
         MSG";
    assert_only_warned(
        cmd,
        run_with_warned_rules(cmd),
        "main warns here; an unjudged-content sweep must not turn it into a hard deny",
    );
}

/// Cold review 2 (fail-open under the live policy shape): the nested statement
/// is emitted ahead of the sibling after it, so a warned rule in the nested
/// body, returned first, turned main's DENY of the later `rm -rf` into a WARN.
/// A nested denial is held until nothing else denies.
#[test]
fn a_warned_nested_rule_does_not_hide_a_later_hard_denied_sibling() {
    let cmd = "bash <<'EOF'\npython3 <<'PY'\nimport shutil; shutil.rmtree('/srv/cache')\nPY\n\
               rm -rf /srv/data\nEOF";
    let (stdout, stderr, exit_code) = run_with_warned_rules(cmd);
    assert!(
        stdout.contains("rm-rf"),
        "the sibling's rule decides, not the warned nested one\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_denied(
        cmd,
        (stdout, stderr, exit_code),
        "main denies this command; reading the nested body must not weaken it",
    );
}

#[test]
fn an_unterminated_nested_cat_body_is_allowed() {
    let cmd = "bash <<'EOF'\ncat <<X\nnotes: os.remove is used by the cleanup step\nEOF";
    let (stdout, stderr, exit_code) = run_default(cmd);
    assert_eq!(exit_code, 0, "stderr: {stderr}");
    assert_eq!(
        decision(&stdout),
        None,
        "an unterminated cat body is still data\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn a_terminated_nested_python_heredoc_in_a_bash_body_is_denied_by_its_rule() {
    let (stdout, stderr, exit_code) = run_default(TERMINATED_OS_REMOVE);
    assert!(
        stdout.contains("os_remove"),
        "a complete nested body is judged by the python rule, not by the regex \
         sweep\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_denied(
        TERMINATED_OS_REMOVE,
        (stdout, stderr, exit_code),
        "the nested body reaches python; its rule must read it",
    );
}

// ---------------------------------------------------------------------------
// The controls: what a wider fix -- unmasking bash bodies, or reading every
// `<<` in them as a heredoc -- would break.
// ---------------------------------------------------------------------------

/// Case C: the floor under rows A and D. The python rule denies this body when
/// nothing wraps it, so a red above is about the nesting, not the rule.
#[test]
fn the_same_python_body_at_top_level_is_denied() {
    let cmd = "python3 <<'PY'\nimport os; os.remove('/etc/hosts')\nPY";
    assert_denied(cmd, run_default(cmd), "the rule itself fires");
}

/// fxck7's and zc6tb's false positive, the constraint on this fix. `<< 4` is an
/// arithmetic shift the bash parser does not read as a heredoc; the context-free
/// extractor does, so extraction is `Partial` and the sweep runs. The warned
/// `git reset --hard` was judged, so it must stay a warning, not an "unjudged"
/// hard deny.
const WARNED_RESET_BESIDE_A_SHIFT: &str = "bash <<'EOF'\nx=$((1 << 4))\ngit reset --hard\nEOF";

#[test]
fn a_warned_reset_hard_beside_an_arithmetic_shift_only_warns() {
    assert_only_warned(
        WARNED_RESET_BESIDE_A_SHIFT,
        run_with_warned_rules(WARNED_RESET_BESIDE_A_SHIFT),
        "the rule was judged and the policy warns on it",
    );
}

#[test]
fn a_reset_hard_beside_an_arithmetic_shift_denies_by_default() {
    assert_denied(
        WARNED_RESET_BESIDE_A_SHIFT,
        run_default(WARNED_RESET_BESIDE_A_SHIFT),
        "the warn row above is the policy, not a reader that went blind",
    );
}

/// Reading the nested statement must not turn prose into code: a `cat` body is
/// data wherever it is spelled, which is what spec 333 exists for.
#[test]
fn a_nested_cat_body_quoting_rm_rf_is_allowed() {
    let cmd = "bash <<'EOF'\ncat <<'X' > notes.md\nnever run rm -rf /srv/x here\nX\nEOF";
    let (stdout, stderr, exit_code) = run_default(cmd);
    assert_eq!(exit_code, 0, "stderr: {stderr}");
    assert_eq!(
        decision(&stdout),
        None,
        "a nested cat body is data\nstdout: {stdout}\nstderr: {stderr}"
    );
}
