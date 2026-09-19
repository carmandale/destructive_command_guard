//! A git global option before the subcommand does not hide it
//! (`.agent-config-5cw2y`).
//!
//! The shared payload detector took the FIRST word after `git` as the
//! subcommand, so an argv that puts a global option first read `-C` as the
//! subcommand. In a terminated `node <<'JS'` heredoc, on origin/main 3b648f5a
//! and again on d022cf8c:
//!
//! ```text
//!   cp.spawnSync("git", ["-C", "/repo", "reset", "--hard"])  | ALLOW
//!   cp.spawnSync("git", ["-C", ".", "clean", "-fd"])         | ALLOW
//!   cp.execSync("git -C /repo reset --hard")                 | DENY core.git:reset-hard
//! ```
//!
//! The argv rows were real fail-opens: the argv is split into separate
//! literals, so no raw-text rule sees `reset --hard`. The execSync row was
//! denied only because `core.git` reads the raw text; it pins which rule now
//! reads the call.
//!
//! Every argv reader shares that detector: `spawn`, `spawnSync`,
//! `execFile`, `execFileSync` (`.agent-config-crqi7`), a Python `subprocess`
//! list (`.agent-config-ei4it`), and the shell strings of `exec`/`execSync`.
//!
//! The detector now skips git's global options before choosing the
//! subcommand. Which options take a value is
//! `context::git_global_option_takes_value`, the list the sanitizer already
//! used to find a `git grep`, measured against git 2.55.0 and extended by the
//! two it missed (`--attr-source`, `--shallow-file`). A value-taking option is
//! read both ways, owning the next word and not, because an argv reader keeps
//! only the string literals it finds: `["-C", dir, "reset", "--hard"]` arrives
//! as `-C reset --hard`, and reading `reset` as `-C`'s value alone allowed it.
//! Every word either reading reaches is judged as the subcommand; the most
//! severe hit decides. Two or more literals inside one element
//! (`path.join(dir, "a", "b")`) still hide it
//! (`.agent-config-argv-nested-literal-txccq`).
//!
//! The two added options also closed a plain-shell fail-open in the sanitizer:
//! `git --shallow-file grep reset --hard` runs `reset --hard` (grep is the
//! option's value), but the sanitizer took `grep` for the subcommand and
//! masked `reset --hard` as its pattern, so `core.git` never saw it.
//!
//! Accepted over-blocks. On commands that run nothing: an option that makes
//! git exit before the subcommand (`--html-path`, `--list-cmds=`,
//! `--exec-path`, `-h`, `-v`) or one git rejects (`-C<dir>`, `--`, `--pager`)
//! -- a destructive word after it is judged anyway. On commands that run:
//! reading both ways judges the word after a value-taking option as a
//! subcommand too (a directory named `clean`: `git -C clean log
//! --diff-filter=d` in a shell string), and when the value was dropped, the
//! real subcommand's own options are read as global ones, so a word after
//! them is judged as well (`["-C", dir, "grep", "-e", "reset --hard"]`,
//! `["-C", dir, "commit", "-m", "reset --hard is bad"]`).
//!
//! Every deny asserts the `ruleId`, so a deny from the regex sweep or from
//! another pack cannot pass for the rule reading the call.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Assembled at runtime so this source file is not itself a payload.
const GIT: &str = "git";
const RESET: &str = "reset";
const CLEAN: &str = "clean";

const JS_RESET: &str = "heredoc.javascript:spawnsync.git_reset_hard";
const JS_CLEAN: &str = "heredoc.javascript:spawnsync.git_clean_fd";

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

fn node(body: &str) -> String {
    format!("node <<'JS'\n{body}\nJS")
}

/// `cp.spawnSync("git", [<options>..., <rest>...])` in a node heredoc.
fn spawn_git(options: &[&str], rest: &[&str]) -> String {
    let argv: Vec<String> = options
        .iter()
        .chain(rest)
        .map(|word| format!("{word:?}"))
        .collect();
    node(&format!(
        r#"const cp=require("child_process"); cp.spawnSync("{GIT}",[{}])"#,
        argv.join(",")
    ))
}

/// Global-option spellings git 2.55.0 runs a subcommand after: every
/// separate-value option, a sample of the attached `=` forms and flag-only
/// options, and a stack of them.
const GLOBAL_OPTIONS: &[&[&str]] = &[
    &["-C", "/repo"],
    &["-c", "core.pager=cat"],
    &["--git-dir", "/repo/.git"],
    &["--git-dir=/repo/.git"],
    &["--work-tree", "/repo"],
    &["--work-tree=/repo"],
    &["--namespace", "n"],
    &["--namespace=n"],
    &["--config-env", "core.editor=HOME"],
    &["--attr-source", "HEAD"],
    &["--attr-source=HEAD"],
    &["--shallow-file", "f"],
    &["--no-pager"],
    &["-P"],
    &["-p"],
    &["--no-optional-locks"],
    &["-C", ".", "-c", "a.b=c", "--no-pager"],
];

/// `cp.spawnSync("git", [<elements>])`, the elements written as JS source,
/// with `dir` bound to a string the literal extractor does not read.
fn spawn_git_js(elements: &str) -> String {
    node(&format!(
        r#"const cp=require("child_process"); const dir="/repo"; cp.spawnSync("{GIT}",[{elements}])"#
    ))
}

#[test]
fn a_global_option_before_reset_hard_denies() {
    for options in GLOBAL_OPTIONS {
        assert_denied_by(&spawn_git(options, &[RESET, "--hard"]), JS_RESET);
    }
}

#[test]
fn a_global_option_before_clean_fd_denies() {
    for options in GLOBAL_OPTIONS {
        assert_denied_by(&spawn_git(options, &[CLEAN, "-fd"]), JS_CLEAN);
    }
}

#[test]
fn a_value_that_is_not_a_literal_does_not_hide_the_subcommand() {
    // The reader keeps only literals, so each value is dropped (a template is
    // kept as one word): the option must not be read as owning `reset`. One
    // literal inside a call stands in for the value it replaced.
    for value in [
        "dir",
        "opts.dir",
        "process.cwd()",
        "`${dir}/sub`",
        "path.join(dir, sub)",
        r#"path.join(dir, "x")"#,
    ] {
        let elements = format!(r#""-C",{value},"{RESET}","--hard""#);
        assert_denied_by(&spawn_git_js(&elements), JS_RESET);
    }
    for elements in [
        format!(r#""-c",dir,"{RESET}","--hard""#),
        format!(r#""--git-dir",dir,"{RESET}","--hard""#),
        format!(r#""-C",dir,"-c","a.b=c","{RESET}","--hard""#),
    ] {
        assert_denied_by(&spawn_git_js(&elements), JS_RESET);
    }
    assert_denied_by(
        &spawn_git_js(&format!(r#""-C",dir,"{CLEAN}","-fd""#)),
        JS_CLEAN,
    );
}

#[test]
fn a_plain_command_is_not_masked_as_a_grep_pattern() {
    // `grep` is the option's value; git runs `reset --hard` (measured on
    // 2.55.0). The sanitizer took `grep` for the subcommand and masked the
    // rest as its pattern, so core.git never saw it.
    for option in ["--shallow-file", "--attr-source"] {
        let command = format!("{GIT} {option} grep {RESET} --hard");
        assert_denied_by(&command, "core.git:reset-hard");
    }
}

#[test]
fn every_argv_reader_skips_the_options() {
    // The bead's own row: `spawn`, and the rest of child_process with it.
    for (call, rule) in [
        ("spawn", "heredoc.javascript:spawn.git_reset_hard"),
        ("execFile", "heredoc.javascript:execfile.git_reset_hard"),
        (
            "execFileSync",
            "heredoc.javascript:execfilesync.git_reset_hard",
        ),
    ] {
        let body = format!(
            r#"const cp=require("child_process"); cp.{call}("{GIT}",["-C","/repo","{RESET}","--hard"])"#
        );
        assert_denied_by(&node(&body), rule);
    }
    let body =
        format!(r#"const cp=require("child_process"); cp.exec("{GIT} -C /repo {RESET} --hard")"#);
    assert_denied_by(&node(&body), "heredoc.javascript:exec.git_reset_hard");
    // A Python list, its value a name the reader drops.
    let py = format!(
        "python3 -c \"import subprocess; repo='/repo'; subprocess.run(['{GIT}', '-C', repo, '{RESET}', '--hard'])\""
    );
    assert_denied_by(&py, "heredoc.python:subprocess_run.git_reset_hard");
}

#[test]
fn typescript_reads_the_same_argv() {
    let body = format!(
        r#"import * as cp from "child_process"; cp.spawnSync("{GIT}", ["-C", "/repo", "{RESET}", "--hard"]);"#
    );
    assert_denied_by(
        &format!("deno run - <<'TS'\n{body}\nTS"),
        "heredoc.typescript:spawnsync.git_reset_hard",
    );
}

#[test]
fn an_exec_sync_string_is_read_by_the_rule_that_read_the_call() {
    // Denied before the fix too, but by core.git reading the raw text.
    let body = format!(
        r#"const cp=require("child_process"); cp.execSync("{GIT} -C /repo {RESET} --hard")"#
    );
    assert_denied_by(&node(&body), "heredoc.javascript:execsync.git_reset_hard");
}

#[test]
fn a_benign_subcommand_after_global_options_allows() {
    assert_allowed(&spawn_git(&["-C", "."], &["status"]));
    assert_allowed(&spawn_git(&["--git-dir=.git"], &["log", "--oneline"]));
    assert_allowed(&spawn_git(&["-c", "core.pager=cat"], &["diff"]));
    // Reading a value both ways does not make a benign call destructive.
    // Only a word the option skip reaches is a subcommand: the joined reading
    // splits `-S`'s value into `reset --hard`, after the real subcommand, and
    // a flag-only option owns no word that would let the skip reach it.
    let search = format!("{RESET} --hard");
    assert_allowed(&spawn_git(&["-C", "."], &["log", "-S", &search]));
    assert_allowed(&spawn_git(&["--no-pager"], &["log", "-S", &search]));
}
