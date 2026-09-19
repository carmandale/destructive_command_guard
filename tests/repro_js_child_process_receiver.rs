//! A `child_process` call is read on whatever the module is bound to
//! (`.agent-config-w9pvb`).
//!
//! The JavaScript and TypeScript heredoc rules named the receiver:
//! `child_process.spawnSync($$$)`, `child_process.execSync($$$)`. ast-grep
//! matches that identifier literally, so in a terminated `node <<'JS'` heredoc:
//!
//! ```text
//!   spelling                                            | before the fix
//!   ----------------------------------------------------|------------------------------------
//!   cp.spawnSync("rm", ["-rf", "/srv"])   (aliased)     | ALLOW
//!   spawnSync("rm", ["-rf", "/srv"])      (destructured)| ALLOW
//!   require("child_process").spawnSync(..)              | ALLOW
//!   cp.execSync("rm -rf /srv") / execSync("rm -rf /srv")| DENY core.filesystem:rm-rf-root-home
//! ```
//!
//! The spawnSync rows were real fail-opens: the argv is split into separate
//! literals, so no raw-text regex sees `rm -rf`, and extraction was complete, so
//! the fallback sweep never ran. The execSync rows were already denied, but by
//! `core.filesystem` reading the raw command, not by a rule that read the call;
//! those rows pin WHICH rule reads it.
//!
//! The rules now take any receiver (`$M.spawnSync($$$)`) and the bare call
//! (`spawnSync($$$)`). A match only blocks when the payload classifier finds a
//! destructive LITERAL (critical/high); a benign or dynamic call stays medium,
//! which the hook skips. What the classifier gets wrong now reaches every
//! receiver. A spawnSync argv is read twice, and the MOST SEVERE hit of either
//! reading decides (a less severe hit never hides a more severe one, here or
//! across the segments of any shell line -- a policy warn can downgrade a high
//! hit, never a critical one): as
//! words, the way it runs with no shell (`/bin/rm`, `/usr/bin/env`, an
//! `sh -c` script), and as the joined line, the way `{ shell: true }` runs it
//! and the only reading the rule had before. With the joined reading
//! unconditional and most-severe aggregation, the old rule's hit is always a
//! candidate, so no verdict is less severe than it was. Every cut that broke
//! one of those halves reopened a call the old rule blocked: words only, a text
//! guess at an options argument, first-hit and first-blocking-hit aggregation.
//! Three false positives remain, all over-blocking: a shell line -- an execSync
//! payload, an `sh -c` script, or a joined argv -- is split on `;` `|` `&`
//! without quote awareness (`.agent-config-fqbws`); and a dry-run
//! `git clean -n -fd` is judged
//! destructive (`.agent-config-g5xom`); and a `--long-option` is scanned as short
//! flags, so `--verbose` reads as `-r` (`.agent-config-6j4tg`). A dry-run veto was
//! tried and removed:
//! every spelling of git's option grammar it missed (`-enode_modules`,
//! `-e -n`, `--exclude -n`, `-- -n`) was a fail-open that origin/main denies
//! on the `child_process.` receiver.
//!
//! `require('child_process').execSync(..)` gets its `require_execsync` id from
//! the receiver, not from a second pattern: two patterns on one call produced
//! two matches, and allowlisting both ids the deny could name still denied.
//!
//! Still NOT read, recorded rather than claimed: `cp.execFileSync`, `cp.spawn`,
//! `cp.exec`, a renamed destructure (`{ spawnSync: s }`), `cp?.spawnSync`,
//! `cp["spawnSync"]`, a template-literal argv, a TS generic call
//! (`.agent-config-crqi7`); an unterminated body, which only the fallback regex
//! sweep reads -- by call shape, with no payload judged (`.agent-config-artmu`
//! gave it the bare `spawnSync(` / `execSync(` shapes); a node heredoc
//! nested in a bash heredoc body (`.agent-config-0awpo`); a catastrophic `rm`
//! target after the first, or under `/Users` (`.agent-config-b8m7s`).
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

/// Assembled at runtime so this source file is not itself a payload.
const RM: &str = "rm";
const GIT: &str = "git";

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

fn assert_allowed(command: &str) {
    let out = hook(command);
    assert!(
        out.is_null(),
        "must allow (empty hook stdout)\ncommand: {command:?}\noutput: {out}"
    );
}

const JS_SPAWN_RM: &str = "heredoc.javascript:spawnsync.rm_rf_catastrophic";
const JS_EXEC_RM: &str = "heredoc.javascript:execsync.rm_rf_catastrophic";
const JS_REQUIRE_EXEC_RM: &str = "heredoc.javascript:require_execsync.rm_rf_catastrophic";
const TS_SPAWN_RM: &str = "heredoc.typescript:spawnsync.rm_rf_catastrophic";
const TS_EXEC_RM: &str = "heredoc.typescript:execsync.rm_rf_catastrophic";

// ---------------------------------------------------------------------------
// The fail-opens: a spawnSync argv on a receiver not named `child_process`.
// ---------------------------------------------------------------------------

#[test]
fn an_aliased_spawn_sync_with_a_destructive_argv_denies() {
    // The spelling the fail-open lane measured ALLOW on `main` 639a354b.
    let body = format!(r#"const cp=require("child_process"); cp.spawnSync("{RM}",["-rf","/srv"])"#);
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn a_destructured_spawn_sync_with_a_destructive_argv_denies() {
    let body = format!(
        r#"const {{ spawnSync }} = require("child_process"); spawnSync("{RM}", ["-rf", "/srv"])"#
    );
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn an_inline_require_spawn_sync_denies() {
    let body = format!(r#"require("child_process").spawnSync("{RM}",["-rf","/srv"])"#);
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn a_node_prefixed_module_alias_denies() {
    let body =
        format!(r#"const cp=require("node:child_process"); cp.spawnSync("{RM}",["-rf","/srv"])"#);
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn typescript_spawn_sync_on_any_receiver_denies() {
    let aliased = format!(
        r#"import * as cp from "child_process"; cp.spawnSync("{RM}", ["-rf", "/srv"] as string[]);"#
    );
    assert_denied_by(&ts(&aliased), TS_SPAWN_RM);
    let destructured = format!(
        r#"import {{ spawnSync }} from "node:child_process"; spawnSync("{RM}", ["-rf", "/srv"]);"#
    );
    assert_denied_by(&ts(&destructured), TS_SPAWN_RM);
}

// ---------------------------------------------------------------------------
// The argv is read as a command's words -- the way it runs with no shell -- as
// well as the joined line (below); either reading denies.
// ---------------------------------------------------------------------------

#[test]
fn a_spawn_sync_of_rm_by_path_denies() {
    let body =
        format!(r#"const cp=require("child_process"); cp.spawnSync("/bin/{RM}",["-rf","/srv"])"#);
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn a_spawn_sync_of_a_shell_script_is_read_as_a_script() {
    for shell in ["sh", "bash"] {
        let body = format!(
            r#"const cp=require("child_process"); cp.spawnSync("{shell}",["-c","{RM} -rf /srv"])"#
        );
        assert_denied_by(&node(&body), JS_SPAWN_RM);
    }
}

#[test]
fn a_spawn_sync_through_sudo_still_denies() {
    // The wrapper skip the shell-string reader had must survive the argv reader.
    let body =
        format!(r#"const cp=require("child_process"); cp.spawnSync("sudo",["{RM}","-rf","/srv"])"#);
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

// `next_shell_command` compares wrappers by basename, as the command word is.
// One test per wrapper, so each has its own red.

#[test]
fn a_spawn_sync_through_env_by_path_still_denies() {
    let body = format!(
        r#"const cp=require("child_process"); cp.spawnSync("/usr/bin/env",["{RM}","-rf","/srv"])"#
    );
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn a_spawn_sync_through_sudo_by_path_still_denies() {
    let body = format!(
        r#"const cp=require("child_process"); cp.spawnSync("/usr/bin/sudo",["{RM}","-rf","/srv"])"#
    );
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

// ---------------------------------------------------------------------------
// execSync: already denied by core.filesystem's raw-text read; now the rule
// that read the call is the one that denies.
// ---------------------------------------------------------------------------

#[test]
fn an_aliased_exec_sync_is_denied_by_the_rule_that_read_it() {
    let body = format!(r#"const cp=require("child_process"); cp.execSync("{RM} -rf /srv")"#);
    assert_denied_by(&node(&body), JS_EXEC_RM);
}

#[test]
fn a_destructured_exec_sync_is_denied_by_the_rule_that_read_it() {
    let body =
        format!(r#"const {{ execSync }} = require("child_process"); execSync("{RM} -rf /srv")"#);
    assert_denied_by(&node(&body), JS_EXEC_RM);
}

#[test]
fn typescript_exec_sync_on_any_receiver_is_denied_by_the_rule_that_read_it() {
    let aliased = format!(r#"import * as cp from "child_process"; cp.execSync("{RM} -rf /srv");"#);
    assert_denied_by(&ts(&aliased), TS_EXEC_RM);
    let destructured =
        format!(r#"import {{ execSync }} from "child_process"; execSync("{RM} -rf /srv");"#);
    assert_denied_by(&ts(&destructured), TS_EXEC_RM);
}

// ---------------------------------------------------------------------------
// Rule ids for the spellings that already had a rule, and the ones that gain it.
// ---------------------------------------------------------------------------

#[test]
fn the_child_process_spelling_still_denies() {
    let body = format!(
        r#"const child_process=require("child_process"); child_process.spawnSync("{RM}",["-rf","/srv"])"#
    );
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn the_single_quoted_require_spelling_keeps_its_rule_id() {
    // The exact spelling the old `require('child_process').execSync($$$)`
    // pattern matched: `require_execsync` before, `require_execsync` now.
    let body = format!("require('child_process').execSync('{RM} -rf /srv')");
    assert_denied_by(&node(&body), JS_REQUIRE_EXEC_RM);
}

#[test]
fn other_require_spellings_gain_the_require_rule_id() {
    // The old pattern was quote-literal, so these were denied by
    // core.filesystem's raw-text read; they now carry `require_execsync`.
    for module in [r#""child_process""#, "'node:child_process'"] {
        let body = format!(r#"require({module}).execSync("{RM} -rf /srv")"#);
        assert_denied_by(&node(&body), JS_REQUIRE_EXEC_RM);
    }
}

#[test]
fn allowlisting_the_id_a_require_execsync_deny_names_allows_it() {
    // The first cold review's material finding: while `require('child_process')`
    // had a pattern of its own AND matched the any-receiver pattern, one call was
    // two matches, and this allowlist -- the heredoc id the deny names, plus the
    // core rule that reads the same raw text -- still denied under
    // `execsync.git_reset_hard`. Both entries are needed: each rule reads it.
    for (lang, command) in [
        (
            "javascript",
            node(&format!(
                "require('child_process').execSync('{GIT} reset --hard')"
            )),
        ),
        (
            "typescript",
            ts(&format!(
                "require('child_process').execSync('{GIT} reset --hard');"
            )),
        ),
    ] {
        let rule = format!("heredoc.{lang}:require_execsync.git_reset_hard");
        // Control: without the allowlist this denies under exactly that id, so
        // the ALLOW below is the allowlist working, not the rule never firing.
        assert_verdict_denied_by(&hook(&command), &command, &rule);

        let allowlist = format!(
            "[[allow]]\nrule = \"{rule}\"\nreason = \"w9pvb fixture\"\n\n\
             [[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"w9pvb fixture\"\n"
        );
        let out = hook_with_allowlist(&command, Some(&allowlist));
        assert!(
            out.is_null(),
            "allowlisting the id the deny names must allow it\ncommand: {command:?}\noutput: {out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Controls: a call is not a verdict. Only a destructive literal payload blocks.
// ---------------------------------------------------------------------------

#[test]
fn a_benign_aliased_spawn_sync_allows() {
    assert_allowed(&node(
        r#"const cp=require("child_process"); cp.spawnSync("ls")"#,
    ));
    assert_allowed(&node(
        r#"const cp=require("child_process"); cp.spawnSync("ls",["-la","/srv"])"#,
    ));
}

#[test]
fn a_benign_destructured_call_allows() {
    assert_allowed(&node(
        r#"const { spawnSync, execSync } = require("child_process"); spawnSync("ls", ["-la"]); execSync("echo hi")"#,
    ));
}

#[test]
fn a_dynamic_aliased_call_allows() {
    // No literal payload to judge: the refinement keeps this medium, which the
    // hook does not block. Widening the receiver must not turn this into a deny.
    assert_allowed(&node(
        r#"const cp=require("child_process"); const c=process.argv[2]; cp.execSync(c); cp.spawnSync(c, [])"#,
    ));
}

#[test]
fn a_non_catastrophic_rm_rf_does_not_deny() {
    // `rm -rf ./build` refines to medium, the same as it does for the
    // `child_process.` spelling.
    assert_allowed(&node(&format!(
        r#"const cp=require("child_process"); cp.spawnSync("{RM}",["-rf","./build"])"#
    )));
}

#[test]
fn a_forced_git_clean_denies_whatever_its_exclude_pattern_says() {
    // No dry-run veto exists (`.agent-config-g5xom`). Row 1 is the control. The
    // others are spellings a veto got wrong -- an exclude pattern or a pathspec
    // holding `n` read as the dry-run flag: rows 2-3 were ALLOWED by the first
    // veto (a697de7d), rows 4-6 by the one that cut clusters at `e` (131f202b).
    // origin/main denies all six on the `child_process.` receiver. A future
    // veto must keep every one of them denied.
    for args in [
        r#""clean","-fd""#,
        r#""clean","-fd","-enode_modules""#,
        r#""clean","-fdenode_modules""#,
        r#""clean","-fd","-e","-n""#,
        r#""clean","-fd","--exclude","-n""#,
        r#""clean","-fd","--","-n",".""#,
    ] {
        assert_denied_by(
            &node(&format!(
                r#"const cp=require("child_process"); cp.spawnSync("{GIT}",[{args}])"#
            )),
            "heredoc.javascript:spawnsync.git_clean_fd",
        );
    }
    assert_denied_by(
        &node(&format!(
            r#"const cp=require("child_process"); cp.execSync("{GIT} clean -fd")"#
        )),
        "heredoc.javascript:execsync.git_clean_fd",
    );
}

#[test]
fn a_non_blocking_hit_never_hides_a_blocking_one() {
    // A non-catastrophic recursive delete refines to medium, which the hook does
    // not block. Taken as THE verdict because it came first, it hid a blocking
    // hit after it -- in a later segment, or in the other reading of an argv.
    // Every row is DENIED by the pre-change binary for this spelling and was
    // ALLOWED by the first-hit cut (the superset-pass reviewer's rows).
    let git_reset = "heredoc.javascript:spawnsync.git_reset_hard";
    for (call, rule) in [
        (
            format!(
                r#"child_process.spawnSync("bash",["-c","{RM} -rf ./dist && {GIT} reset --hard origin/main"],{{stdio:"inherit"}})"#
            ),
            git_reset,
        ),
        (
            format!(
                r#"child_process.spawnSync("sh",["-c","{RM} -rf build && {GIT} reset --hard"])"#
            ),
            git_reset,
        ),
        (
            format!(r#"child_process.spawnSync("sh",["-c","{RM} -rf build; {RM} -rf /"])"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"child_process.spawnSync("{RM}",["-rf /","build"])"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"child_process.spawnSync("{RM}",["-rf","/ build"])"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"child_process.spawnSync("/bin/{RM}",["-rf","build;","{RM}","-rf","/"])"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"child_process.spawnSync("{RM}",["-rf","build;","{RM}","-rf","/"])"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"child_process.execSync("/bin/{RM} -rf build; {RM} -rf /")"#),
            JS_EXEC_RM,
        ),
        (
            format!(
                r#"child_process.execSync("/usr/bin/env {RM} -rf build && {GIT} reset --hard")"#
            ),
            "heredoc.javascript:execsync.git_reset_hard",
        ),
    ] {
        let body = format!(r#"const child_process=require("child_process"); {call}"#);
        assert_denied_by(&node(&body), rule);
    }
    let ts_body = format!(
        r#"import * as child_process from "child_process"; child_process.spawnSync("sh", ["-c", "{RM} -rf build; {RM} -rf /"]);"#
    );
    assert_denied_by(&ts(&ts_body), TS_SPAWN_RM);
}

#[test]
fn the_most_severe_hit_decides_not_the_first_blocking_one() {
    // A policy warn downgrades a high hit but never a critical one. The old
    // joined reading returned the critical second segment here (it did not
    // read `sh`); the new `sh -c` reading finds the high first segment too. The
    // first BLOCKING hit named `git_reset_hard`, which an observe or pack-warn
    // config then allowed (the blocking-pass reviewer's row).
    let body = format!(
        r#"const child_process=require("child_process"); child_process.spawnSync("sh",["-c","{GIT} reset --hard; {RM} -rf /"])"#
    );
    assert_denied_by(&node(&body), JS_SPAWN_RM);
}

#[test]
fn a_spawn_sync_argv_is_also_read_as_the_joined_shell_line() {
    // Under `{ shell: true }` node joins the argv into one shell line, and a
    // cast, a comment, a `]` inside an element or an options variable can hide
    // that from any text check; a `bash -lc` / `sh -ec` script runs as a shell
    // line with no options at all. So the joined reading -- the only one this
    // rule had before -- always runs beside the words reading. Each row's
    // `child_process.` form DENIES on origin/main (the `cp.` receiver was not
    // read there at all); each was ALLOWED by a cut that skipped the joined reading.
    let js_clean = "heredoc.javascript:spawnsync.git_clean_fd";
    for (call, rule) in [
        (
            format!(r#"child_process.spawnSync("{GIT}",["clean -fd"],{{shell:true}})"#),
            js_clean,
        ),
        (
            format!(r#"cp.spawnSync("echo",["a;","{GIT}","clean","-fd"],{{shell:true}})"#),
            js_clean,
        ),
        (
            format!(r#"cp.spawnSync("{RM}",["-rf /srv"],o)"#),
            JS_SPAWN_RM,
        ),
        (
            format!(r#"cp.spawnSync("{GIT}",["clean -fd"] /* argv */, {{shell:true}})"#),
            js_clean,
        ),
        (
            format!(r#"cp.spawnSync("{GIT}",["clean -fd", "]"],{{shell:true}})"#),
            js_clean,
        ),
        (
            format!(r#"cp.spawnSync("bash",["-lc","cd /repo; {GIT} reset -q --hard"])"#),
            "heredoc.javascript:spawnsync.git_reset_hard",
        ),
    ] {
        let body = format!(
            r#"const child_process=require("child_process"); const cp=child_process; const o={{shell:true}}; {call}"#
        );
        assert_denied_by(&node(&body), rule);
    }
    let ts_body = format!(
        r#"import * as cp from "child_process"; cp.spawnSync("{GIT}", ["clean -fd"] as string[], {{ shell: true }});"#
    );
    assert_denied_by(&ts(&ts_body), "heredoc.typescript:spawnsync.git_clean_fd");
}
