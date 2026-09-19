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
//! The rest of `child_process` is read the same way (`.agent-config-crqi7`):
//! `execFileSync`, `execFile` and `spawn` take an argv as spawnSync does, `exec`
//! a shell string as execSync does -- gated to a `child_process` binding, since
//! RegExp and db objects share its name. A template literal is read by its raw
//! text, a `${..}` kept in it as an opaque word; one in which nothing
//! destructive is found stays a dynamic (medium) match that a deny policy
//! governs, as does an argv with a non-literal element or a concatenated
//! payload. A comment inside an argv array is skipped. Before, every argv row
//! ALLOWED, and exec was denied only where a `core.*` raw-text rule matched
//! (`core.filesystem`, `core.git`) -- `git reset -q --hard` was not.
//!
//! Still NOT read, recorded rather than claimed: `cp?.spawnSync`,
//! `cp["spawnSync"]`, `cp.spawnSync!(..)` and a type argument
//! (`spawnSync<T>(..)`, a TS2558 type error that `deno run` and `bun` do not
//! check, so it does run) are spellings outside the "well-intentioned but
//! fallible" agent dcg's README guards against; a cast literal
//! (`"rm" as string`) is missed because the refinement reads the call's text
//! with regexes, not its AST; any rebinding of the name (`{ spawnSync: s }`,
//! `import { spawn as s }`, `promisify(cp.execFile)`) -- the binding reader
//! `.agent-config-artmu` landed (which now gates exec too) records a renamed
//! destructure as unread; a dynamic `await import(..)`; an unterminated body,
//! which only the fallback regex sweep reads -- by call shape, with no payload
//! judged
//! (`.agent-config-artmu` gave it the bare `spawnSync(` / `execSync(` shapes);
//! a node heredoc nested in a bash heredoc body (`.agent-config-0awpo`); a
//! catastrophic `rm` target after the first, or under `/Users`
//! (`.agent-config-b8m7s`).
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
    hook_in(command, allowlist, None)
}

/// A hook run under a config file (`DCG_CONFIG`), e.g. a `[policy]` table.
fn hook_with_config(command: &str, config: &str) -> serde_json::Value {
    hook_in(command, None, Some(config))
}

fn hook_in(command: &str, allowlist: Option<&str>, config: Option<&str>) -> serde_json::Value {
    let sandbox = spawn::sandbox();
    if let Some(allowlist) = allowlist {
        let dir = sandbox.dcg_config_dir();
        std::fs::create_dir_all(&dir).expect("create dcg config dir");
        std::fs::write(dir.join("allowlist.toml"), allowlist).expect("write allowlist");
    }
    let mut cmd = spawn::dcg_in(&sandbox);
    if let Some(config) = config {
        let path = sandbox.root().join("config.toml");
        std::fs::write(&path, config).expect("write config");
        cmd.env("DCG_CONFIG", &path);
    }
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
fn a_shell_given_combined_or_interleaved_flags_is_read_as_a_script() {
    // `bash -lc`, `sh -ec`, `bash -o pipefail -c` were read as no script at all
    // (.agent-config-wx4ny). `git reset -q --hard` is a spelling core.git's
    // raw-text regex misses, so before this change nothing denied these rows.
    let quiet = format!("{GIT} reset -q --hard");
    for (call, argv, rule) in [
        (
            "spawnSync",
            format!(r#""bash",["-lc","{quiet}"]"#),
            "heredoc.javascript:spawnsync.git_reset_hard",
        ),
        (
            "execFileSync",
            format!(r#""bash",["-o","pipefail","-c","{quiet}"]"#),
            "heredoc.javascript:execfilesync.git_reset_hard",
        ),
        (
            "spawnSync",
            format!(r#""bash",["-c","-e","{quiet}"]"#),
            "heredoc.javascript:spawnsync.git_reset_hard",
        ),
        // The bead's own row.
        (
            "spawn",
            format!(r#""sh",["-ec","{GIT} reset --hard"]"#),
            "heredoc.javascript:spawn.git_reset_hard",
        ),
        // `+c` runs the operand as a script too.
        (
            "spawnSync",
            format!(r#""bash",["+c","{quiet}"]"#),
            "heredoc.javascript:spawnsync.git_reset_hard",
        ),
        // The other two shells the arm names read the same grammar.
        (
            "spawnSync",
            format!(r#""zsh",["-lc","{quiet}"]"#),
            "heredoc.javascript:spawnsync.git_reset_hard",
        ),
        (
            "execFileSync",
            format!(r#""dash",["+ec","{quiet}"]"#),
            "heredoc.javascript:execfilesync.git_reset_hard",
        ),
    ] {
        let body = format!(r#"const cp=require("child_process"); cp.{call}({argv})"#);
        assert_denied_by(&node(&body), rule);
    }
    // Controls: without a `c` flag the operand is a script FILE, and an operand
    // before `-c` ends the options -- neither is read as a script.
    for argv in [
        format!(r#""bash",["-l","{quiet}"]"#),
        format!(r#""bash",["deploy.sh","-c","{quiet}"]"#),
    ] {
        assert_allowed(&node(&format!(
            r#"const cp=require("child_process"); cp.spawnSync({argv})"#
        )));
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

// ---------------------------------------------------------------------------
// The rest of child_process (.agent-config-crqi7). execFileSync / execFile /
// spawn take an argv, as spawnSync does; exec takes a shell string, as
// execSync does. Before: every argv row ALLOWED, and exec was denied only where
// a core.* raw-text rule matched (core.filesystem, core.git).
// ---------------------------------------------------------------------------

/// Each argv call and the rule-id segment it is read under.
const ARGV_CALLS: [(&str, &str); 3] = [
    ("execFileSync", "execfilesync"),
    ("execFile", "execfile"),
    ("spawn", "spawn"),
];

#[test]
fn every_argv_call_with_a_destructive_argv_denies() {
    for (call, id) in ARGV_CALLS {
        let rule = format!("heredoc.javascript:{id}.rm_rf_catastrophic");
        let aliased =
            format!(r#"const cp=require("child_process"); cp.{call}("{RM}",["-rf","/srv"])"#);
        assert_denied_by(&node(&aliased), &rule);
        let destructured = format!(
            r#"const {{ {call} }} = require("child_process"); {call}("{RM}", ["-rf", "/srv"])"#
        );
        assert_denied_by(&node(&destructured), &rule);
    }
}

#[test]
fn an_argv_call_judges_git_as_words() {
    assert_denied_by(
        &node(&format!(
            r#"const cp=require("child_process"); cp.spawn("{GIT}",["reset","--hard"])"#
        )),
        "heredoc.javascript:spawn.git_reset_hard",
    );
    assert_denied_by(
        &node(&format!(
            r#"const cp=require("child_process"); cp.execFileSync("{GIT}",["clean","-fd"])"#
        )),
        "heredoc.javascript:execfilesync.git_clean_fd",
    );
}

#[test]
fn exec_is_denied_by_the_rule_that_read_it() {
    for body in [
        format!(r#"const cp=require("child_process"); cp.exec("{RM} -rf /srv")"#),
        format!(r#"const {{ exec }} = require("child_process"); exec("{RM} -rf /srv")"#),
        format!(
            r#"const child_process=require("child_process"); child_process.exec("{RM} -rf /srv")"#
        ),
        // The gate resolves an inline require to its module (.agent-config-rmxds).
        format!(r#"require("child_process").exec("{RM} -rf /srv", () => {{}})"#),
    ] {
        assert_denied_by(&node(&body), "heredoc.javascript:exec.rm_rf_catastrophic");
    }
}

#[test]
fn typescript_reads_the_rest_of_child_process() {
    let argv = format!(r#"("{RM}", ["-rf", "/srv"])"#);
    let string = format!(r#"("{RM} -rf /srv")"#);
    for (call, id, args) in [
        ("execFileSync", "execfilesync", &argv),
        ("execFile", "execfile", &argv),
        ("spawn", "spawn", &argv),
        ("exec", "exec", &string),
    ] {
        let rule = format!("heredoc.typescript:{id}.rm_rf_catastrophic");
        let aliased = format!(r#"import * as cp from "child_process"; cp.{call}{args};"#);
        assert_denied_by(&ts(&aliased), &rule);
        let destructured =
            format!(r#"import {{ {call} }} from "node:child_process"; {call}{args};"#);
        assert_denied_by(&ts(&destructured), &rule);
    }
}

#[test]
fn a_template_is_read_by_its_raw_text() {
    let argv =
        format!(r#"const cp=require("child_process"); cp.spawnSync(`{RM}`, [`-rf`, `/srv`])"#);
    assert_denied_by(&node(&argv), JS_SPAWN_RM);
    let string = format!(r#"const cp=require("child_process"); cp.exec(`{RM} -rf /srv`)"#);
    assert_denied_by(&node(&string), "heredoc.javascript:exec.rm_rf_catastrophic");
    // A template may span lines; before, this one was left to core.filesystem.
    let multi_line = format!("const cp=require(\"child_process\"); cp.exec(`\n{RM} -rf /srv\n`)");
    assert_denied_by(
        &node(&multi_line),
        "heredoc.javascript:exec.rm_rf_catastrophic",
    );
    // A substitution stays in the text as an opaque word, so a static command
    // name or system-path prefix is judged as a literal path to rm
    // (`"/usr/bin/rm"`) and the concatenation `"/var/lib/" + app` already are.
    // (A concatenated COMMAND, `p + "/rm"`, is not read: no literal follows `(`.)
    let command_by_path = format!(
        r#"const cp=require("child_process"); const p=process.argv[2]; cp.spawn(`${{p}}/{RM}`, ["-rf", "/srv"])"#
    );
    assert_denied_by(
        &node(&command_by_path),
        "heredoc.javascript:spawn.rm_rf_catastrophic",
    );
    let under_a_system_dir = format!(
        r#"const cp=require("child_process"); const app=process.argv[2]; cp.spawnSync("{RM}", ["-rf", `/var/lib/${{app}}`])"#
    );
    assert_denied_by(&node(&under_a_system_dir), JS_SPAWN_RM);
    // Controls: an unknown target, or one under /tmp, is not catastrophic.
    for target in ["`${d}`", "`/tmp/${d}`"] {
        assert_allowed(&node(&format!(
            r#"const cp=require("child_process"); const d=process.argv[2]; cp.spawnSync("{RM}", ["-rf", {target}])"#
        )));
    }
}

#[test]
fn a_comment_inside_an_argv_is_not_read_as_an_element() {
    // Found by the crqi7 cold review: a quoted word in a comment was read as an
    // argv element, moving the target in both directions. The double-quoted
    // row allowed before crqi7 too.
    for comment in [
        "// wipe the `data` dir",
        r#"// wipe the "data" dir"#,
        "/* wipe the `data` dir */",
        // A `]` in a comment does not end the array either.
        "// see [1]",
        "/* [prod] */",
    ] {
        let command = node(&format!(
            "const cp=require(\"child_process\"); cp.spawnSync(\"{RM}\", [\n  \"-rf\", {comment}\n  \"/srv/data\",\n])"
        ));
        assert_denied_by(&command, JS_SPAWN_RM);
    }
    assert_allowed(&node(&format!(
        "const cp=require(\"child_process\"); cp.spawnSync(\"{RM}\", [\n  \"-rf\", // never `/` here\n  \"./build\",\n])"
    )));
    assert_allowed(&node(&format!(
        "const cp=require(\"child_process\"); cp.spawnSync(\"{GIT}\", [\n  \"reset\", // not `--hard` here\n  \"--soft\",\n])"
    )));
}

#[test]
fn the_rest_of_child_process_allows_benign_and_dynamic_calls() {
    assert_allowed(&node(
        r#"const cp=require("child_process"); cp.spawn("ls",["-la","/srv"]); cp.execFileSync("git",["status"]); cp.execFile("ls",[]); cp.exec("echo hi")"#,
    ));
    assert_allowed(&node(
        r#"const cp=require("child_process"); const c=process.argv[2]; cp.exec(c); cp.spawn(c, []); cp.execFileSync(c, []); cp.execFile(c, [])"#,
    ));
    assert_allowed(&node(&format!(
        r#"const cp=require("child_process"); cp.spawn("{RM}",["-rf","./build"])"#
    )));
}

// ---------------------------------------------------------------------------
// Deny policies (crqi7 review round 2). A call these rules cannot judge stays a
// medium match, which a `[policy.rules]` deny or a deny default governs, so a
// dynamic call must not be dropped -- and exec, whose name RegExp and db objects
// share, must not match what is not child_process.
// ---------------------------------------------------------------------------

#[test]
fn a_dynamic_call_stays_a_match_a_deny_policy_governs() {
    let policy = "[policy.rules]\n\
                  \"heredoc.javascript:execsync\" = \"deny\"\n\
                  \"heredoc.javascript:spawnsync\" = \"deny\"\n\
                  \"heredoc.javascript:spawn\" = \"deny\"\n\
                  \"heredoc.javascript:exec\" = \"deny\"\n\
                  \"heredoc.typescript:execsync\" = \"deny\"\n\
                  \"heredoc.typescript:spawnsync\" = \"deny\"\n";
    for (command, rule) in [
        // A template with a substitution: nothing destructive is found in it,
        // and that is not a verdict.
        (
            node(
                r#"const cp=require("child_process"); const s=process.argv[2]; cp.execSync(`npm run ${s}`, {stdio:"inherit"})"#,
            ),
            "heredoc.javascript:execsync",
        ),
        (
            node(
                r#"const cp=require("child_process"); const t=process.argv[2]; cp.spawnSync(`${t}`, ["x"])"#,
            ),
            "heredoc.javascript:spawnsync",
        ),
        (
            node(r#"const cp=require("child_process"); const c=process.argv[2]; cp.exec(`${c}`)"#),
            "heredoc.javascript:exec",
        ),
        (
            ts(
                r#"import { execSync } from "node:child_process"; const pm = Deno.args[0]; execSync(`${pm} install`);"#,
            ),
            "heredoc.typescript:execsync",
        ),
        // A nested call's literal does not stand in for the call's own argument.
        (
            node(
                r#"const cp=require("child_process"); const c=process.argv[2]; cp.execSync(c + (/x/.exec("y") ? "" : ""))"#,
            ),
            "heredoc.javascript:execsync",
        ),
        // Partly literal: a variable argv element, or a variable concatenated onto
        // the literal. The literal part alone is not the call.
        (
            node(&format!(
                r#"const cp=require("child_process"); const s=process.argv[2]; cp.spawn("{RM}", ["-rf", s])"#
            )),
            "heredoc.javascript:spawn",
        ),
        (
            node(
                r#"const cp=require("child_process"); const s=process.argv[2]; cp.exec("npm run " + s)"#,
            ),
            "heredoc.javascript:exec",
        ),
        // Anything applied to the array after its `]` (crqi7 review round 4).
        (
            node(&format!(
                r#"const cp=require("child_process"); const dirs=process.argv.slice(2); cp.spawn("{RM}", ["-rf"].concat(dirs))"#
            )),
            "heredoc.javascript:spawn",
        ),
        // The TypeScript copies of the same checks.
        (
            ts(&format!(
                r#"import {{ spawnSync }} from "node:child_process"; const d = Deno.args; spawnSync("{RM}", ["-rf"].concat(d));"#
            )),
            "heredoc.typescript:spawnsync",
        ),
        (
            ts(
                r#"import { spawnSync } from "node:child_process"; const t = Deno.args[0]; spawnSync("npm", ["run", t]);"#,
            ),
            "heredoc.typescript:spawnsync",
        ),
        (
            ts(
                r#"import { execSync } from "node:child_process"; const pm = Deno.args[0]; execSync("npm run " + pm);"#,
            ),
            "heredoc.typescript:execsync",
        ),
    ] {
        assert_verdict_denied_by(&hook_with_config(&command, policy), &command, rule);
        // Control: without the policy the same medium match only warns.
        assert_allowed(&command);
    }
}

#[test]
fn a_deny_default_does_not_reach_a_regexp_exec() {
    let deny_default = "[policy]\ndefault_mode = \"deny\"\n";
    for body in [
        r"const re=/(\w+)=(\w+)/g; let m; while ((m = re.exec(process.argv[2])) !== null) { console.log(m[1]); }",
        r"const db=open(); db.exec(process.argv[2])",
        r"exec(process.argv[2])",
    ] {
        let command = node(body);
        let out = hook_with_config(&command, deny_default);
        assert!(
            out.is_null(),
            "a non-child_process exec must not match\ncommand: {command:?}\noutput: {out}"
        );
    }
    // Control: a child_process exec is still the rule's, so the deny default
    // denies it by that id.
    let command = node(r#"const cp=require("child_process"); const c=process.argv[2]; cp.exec(c)"#);
    assert_verdict_denied_by(
        &hook_with_config(&command, deny_default),
        &command,
        "heredoc.javascript:exec",
    );
}

#[test]
fn a_call_taken_as_a_member_of_require_is_read() {
    // `git reset -q --hard` is one core.git's raw-text regex does not catch, so a
    // deny here is the exec rule's or nothing (crqi7 review round 3).
    let payload = format!("{GIT} reset -q --hard");
    let member = node(&format!(
        r#"var exec = require("child_process").exec; exec("{payload}", function (err) {{}})"#
    ));
    assert_denied_by(&member, "heredoc.javascript:exec.git_reset_hard");
    // The binding is artmu's collector's, so the fs rules read it too.
    let fs_member =
        node(r#"const rmSync = require("fs").rmSync; rmSync("/etc", {recursive: true})"#);
    assert_denied_by(&fs_member, "heredoc.javascript:fs_rmsync.catastrophic");
    // Control: the same payload through a name bound to nothing is not read by
    // any rule -- the gap the binding above closes.
    assert_allowed(&node(&format!(
        r#"var run = pick(); run.exec("{payload}")"#
    )));
}
