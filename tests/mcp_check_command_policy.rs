//! The MCP `check_command` tool answers with the mode the hook applies
//! (`.agent-config-dcg-mcp-ignores-policy-b1loi`).
//!
//! It used to answer from `EvaluationResult::effective_mode`, which the
//! evaluator stamps from SEVERITY and never from `[policy]`. So the MCP answer
//! and the hook disagreed exactly when the policy differs from severity: a
//! `[policy.rules]` deny on a Medium rule came back `allowed: true` while the
//! hook blocked it, and a warn on a High rule came back `allowed: false` while
//! the hook let it through. An allowlisted command, which the hook allows, came
//! back `allowed: false` too, because the allowlist result carries a `Deny`
//! `effective_mode`.
//!
//! Every test here drives the real `dcg mcp-server` over stdio, and each policy
//! assertion carries its no-policy control: the control is what proves the
//! answer came from the policy, since without it a test on a rule whose
//! severity already gives the asserted answer would pass for the wrong reason.

#![allow(clippy::doc_markdown)]

use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// `core.git:stash-drop` is Medium: severity alone warns.
const MEDIUM_COMMAND: &str = "git stash drop";
/// `core.git:checkout-discard` is High: severity alone denies.
const HIGH_COMMAND: &str = "git checkout -- file.txt";

const DENY_MEDIUM: &str = "[policy.rules]\n\"core.git:stash-drop\" = \"deny\"\n";
const WARN_HIGH: &str = "[policy.rules]\n\"core.git:checkout-discard\" = \"warn\"\n";
const NO_POLICY: &str = "";

/// How long one MCP exchange may take before the test gives up on the server.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Ask `dcg mcp-server` about each command under `config`, one `check_command`
/// call per command, and return the tool's JSON bodies in order.
///
/// `allowlist`, when given, is written as the sandbox user's allowlist.
fn mcp_check(config: &str, allowlist: Option<&str>, commands: &[&str]) -> Vec<Value> {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(&config_path, config).expect("write policy config");
    if let Some(allowlist) = allowlist {
        let dir = sandbox.dcg_config_dir();
        std::fs::create_dir_all(&dir).expect("create sandbox dcg config dir");
        std::fs::write(dir.join("allowlist.toml"), allowlist).expect("write allowlist");
    }

    let mut cmd = spawn::dcg_in(&sandbox);
    let mut child = cmd
        .arg("mcp-server")
        .env("DCG_CONFIG", &config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcg mcp-server");

    // Read on a thread so a server that never answers fails the test instead
    // of hanging it.
    let stdout = child.stdout.take().expect("mcp-server stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take().expect("mcp-server stdin");
    let mut send = |message: &Value| {
        writeln!(stdin, "{message}").expect("write to mcp-server");
        stdin.flush().expect("flush mcp-server stdin");
    };
    let response_to = |id: u64| -> Value {
        loop {
            let line = rx
                .recv_timeout(RESPONSE_TIMEOUT)
                .unwrap_or_else(|e| panic!("no MCP response to request {id}: {e}"));
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("mcp-server wrote non-JSON {line:?}: {e}"));
            // A reply carries our id and no method; a request the server
            // sends on its own carries a method.
            if message["id"] == id && message.get("method").is_none() {
                return message;
            }
        }
    };

    send(&json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp_check_command_policy", "version": "0"}
        }
    }));
    let init = response_to(0);
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    let mut bodies = Vec::with_capacity(commands.len());
    for (id, command) in (1_u64..).zip(commands) {
        send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": "check_command", "arguments": {"command": command}}
        }));
        let response = response_to(id);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("check_command returned no text: {response}"));
        bodies.push(serde_json::from_str(text).expect("check_command body is JSON"));
    }

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    bodies
}

/// Whether the hook denies `command` under `config`, run the way the other hook
/// tests run it, against the same sandbox layout `mcp_check` uses.
fn hook_denies(config: &str, allowlist: Option<&str>, command: &str) -> bool {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(&config_path, config).expect("write policy config");
    if let Some(allowlist) = allowlist {
        let dir = sandbox.dcg_config_dir();
        std::fs::create_dir_all(&dir).expect("create sandbox dcg config dir");
        std::fs::write(dir.join("allowlist.toml"), allowlist).expect("write allowlist");
    }

    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut cmd = spawn::dcg_in(&sandbox);
    let mut child = cmd
        .env("DCG_CONFIG", &config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .as_mut()
        .expect("hook stdin")
        .write_all(input.as_bytes())
        .expect("write hook payload");
    let output = child.wait_with_output().expect("wait for dcg hook");
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook exits 0 on allow and deny"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return false;
    }
    let json: Value = serde_json::from_str(&stdout).expect("hook output is JSON");
    json["hookSpecificOutput"]["permissionDecision"] == "deny"
}

fn assert_answer(body: &Value, allowed: bool, mode: &str, rule: &str, severity: &str) {
    assert_eq!(body["rule_id"], rule, "the answer names the rule: {body}");
    assert_eq!(body["severity"], severity, "rule severity: {body}");
    assert_eq!(body["allowed"], allowed, "allowed: {body}");
    assert_eq!(body["mode"], mode, "mode: {body}");
}

#[test]
fn a_policy_deny_on_a_medium_rule_answers_not_allowed() {
    let with_policy = mcp_check(DENY_MEDIUM, None, &[MEDIUM_COMMAND]);
    assert_answer(
        &with_policy[0],
        false,
        "deny",
        "core.git:stash-drop",
        "medium",
    );

    // Control: severity alone warns, so a pass above came from the policy.
    let without = mcp_check(NO_POLICY, None, &[MEDIUM_COMMAND]);
    assert_answer(&without[0], true, "warn", "core.git:stash-drop", "medium");
}

#[test]
fn a_policy_warn_on_a_high_rule_answers_allowed() {
    let with_policy = mcp_check(WARN_HIGH, None, &[HIGH_COMMAND]);
    assert_answer(
        &with_policy[0],
        true,
        "warn",
        "core.git:checkout-discard",
        "high",
    );

    // Control: severity alone denies, so a pass above came from the policy.
    let without = mcp_check(NO_POLICY, None, &[HIGH_COMMAND]);
    assert_answer(
        &without[0],
        false,
        "deny",
        "core.git:checkout-discard",
        "high",
    );
}

/// An allowlisted rule is allowed by the hook, and the answer must say so. Its
/// evaluation result is an Allow that still carries a `Deny` `effective_mode`,
/// which is what the MCP answer used to report.
#[test]
fn an_allowlisted_rule_answers_allowed() {
    let allowlist = "[[allow]]\nrule = \"core.git:stash-clear\"\nreason = \"test\"\n";
    let command = "git stash clear";
    assert!(
        !hook_denies(NO_POLICY, Some(allowlist), command),
        "precondition: the hook lets the allowlisted rule through"
    );
    let body = &mcp_check(NO_POLICY, Some(allowlist), &[command])[0];
    assert_eq!(body["decision"], "allow", "{body}");
    assert_eq!(
        body["allowlist"]["layer"], "user",
        "the answer names the allowlist: {body}"
    );
    assert_eq!(body["allowed"], true, "{body}");
    assert!(body["mode"].is_null(), "an allow applies no mode: {body}");

    // Control: without the allowlist the same Critical rule is denied.
    let without = &mcp_check(NO_POLICY, None, &[command])[0];
    assert_answer(without, false, "deny", "core.git:stash-clear", "critical");
}

/// The property the bead exists for: for the same config, the MCP answer is
/// the hook's answer, command by command.
#[test]
fn the_mcp_answer_is_the_hooks_answer() {
    let config = "[policy.rules]\n\
                  \"core.git:stash-drop\" = \"deny\"\n\
                  \"core.git:checkout-discard\" = \"warn\"\n";
    let commands = [
        MEDIUM_COMMAND,
        HIGH_COMMAND,
        "git stash clear",
        "git branch -D feature",
        "git status",
    ];
    let bodies = mcp_check(config, None, &commands);
    let mut denied = 0;
    for (command, body) in commands.iter().zip(&bodies) {
        let hook_denied = hook_denies(config, None, command);
        denied += usize::from(hook_denied);
        assert_eq!(
            body["allowed"], !hook_denied,
            "MCP and the hook disagree on {command:?}: hook denied={hook_denied}, MCP {body}"
        );
    }
    // Both answers must occur, or agreement could be a constant.
    assert_eq!(
        denied, 2,
        "stash-drop (policy) and stash-clear (Critical) deny"
    );
}
