//! Tests for `HookSpecificOutput` JSON structure and required fields.
//!
//! These tests verify that the hook output contains all fields required
//! for AI agent integration as specified in `git_safety_guard-e4fl.1`.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Run dcg in hook mode with the given command as JSON input.
fn run_hook_mode(command: &str) -> (String, String, i32) {
    // Cleared, as in `cli_e2e.rs`. Without this these tests read the
    // developer's real `~/.config/dcg/config.toml`, so a local policy
    // downgrade (`"core.git:reset-hard" = "warn"`) makes dcg emit a stderr
    // warning and no JSON — and eleven tests here fail for a reason that has
    // nothing to do with dcg.
    let (cmd, sandbox) = spawn::dcg();
    run_hook(cmd, &sandbox, command)
}

/// Send `command` as a PreToolUse payload to an already-configured dcg.
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

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

#[test]
fn test_hook_output_contains_hook_event_name() {
    let (stdout, stderr, exit_code) = run_hook_mode("git reset --hard");

    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0 even on deny\nstderr: {stderr}"
    );
    assert!(!stdout.is_empty(), "stdout should contain JSON output");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert!(
        hook_output.get("hookEventName").is_some(),
        "hookEventName field required in output"
    );
    assert_eq!(
        hook_output["hookEventName"], "PreToolUse",
        "hookEventName should be 'PreToolUse'"
    );
}

#[test]
fn test_hook_output_contains_permission_decision() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert!(
        hook_output.get("permissionDecision").is_some(),
        "permissionDecision field required in output"
    );

    let decision = hook_output["permissionDecision"].as_str().unwrap();
    assert!(
        decision == "allow" || decision == "deny",
        "permissionDecision should be 'allow' or 'deny', got: {decision}"
    );
}

#[test]
fn test_hook_output_deny_has_rule_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    // For denied commands, ruleId should be present
    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("ruleId").is_some(),
            "ruleId field should be present for denied commands"
        );

        let rule_id = hook_output["ruleId"].as_str().unwrap();
        assert!(
            rule_id.contains(':'),
            "ruleId should have format 'packId:patternName', got: {rule_id}"
        );
    }
}

#[test]
fn test_hook_output_deny_has_pack_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("packId").is_some(),
            "packId field should be present for denied commands"
        );

        let pack_id = hook_output["packId"].as_str().unwrap();
        assert!(!pack_id.is_empty(), "packId should not be empty");
    }
}

#[test]
fn test_hook_output_deny_has_severity() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("severity").is_some(),
            "severity field should be present for denied commands"
        );

        let severity = hook_output["severity"].as_str().unwrap();
        let valid_severities = ["critical", "high", "medium", "low"];
        assert!(
            valid_severities.contains(&severity),
            "severity should be one of {:?}, got: {severity}",
            valid_severities
        );
    }
}

#[test]
fn test_hook_output_deny_has_remediation() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("remediation").is_some(),
            "remediation field should be present for denied commands"
        );

        let remediation = &hook_output["remediation"];

        // Verify remediation structure
        assert!(
            remediation.get("explanation").is_some(),
            "remediation.explanation should be present"
        );
        assert!(
            remediation.get("allowOnceCommand").is_some(),
            "remediation.allowOnceCommand should be present"
        );
    }
}

#[test]
fn test_hook_output_deny_has_allow_once_code() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("allowOnceCode").is_some(),
            "allowOnceCode should be present for denied commands"
        );

        let code = hook_output["allowOnceCode"].as_str().unwrap();
        assert!(!code.is_empty(), "allowOnceCode should not be empty");

        // Also verify the remediation includes the allow-once command
        if let Some(remediation) = hook_output.get("remediation") {
            let allow_cmd = remediation["allowOnceCommand"].as_str().unwrap();
            assert!(
                allow_cmd.contains("dcg allow-once"),
                "allowOnceCommand should contain 'dcg allow-once'"
            );
            assert!(
                allow_cmd.contains(code),
                "allowOnceCommand should contain the allowOnceCode"
            );
        }
    }
}

#[test]
fn test_hook_output_permission_decision_reason() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert!(
        hook_output.get("permissionDecisionReason").is_some(),
        "permissionDecisionReason should be present"
    );

    let reason = hook_output["permissionDecisionReason"].as_str().unwrap();
    assert!(
        !reason.is_empty(),
        "permissionDecisionReason should not be empty"
    );

    // For denied commands, reason should be descriptive
    if hook_output["permissionDecision"] == "deny" {
        assert!(
            reason.contains("BLOCKED") || reason.contains("Reason:"),
            "permissionDecisionReason for deny should explain the block"
        );
    }
}

#[test]
fn test_hook_output_stderr_includes_allowlist_add_hint() {
    let (stdout, stderr, exit_code) = run_hook_mode("git reset --hard");

    assert_eq!(exit_code, 0, "hook mode should exit 0");
    assert!(!stdout.trim().is_empty(), "deny should emit JSON on stdout");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "git reset --hard should be denied"
    );

    assert!(
        stderr.contains("dcg allowlist add core.git:reset-hard --project"),
        "stderr should include allowlist add hint for matched rule.\nstderr:\n{stderr}"
    );
}

#[test]
fn test_hook_output_safe_command_returns_no_output() {
    let (stdout, _stderr, exit_code) = run_hook_mode("git status");

    assert_eq!(exit_code, 0, "safe command should exit 0");
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "safe command should produce no stdout output, got: {stdout}"
    );
}

#[test]
fn test_hook_output_git_clean_dry_run_allowed() {
    // git clean -n (dry run) should be allowed
    let (stdout, _stderr, exit_code) = run_hook_mode("git clean -n");

    assert_eq!(exit_code, 0, "git clean -n should exit 0");
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "git clean -n (dry run) should be allowed with no output, got: {stdout}"
    );
}

#[test]
fn test_hook_output_multiple_destructive_commands() {
    // Test various destructive commands to ensure consistent output format
    let commands = [
        "git reset --hard HEAD~5",
        "git clean -fd",
        "git push --force origin main",
        "rm -rf /important/data",
    ];

    for cmd in commands {
        let (stdout, stderr, exit_code) = run_hook_mode(cmd);

        assert_eq!(
            exit_code, 0,
            "hook mode should exit 0 for cmd: {cmd}\nstderr: {stderr}"
        );

        if !stdout.is_empty() {
            let json: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("invalid JSON for cmd '{cmd}': {e}\nstdout: {stdout}"));

            let hook_output = &json["hookSpecificOutput"];

            // All denied commands should have these fields
            if hook_output["permissionDecision"] == "deny" {
                assert!(
                    hook_output.get("ruleId").is_some() || hook_output.get("packId").is_some(),
                    "denied command should have ruleId or packId: {cmd}"
                );
                assert!(
                    hook_output.get("severity").is_some(),
                    "denied command should have severity: {cmd}"
                );
            }
        }
    }
}

#[test]
fn test_hook_output_rule_id_format() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if let Some(rule_id) = hook_output.get("ruleId") {
        let rule_id_str = rule_id.as_str().unwrap();

        // Rule ID format: "{packId}:{patternName}"
        let parts: Vec<&str> = rule_id_str.split(':').collect();
        assert_eq!(
            parts.len(),
            2,
            "ruleId should have format 'packId:patternName', got: {rule_id_str}"
        );

        // The pack_id in ruleId should match packId field
        if let Some(pack_id) = hook_output.get("packId") {
            assert_eq!(
                parts[0],
                pack_id.as_str().unwrap(),
                "ruleId pack portion should match packId"
            );
        }
    }
}

#[test]
fn test_hook_output_remediation_safe_alternative() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if let Some(remediation) = hook_output.get("remediation") {
        // safeAlternative is optional but when present should be helpful
        if let Some(safe_alt) = remediation.get("safeAlternative") {
            let alt_str = safe_alt.as_str().unwrap();
            assert!(
                !alt_str.is_empty(),
                "safeAlternative when present should not be empty"
            );
        }
    }
}

/// The first destructive match used to decide the whole command, so a
/// warn-only rule in front of a blocking one downgraded it: `git stash clear`
/// alone was denied, but `git stash drop && git stash clear` was allowed with a
/// warning, because core.git lists stash-drop (Medium) before stash-clear
/// (Critical). The evaluator now holds a warn/log match and keeps scanning, so
/// the rule that blocks is the rule that decides (.agent-config-3ktl8).
#[test]
fn test_warn_rule_in_front_does_not_downgrade_a_blocking_rule() {
    let (stdout, stderr, exit_code) = run_hook_mode("git stash drop && git stash clear");

    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0 even on deny\nstderr: {stderr}"
    );
    assert!(
        !stdout.is_empty(),
        "a blocking rule anywhere in the command must produce hook JSON, \
         not a bare stderr warning\nstderr: {stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];

    assert!(
        hook_output.get("permissionDecision").is_some(),
        "permissionDecision field required in output\nstdout: {stdout}"
    );
    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "the Critical stash-clear must decide, not the Medium stash-drop in \
         front of it\nstdout: {stdout}"
    );
    assert!(
        hook_output.get("ruleId").is_some(),
        "ruleId field required in output\nstdout: {stdout}"
    );
    assert_eq!(
        hook_output["ruleId"], "core.git:stash-clear",
        "the denial must name the rule that blocks\nstdout: {stdout}"
    );
}

/// Control for the test above: the same blocking rule on its own. If this ever
/// stops denying, the test above is passing for the wrong reason.
#[test]
fn test_blocking_stash_rule_alone_still_denies() {
    let (stdout, stderr, _exit_code) = run_hook_mode("git stash clear");

    assert!(
        !stdout.is_empty(),
        "git stash clear must produce hook JSON\nstderr: {stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
    assert_eq!(hook_output["ruleId"], "core.git:stash-clear");
}

/// Second control: the warn-only rule on its own must still be allowed. Denying
/// every Medium match would make the test above pass while breaking the policy
/// layer it is supposed to leave alone.
#[test]
fn test_warn_only_stash_rule_alone_is_still_allowed() {
    let (stdout, stderr, exit_code) = run_hook_mode("git stash drop stash@{0}");

    assert_eq!(
        exit_code, 0,
        "a warn-only match exits 0\nstderr: {stderr}\nstdout: {stdout}"
    );

    if stdout.is_empty() {
        assert!(
            stderr.contains("stash"),
            "a warn-only match warns on stderr about the rule it matched\n\
             stderr: {stderr}"
        );
    } else {
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("hook output should be valid JSON");
        assert_ne!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "git stash drop is Medium and must not be denied\nstdout: {stdout}"
        );
    }
}

/// Run the hook under a policy that sets High and Critical rules to warn, as
/// the live config does for `core.git:reset-hard` and `core.git:clean-force`.
fn run_hook_mode_with_warned_rules(command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(
        &config_path,
        "[policy.rules]\n\
         \"core.git:reset-hard\" = \"warn\"\n\
         \"core.git:clean-force\" = \"warn\"\n\
         \"core.filesystem:rm-rf-general\" = \"warn\"\n",
    )
    .expect("write policy config");
    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem,remote.rsync");
    run_hook(cmd, &sandbox, command)
}

/// Assert the hook denied `command` and named `rule`.
fn assert_denied_by(command: &str, (stdout, stderr, exit_code): (String, String, i32), rule: &str) {
    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0 even on deny\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        !stdout.is_empty(),
        "a rule the policy blocks must produce hook JSON, not a bare stderr \
         warning\ncommand: {command}\nstderr: {stderr}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "command: {command}\nstdout: {stdout}"
    );
    assert_eq!(
        hook_output["ruleId"], rule,
        "the denial must name the rule the policy blocks\ncommand: {command}\nstdout: {stdout}"
    );
}

/// 3ktl8's hold asked the SEVERITY whether a rule blocks, and the hook asks the
/// POLICY. A High rule the policy sets to warn was therefore returned at once,
/// the hook warned and allowed, and a later rule the policy blocks was never
/// reported: `git reset --hard && git stash clear` ran (.agent-config-5nyrn).
#[test]
fn test_policy_warned_high_rule_in_front_does_not_hide_a_blocking_rule() {
    let command = "git reset --hard && git stash clear";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_rules(command),
        "core.git:stash-clear",
    );
}

/// The same across packs: the warned core.git rule is in an earlier pack than
/// the rsync rule it hid.
#[test]
fn test_policy_warned_rule_does_not_hide_a_blocking_rule_in_a_later_pack() {
    let command = "git clean -fd && rsync -a --delete /src/ /dst/";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_rules(command),
        "remote.rsync:rsync-delete",
    );
}

/// core.filesystem decides through its rm parser, which returned its denial
/// without asking whether the policy blocks it.
#[test]
fn test_policy_warned_rm_rule_does_not_hide_a_blocking_rule_in_a_later_pack() {
    let command = "rm -rf ./build && rsync -a --delete /src/ /dst/";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_rules(command),
        "remote.rsync:rsync-delete",
    );
}

/// Controls for the three tests above. Each warned rule on its own still only
/// warns, so the policy loaded and the denials above are not the policy being
/// ignored; and each blocking rule on its own is denied, so they are not a
/// rule that stopped matching.
#[test]
fn test_policy_warned_rules_alone_still_only_warn() {
    for (command, rule) in [
        ("git reset --hard", "core.git:reset-hard"),
        ("git clean -fd", "core.git:clean-force"),
        ("rm -rf ./build", "core.filesystem:rm-rf-general"),
    ] {
        let (stdout, stderr, exit_code) = run_hook_mode_with_warned_rules(command);
        assert_eq!(
            exit_code, 0,
            "a warned rule exits 0\ncommand: {command}\nstderr: {stderr}"
        );
        assert!(
            stdout.is_empty(),
            "a rule the policy warns on must not produce a hook denial\n\
             command: {command}\nstdout: {stdout}"
        );
        assert!(
            stderr.contains(rule),
            "the warning names the warned rule, which proves the policy loaded\n\
             command: {command}\nstderr: {stderr}"
        );
    }
    for (command, rule) in [
        ("git stash clear", "core.git:stash-clear"),
        ("rsync -a --delete /src/ /dst/", "remote.rsync:rsync-delete"),
    ] {
        assert_denied_by(command, run_hook_mode_with_warned_rules(command), rule);
    }
}

/// Run the hook under a policy that sets a heredoc / inline-script rule to
/// warn. `heredoc.python.shutil_rmtree` splits into pack `heredoc.python` and
/// pattern `shutil_rmtree` (`split_ast_rule_id`), which is the key the hook
/// resolves the mode from.
fn run_hook_mode_with_warned_heredoc_rule(command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("heredoc-policy.toml");
    std::fs::write(
        &config_path,
        "[policy.rules]\n\
         \"heredoc.python:shutil_rmtree\" = \"warn\"\n",
    )
    .expect("write policy config");
    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem");
    run_hook(cmd, &sandbox, command)
}

/// `evaluate_heredoc` kept a match only when its SEVERITY blocked and returned
/// the first one it kept, before the outer command's pack scan ever ran. The
/// hook then resolved that rule's mode from `[policy.rules]`, so a
/// policy-warned heredoc rule warned and the outer command -- a real
/// `git stash clear` -- was never evaluated
/// (.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7).
#[test]
fn test_policy_warned_heredoc_rule_does_not_hide_the_outer_command() {
    let command =
        "python3 -c \"import shutil; shutil.rmtree('/Users/someone/proj')\" && git stash clear";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_heredoc_rule(command),
        "core.git:stash-clear",
    );
}

/// Controls for the test above. The warned heredoc rule on its own still only
/// warns AND names itself on stderr, which proves the policy key resolved --
/// a wrong key would deny here instead. The blocking rule on its own is still
/// denied, so the denial above is not a rule that merely started matching.
#[test]
fn test_warned_heredoc_rule_alone_warns_and_the_blocking_rule_alone_denies() {
    let warned = "python3 -c \"import shutil; shutil.rmtree('/Users/someone/proj')\"";
    let (stdout, stderr, exit_code) = run_hook_mode_with_warned_heredoc_rule(warned);
    assert_eq!(
        exit_code, 0,
        "a warned rule exits 0\ncommand: {warned}\nstderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "a heredoc rule the policy warns on must not produce a hook denial\n\
         command: {warned}\nstdout: {stdout}"
    );
    assert!(
        stderr.contains("shutil_rmtree"),
        "the warning names the warned heredoc rule, which proves the policy \
         key resolved\ncommand: {warned}\nstderr: {stderr}"
    );

    let blocking = "git stash clear";
    assert_denied_by(
        blocking,
        run_hook_mode_with_warned_heredoc_rule(blocking),
        "core.git:stash-clear",
    );
}
