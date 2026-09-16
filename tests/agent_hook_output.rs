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

/// Run the hook under an explicit `[overrides] block` and a warning
/// `default_mode` — the shape that let a wrapper downgrade an explicit block.
fn run_hook_mode_with_blocked_override(command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("override-policy.toml");
    std::fs::write(
        &config_path,
        "[policy]\n\
         default_mode = \"warn\"\n\
         \n\
         [policy.rules]\n\
         \"core.git:reset-hard\" = \"warn\"\n\
         \n\
         [overrides]\n\
         block = [{ pattern = \"^terraform destroy\", \
         reason = \"terraform destroy is forbidden here\" }]\n",
    )
    .expect("write override policy config");
    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem");
    run_hook(cmd, &sandbox, command)
}

/// Assert the hook denied `command` and that the denial names `reason`.
///
/// A config override carries no `pack_id` or `pattern_name`, so there is no
/// `ruleId` to assert on and the reason text is the only thing that proves
/// WHICH rule denied. `permissionDecisionReason` is read as a string before it
/// is searched, so a renamed or missing field fails instead of passing.
fn assert_denied_naming(
    command: &str,
    (stdout, stderr, exit_code): (String, String, i32),
    reason: &str,
) {
    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0 even on deny\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        !stdout.is_empty(),
        "an explicit config block must produce hook JSON, not a bare stderr \
         warning\ncommand: {command}\nstderr: {stderr}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "command: {command}\nstdout: {stdout}"
    );
    let denial_reason = hook_output["permissionDecisionReason"]
        .as_str()
        .expect("permissionDecisionReason must be present and a string");
    assert!(
        denial_reason.contains(reason),
        "the denial must name the config block that produced it\n\
         command: {command}\nwanted: {reason}\ngot: {denial_reason}"
    );
}

/// An `[overrides] block` is not a pack rule: it carries no pack id, pattern
/// name or severity, so `resolve_mode(None, None, None)` returns `[policy]
/// default_mode`. Tier 2.5 relabelled every inner denial
/// `MatchSource::HeredocAst`, which sent an explicit block down exactly that
/// path — and main.rs promises never to downgrade one. Under `default_mode =
/// "warn"`, `bash -c 'terraform destroy'` warned and ran while the unwrapped
/// command denied (.agent-config-dcg-tier25-relabels-config-denials-4mnqi).
#[test]
fn test_config_block_inside_a_shell_wrapper_is_not_downgraded_to_default_mode() {
    const REASON: &str = "terraform destroy is forbidden here";

    // Control: unwrapped, the block denies. Without this, a green subject
    // could equally mean the config never loaded.
    assert_denied_naming(
        "terraform destroy",
        run_hook_mode_with_blocked_override("terraform destroy"),
        REASON,
    );

    // Subject: the same block reached through the shell wrapper that Tier 2.5
    // evaluates recursively.
    let command = "bash -c 'terraform destroy'";
    assert_denied_naming(
        command,
        run_hook_mode_with_blocked_override(command),
        REASON,
    );
}

/// The opposite control, so the fix above cannot be "deny everything inside a
/// wrapper". The same config carries `"core.git:reset-hard" = "warn"`, and a
/// pack rule the policy warns on must still warn when it is wrapped exactly as
/// the subject above is. A pack match inside a wrapper stays policy resolved;
/// only the explicit block is exempt.
#[test]
fn test_pack_rule_inside_a_shell_wrapper_is_still_downgraded_by_the_policy() {
    let command = "bash -c 'git reset --hard'";
    let (stdout, stderr, exit_code) = run_hook_mode_with_blocked_override(command);

    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "a pack rule the policy sets to warn must warn, not deny\n\
         command: {command}\nstdout: {stdout}"
    );
    assert!(
        stderr.contains("reset"),
        "the warning names the rule it matched, which proves the wrapper was \
         evaluated at all\ncommand: {command}\nstderr: {stderr}"
    );
}

/// Run the hook under a policy that sets a heredoc / inline-script rule to
/// warn. `heredoc.python.shutil_rmtree` splits into pack `heredoc.python` and
/// pattern `shutil_rmtree` (`split_ast_rule_id`), which is the key the hook
/// resolves the mode from.
fn run_hook_mode_with_warned_heredoc_rule(command: &str) -> (String, String, i32) {
    run_hook_mode_with_heredoc_policy("\"heredoc.python:shutil_rmtree\" = \"warn\"\n", command)
}

/// Run the hook with `rules` as the whole `[policy.rules]` table.
fn run_hook_mode_with_heredoc_policy(rules: &str, command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("heredoc-policy.toml");
    std::fs::write(&config_path, format!("[policy.rules]\n{rules}")).expect("write policy config");
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

/// The reverse hole on the same line of `evaluate_heredoc`: a match whose
/// SEVERITY does not block was dropped before its mode was resolved, so a
/// `[policy.rules]` deny on a Medium heredoc rule never blocked anything.
/// `os.system` is Medium on purpose, and the control shows it passing without
/// the override, so the denial can only come from the policy
/// (.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7).
#[test]
fn test_policy_denied_medium_heredoc_rule_blocks() {
    let command = "python3 -c \"import os; os.system('ls')\"";
    assert_denied_by(
        command,
        run_hook_mode_with_heredoc_policy("\"heredoc.python:os_system\" = \"deny\"\n", command),
        "heredoc.python:os_system",
    );

    let (stdout, stderr, exit_code) = run_hook_mode_with_heredoc_policy("", command);
    assert_eq!(
        exit_code, 0,
        "an allowed command exits 0\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "os.system is Medium and is not denied without the override\n\
         command: {command}\nstdout: {stdout}"
    );
}

/// The same early return one tier up: `evaluate_heredoc` feeds each command of
/// a Bash heredoc or `bash -c` back through the evaluator (Tier 2.5) and
/// returned the first denial it got, whether or not the POLICY denies it. So a
/// warned rule wrapped in `bash -c` warned and the command after it ran, though
/// the same line unwrapped is denied
/// (.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7).
#[test]
fn test_policy_warned_rule_inside_bash_does_not_hide_the_next_command() {
    let command = "bash -c 'git reset --hard && git stash clear'";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_rules(command),
        "core.git:stash-clear",
    );

    let command = "bash <<'EOF'\n\
                   python3 -c \"import shutil; shutil.rmtree('/Users/someone/proj')\"\n\
                   git stash clear\n\
                   EOF";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_heredoc_rule(command),
        "core.git:stash-clear",
    );

    // No policy at all: stash-drop is Medium, so it warns by default, and it
    // used to hide the Critical stash-clear after it -- inside the script, and
    // outside it, where only the outer command's own scan can decide.
    for command in [
        "bash -c 'git stash drop; git stash clear'",
        "bash -c 'git stash drop' && git stash clear",
    ] {
        assert_denied_by(command, run_hook_mode(command), "core.git:stash-clear");
    }

    // A bash AST rule with no pack twin still decides behind a warned inner
    // command, beside it or nested in it: core.filesystem wants -r AND -f,
    // `heredoc.bash.rm_r` does not.
    for command in [
        "bash -c 'git stash drop; rm -r /srv/data'",
        "bash -c 'git stash drop $(rm -r /srv/data)'",
        "bash -c 'rm -r /srv/data $(git stash drop)'",
    ] {
        assert_denied_by(command, run_hook_mode(command), "heredoc.bash:rm_r");
    }

    // The bash AST twin of every other warned rule stays quiet too, however
    // the pack's match lines up with the command: clean-force matches `git
    // clean -f` inside `git clean -fd`, and core.filesystem reports its match
    // at the `-rf` flag, not the command's head.
    for (command, rule) in [
        ("bash -c 'git clean -fd'", "core.git:clean-force"),
        ("bash -c 'rm -rf ./build'", "core.filesystem:rm-rf-general"),
    ] {
        assert_warned_by(command, run_hook_mode_with_warned_rules(command), rule);
    }
    // And the `rm_r` arm: core.filesystem names `rm -r -f` rm-r-f-separate,
    // which `heredoc.bash.rm_r` restates on the same command.
    let command = "bash -c 'rm -r -f ./build'";
    assert_warned_by(
        command,
        run_hook_mode_with_heredoc_policy(
            "\"core.filesystem:rm-r-f-separate\" = \"warn\"\n",
            command,
        ),
        "core.filesystem:rm-r-f-separate",
    );

    // A warned twin quiets only its own command: the `rm -r` after the warned
    // `rm -rf` is a different command, and its bash rule still decides.
    let command = "bash -c 'rm -rf ./build; rm -r /srv/data'";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_rules(command),
        "heredoc.bash:rm_r",
    );

    // Control: the warned rule wrapped on its own still only warns, and names
    // itself, so the denials above are not the wrapper denying everything --
    // nor the bash AST rules, which restate `git reset --hard` under a rule
    // the policy does not name.
    let command = "bash -c 'git reset --hard'";
    let (stdout, stderr, exit_code) = run_hook_mode_with_warned_rules(command);
    assert_eq!(
        exit_code, 0,
        "a warned rule exits 0\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "a warned rule inside bash -c must not produce a hook denial\n\
         command: {command}\nstdout: {stdout}"
    );
    assert!(
        stderr.contains("core.git:reset-hard"),
        "the warning names the warned rule\ncommand: {command}\nstderr: {stderr}"
    );
}

/// Assert the hook let `command` run with a warning that names `rule`.
fn assert_warned_by(command: &str, (stdout, stderr, exit_code): (String, String, i32), rule: &str) {
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
        "the warning names the warned rule\ncommand: {command}\nstderr: {stderr}"
    );
}

/// Holding a warned match lets the evaluation reach the raw-command fallback,
/// which the old early return always skipped. The fallback runs when some
/// content could not be extracted -- here a Python `1 << 20` or a bash
/// `$((1 << 4))`, which the extractor reads as an unterminated heredoc -- and
/// it must not hard-deny, as "unjudged", the very text the policy warned on:
/// the content holding the warned match was judged, so it is masked from the
/// fallback like any other judged content
/// (.agent-config-dcg-fallback-scans-judged-content-zc6tb). Content that truly
/// went unjudged is still read, and what sits beside the warned match is still
/// judged by the outer pack scan
/// (.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7).
#[test]
fn test_fallback_spares_the_warned_match_and_still_reads_unjudged_content() {
    let command = "python3 <<'PY'\n\
                   import shutil\n\
                   shutil.rmtree('/Users/someone/proj/build')\n\
                   print(1 << 20)\n\
                   PY";
    assert_warned_by(
        command,
        run_hook_mode_with_warned_heredoc_rule(command),
        "shutil_rmtree",
    );
    let command = "python3 <<'PY'\r\nimport shutil\r\nshutil.rmtree('/Users/someone/proj/build')\r\nprint(1 << 20)\r\nPY";
    assert_warned_by(
        command,
        run_hook_mode_with_warned_heredoc_rule(command),
        "shutil_rmtree",
    );

    // The same body plain, tab-stripped by `<<-`, and with CRLF line ends. The
    // last two extract to text that differs from the raw bytes; the body's raw
    // range is masked all the same. The fallback's own `git reset --hard`
    // pattern would otherwise deny what the policy warned on.
    for command in [
        "bash <<'EOF'\ngit reset --hard origin/main\necho $((1 << 4))\nEOF",
        "bash <<-'EOF'\n\tgit reset --hard origin/main\n\techo $((1 << 4))\n\tEOF",
        "bash <<'EOF'\r\ngit reset --hard origin/main\r\necho $((1 << 4))\r\nEOF",
    ] {
        assert_warned_by(
            command,
            run_hook_mode_with_warned_rules(command),
            "core.git:reset-hard",
        );
    }

    // A real `rm -rf` handed to os.system -- Medium, so no AST rule stops
    // it -- is still denied behind the warned rmtree. The judged body is
    // masked from the fallback, so the outer pack scan is what reads it; the
    // old early return ended at the rmtree and warned.
    let command = "python3 <<'PY'\n\
                   import os, shutil\n\
                   shutil.rmtree('/Users/someone/proj/build')\n\
                   os.system('rm -rf /srv/data')\n\
                   print(1 << 20)\n\
                   PY";
    assert_denied_by(
        command,
        run_hook_mode_with_warned_heredoc_rule(command),
        "core.filesystem:rm-rf-root-home",
    );

    // Control: an 11th inline script is past max_heredocs (10) and never
    // judged, so the fallback still reads it -- behind the held warn, where
    // the early return never looked. No pack reads Python, so only the
    // fallback can deny it.
    let mut command =
        String::from("python3 -c \"import shutil; shutil.rmtree('/Users/someone/proj')\"");
    for _ in 0..9 {
        command.push_str("; python3 -c \"print(1)\"");
    }
    command.push_str("; python3 -c \"import os; os.remove('/etc/hosts')\"");
    let (stdout, stderr, exit_code) = run_hook_mode_with_warned_heredoc_rule(&command);
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 even on deny\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\"") && stdout.contains("fallback check"),
        "the unjudged os.remove must be denied by the fallback\n\
         command: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
}
