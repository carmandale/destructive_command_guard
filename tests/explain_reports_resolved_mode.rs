//! The explain trace answers with the mode the hook applies, not the raw match
//! (`.agent-config-33e9r`).
//!
//! `dcg explain`, `dcg test --explain` and `dcg test -vvv` share one handler,
//! and it used to hand the evaluator's raw `EvaluationDecision` straight to the
//! trace. So under `[policy.rules] "core.git:checkout-discard" = "warn"` the
//! trace printed `Decision: DENY` for a command the hook waves through, and
//! `dcg test --explain "rm -rf /"` exited 0 although README documents `dcg test`
//! as 0 allowed / 1 blocked.
//!
//! Every policy assertion here carries its no-policy control. Without one, a
//! case on a rule whose SEVERITY already gives the asserted answer passes for
//! the wrong reason -- which is exactly how the defect survived: severity and
//! policy agree under the default config, and every existing explain test runs
//! under the default config.
//!
//! Each test drives the real binary through `common/spawn.rs`, so what is
//! measured is the shipped surface and not a re-implementation of it.

use std::process::Output;

use serde_json::Value;

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

/// Run dcg under `config` with `args`, isolated from the developer's machine.
fn run(config: &str, args: &[&str]) -> Output {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(&config_path, config).expect("write policy config");

    spawn::dcg_in(&sandbox)
        .args(args)
        .env("DCG_CONFIG", &config_path)
        .env("NO_COLOR", "1")
        .output()
        .expect("run dcg")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The `mode` field of an explain trace for `command` under `config`.
///
/// `Value::Null` when the key is absent, which is a distinct answer from any
/// mode and is asserted as such below.
fn explain_json(config: &str, command: &str) -> Value {
    let output = run(config, &["explain", "--format", "json", command]);
    assert!(
        output.status.success(),
        "dcg explain exits 0 on every verdict; got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout_of(&output)).expect("explain --format json emits JSON")
}

/// Whether the hook blocks `command` under `config`, asked of the hook itself
/// so the comparison below is against behaviour and not against a second
/// reading of the same code.
///
/// The hook — and only the hook — runs under a 200ms wall-clock evaluation
/// budget (`perf::HOOK_EVALUATION_BUDGET_MS`); past it it fails closed under
/// `core.limits:evaluation-timeout` rather than under the rule that matched.
/// `dcg explain` has no budget, so on a loaded machine a comparison between
/// them would report a surface disagreement that is really a stopwatch. The
/// budget is raised here so this test measures the verdict.
fn hook_denies(config: &str, command: &str) -> bool {
    use std::io::Write;
    use std::process::Stdio;

    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(&config_path, config).expect("write policy config");

    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = spawn::dcg_in(&sandbox)
        .env("DCG_CONFIG", &config_path)
        .env("DCG_HOOK_TIMEOUT_MS", "600000")
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

// ===========================================================================
// JSON trace
// ===========================================================================

#[test]
fn a_policy_warn_on_a_high_rule_reports_mode_warn() {
    let body = explain_json(WARN_HIGH, HIGH_COMMAND);
    assert_eq!(body["match"]["rule_id"], "core.git:checkout-discard");
    assert_eq!(body["match"]["severity"], "high");
    assert_eq!(body["decision"], "deny", "the raw match is still reported");
    assert_eq!(body["mode"], "warn", "the hook only warns: {body}");

    // Control: severity alone denies this rule, so the answer above came from
    // the policy and not from the rule's own severity.
    let without = explain_json(NO_POLICY, HIGH_COMMAND);
    assert_eq!(without["decision"], "deny");
    assert_eq!(without["mode"], "deny", "{without}");
}

#[test]
fn a_policy_deny_on_a_medium_rule_reports_mode_deny() {
    let body = explain_json(DENY_MEDIUM, MEDIUM_COMMAND);
    assert_eq!(body["match"]["rule_id"], "core.git:stash-drop");
    assert_eq!(body["match"]["severity"], "medium");
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["mode"], "deny", "{body}");

    // Control: severity alone warns on a Medium rule.
    let without = explain_json(NO_POLICY, MEDIUM_COMMAND);
    assert_eq!(without["decision"], "deny");
    assert_eq!(without["mode"], "warn", "{without}");
}

#[test]
fn an_allowed_command_reports_no_mode() {
    let body = explain_json(NO_POLICY, "git status");
    assert_eq!(body["decision"], "allow");
    assert!(
        body.get("mode").is_none(),
        "an allow resolves no mode, and the key is absent rather than null: {body}"
    );
    // `mode` is additive: it costs the schema no version bump, because a v2
    // reader receives exactly the object it received before.
    assert_eq!(body["schema_version"], 2, "{body}");
}

// ===========================================================================
// Pretty and compact traces
// ===========================================================================

#[test]
fn the_pretty_trace_names_the_hook_verdict() {
    let warned = stdout_of(&run(WARN_HIGH, &["explain", HIGH_COMMAND]));
    assert!(
        warned.contains("Decision: DENY"),
        "the raw match stays: {warned}"
    );
    assert!(
        warned.contains("Hook verdict: WARN (policy allows)"),
        "the verdict sits beside it: {warned}"
    );

    // Control: the identical command under no policy is blocked, and says so.
    let blocked = stdout_of(&run(NO_POLICY, &["explain", HIGH_COMMAND]));
    assert!(blocked.contains("Decision: DENY"), "{blocked}");
    assert!(blocked.contains("Hook verdict: BLOCKED"), "{blocked}");
    assert!(!blocked.contains("policy allows"), "{blocked}");
}

#[test]
fn the_compact_trace_brackets_a_deny_the_hook_does_not_apply() {
    let warned = stdout_of(&run(
        WARN_HIGH,
        &["explain", "--format", "compact", HIGH_COMMAND],
    ));
    assert!(
        warned.starts_with("DENY[warn] core.git:checkout-discard"),
        "{warned}"
    );

    // Control: blocked, so the line consumers already parse is unchanged.
    let blocked = stdout_of(&run(
        NO_POLICY,
        &["explain", "--format", "compact", HIGH_COMMAND],
    ));
    assert!(
        blocked.starts_with("DENY core.git:checkout-discard"),
        "{blocked}"
    );
}

// ===========================================================================
// Exit codes
// ===========================================================================

/// The exit code of `dcg test --explain`, which README documents as 0 allowed /
/// 1 blocked for `dcg test`. `--explain` is a flag of that subcommand.
fn test_explain_exit(config: &str, command: &str, extra: &[&str]) -> i32 {
    let mut args = vec!["test", "--explain"];
    args.extend_from_slice(extra);
    args.push(command);
    run(config, &args)
        .status
        .code()
        .expect("dcg test --explain exits, not signalled")
}

#[test]
fn dcg_test_explain_exits_on_the_hooks_verdict() {
    // A High rule the policy downgrades to warn runs, so exit 0.
    assert_eq!(test_explain_exit(WARN_HIGH, HIGH_COMMAND, &[]), 0);
    // Control: the same command under no policy is blocked, so exit 1.
    assert_eq!(test_explain_exit(NO_POLICY, HIGH_COMMAND, &[]), 1);

    // And the other direction: a Medium rule the policy raises to deny.
    assert_eq!(test_explain_exit(DENY_MEDIUM, MEDIUM_COMMAND, &[]), 1);
    assert_eq!(test_explain_exit(NO_POLICY, MEDIUM_COMMAND, &[]), 0);
}

#[test]
fn dcg_test_explain_json_exits_on_the_hooks_verdict() {
    let extra = ["--format", "json"];
    assert_eq!(test_explain_exit(WARN_HIGH, HIGH_COMMAND, &extra), 0);
    assert_eq!(test_explain_exit(NO_POLICY, HIGH_COMMAND, &extra), 1);
    assert_eq!(test_explain_exit(DENY_MEDIUM, MEDIUM_COMMAND, &extra), 1);
    assert_eq!(test_explain_exit(NO_POLICY, MEDIUM_COMMAND, &extra), 0);
}

/// `-vvv` reaches the same trace by a different route (`test_command` hands off
/// to the explain handler), and used to return a flat "not blocked".
#[test]
fn dcg_test_vvv_exits_on_the_hooks_verdict() {
    let exit = |config: &str, command: &str| {
        run(config, &["test", "-vvv", command])
            .status
            .code()
            .expect("dcg test -vvv exits, not signalled")
    };
    assert_eq!(exit(WARN_HIGH, HIGH_COMMAND), 0);
    assert_eq!(exit(NO_POLICY, HIGH_COMMAND), 1);
    assert_eq!(exit(DENY_MEDIUM, MEDIUM_COMMAND), 1);
    assert_eq!(exit(NO_POLICY, MEDIUM_COMMAND), 0);
}

/// `dcg explain` is a diagnostic: it exits 0 on every verdict. Pinned here as a
/// decision, not an accident -- `tests/agent_exit_codes.rs`,
/// `tests/robot_mode.rs` and `tests/tui_e2e.rs` already depend on it, and the
/// exit-1 contract belongs to `dcg test`.
#[test]
fn dcg_explain_itself_always_exits_zero() {
    for (config, command) in [
        (NO_POLICY, HIGH_COMMAND),
        (WARN_HIGH, HIGH_COMMAND),
        (DENY_MEDIUM, MEDIUM_COMMAND),
        (NO_POLICY, "git status"),
    ] {
        let output = run(config, &["explain", command]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "dcg explain {command:?} under {config:?}"
        );
    }
}

// ===========================================================================
// The property the bead exists for
// ===========================================================================

/// For the same config, the explain trace's verdict is the hook's verdict,
/// command by command -- across both the JSON `mode` and the `dcg test
/// --explain` exit code.
#[test]
fn the_explain_verdict_is_the_hooks_verdict() {
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

    let mut denied = 0;
    for command in commands {
        let hook_denied = hook_denies(config, command);
        denied += usize::from(hook_denied);

        let body = explain_json(config, command);
        let mode_blocks = body["mode"] == "deny";
        assert_eq!(
            mode_blocks, hook_denied,
            "explain and the hook disagree on {command:?}: hook denied={hook_denied}, {body}"
        );

        let exit = test_explain_exit(config, command, &[]);
        assert_eq!(
            exit,
            i32::from(hook_denied),
            "dcg test --explain exit disagrees with the hook on {command:?}"
        );
    }

    // Both answers must occur, or agreement could be a constant.
    assert_eq!(
        denied, 2,
        "stash-drop (raised by policy) and stash-clear (Critical) block"
    );
}
