//! Every verdict surface answers with the mode the hook applies
//! (`.agent-config-a56do`).
//!
//! `dcg simulate`, `dcg hook --batch`, `dcg test` (JSON/TOON decision, and the
//! exit code in every format), `dcg scan` and the confidence in
//! `evaluate_detailed` each decided from something other than the hook's
//! answer: simulate and `evaluate_detailed` read `effective_mode`, which the
//! evaluator stamps from SEVERITY alone; batch and `dcg test` read the raw
//! match; scan kept its own copy of the policy step and never applied
//! confidence. So under a policy that differs from severity -- or, for batch and
//! `dcg test`, under no policy at all, for any Medium rule -- they reported a
//! verdict the hook does not apply. They now all resolve through
//! `evaluator::resolve_decision_mode`, the resolver the hook calls.
//!
//! Each policy assertion carries its no-policy control: `core.git:stash-drop`
//! is Medium (severity alone warns) and `core.git:checkout-discard` is High
//! (severity alone denies), so without the control a test could pass on
//! severity alone and say nothing about the policy.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use destructive_command_guard::config::{Config, PolicyMode};
use destructive_command_guard::packs::DecisionMode;
use destructive_command_guard::{LayeredAllowlist, evaluate_detailed_with_allowlists};
use serde_json::Value;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// `core.git:stash-drop` is Medium: severity alone warns.
const MEDIUM_COMMAND: &str = "git stash drop";
/// `core.git:checkout-discard` is High: severity alone denies.
const HIGH_COMMAND: &str = "git checkout -- file.txt";
const MEDIUM_RULE: &str = "core.git:stash-drop";
const HIGH_RULE: &str = "core.git:checkout-discard";

const DENY_MEDIUM: &str = "[policy.rules]\n\"core.git:stash-drop\" = \"deny\"\n";
const WARN_HIGH: &str = "[policy.rules]\n\"core.git:checkout-discard\" = \"warn\"\n";
const LOG_HIGH: &str = "[policy.rules]\n\"core.git:checkout-discard\" = \"log\"\n";
const NO_POLICY: &str = "";
/// The policy denies the Medium rule and confidence then downgrades it. The
/// `log` rule on the High one is a marker that the config loaded at all -- a
/// Medium rule warns by severity anyway, so the downgrade alone cannot tell.
/// `warn_threshold` above the 1.0 ceiling downgrades every match confidence may
/// downgrade (the construction `repro_confidence_hides_later_rule.rs` uses), so
/// the hook warns rather than denies.
const DENY_MEDIUM_CONFIDENCE_ON: &str = "[confidence]\n\
                                         enabled = true\n\
                                         warn_threshold = 1.1\n\
                                         \n\
                                         [policy.rules]\n\
                                         \"core.git:stash-drop\" = \"deny\"\n\
                                         \"core.git:checkout-discard\" = \"log\"\n";

/// Commands covering both answers under each config: the two policy subjects,
/// a Critical rule no config here loosens, and a clean command.
const COMMANDS: [&str; 4] = [
    MEDIUM_COMMAND,
    HIGH_COMMAND,
    "git stash clear",
    "git status",
];
const CLEAN_COMMAND: &str = "git status";

/// One isolated dcg invocation under `config`. `files` are written into the
/// child's working directory first, and `stdin` is built from that directory,
/// so a hook payload's `cwd` names the directory the child actually runs in.
fn run(
    config: &str,
    args: &[&str],
    files: &[(&str, &str)],
    stdin: &dyn Fn(&Path) -> String,
) -> (String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(&config_path, config).expect("write policy config");
    for (name, body) in files {
        std::fs::write(sandbox.root().join(name), body).expect("write input file");
    }
    let input = stdin(sandbox.root());
    let mut cmd = spawn::dcg_in(&sandbox);
    let mut child = cmd
        .args(args)
        .env("DCG_CONFIG", &config_path)
        // The hook fails closed past its 200 ms budget, so under load it could
        // deny a clean command and read as a disagreement. The verdict, not the
        // latency, is under test here.
        .env("DCG_HOOK_TIMEOUT_MS", "10000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("dcg stdin")
        .write_all(input.as_bytes())
        .expect("write dcg stdin");
    let output = child.wait_with_output().expect("wait for dcg");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// Whether the hook itself denies `command` under `config` -- the answer every
/// other surface must give.
fn hook_denies(config: &str, command: &str) -> bool {
    let (stdout, code) = run(config, &[], &[], &|cwd| {
        payload::pre_tool_use(cwd, command).to_string()
    });
    assert_eq!(code, 0, "hook mode exits 0 on allow and deny");
    if stdout.trim().is_empty() {
        return false;
    }
    let json: Value = serde_json::from_str(&stdout).expect("hook output is JSON");
    json["hookSpecificOutput"]["permissionDecision"] == "deny"
}

/// `dcg simulate`'s per-rule decision for each rule that matched `commands`.
fn simulate_rule_decisions(config: &str, commands: &[&str]) -> Value {
    let input = commands.join("\n") + "\n";
    let (stdout, code) = run(config, &["simulate", "-f", "-", "-F", "json"], &[], &|_| {
        input.clone()
    });
    assert_eq!(code, 0, "simulate exits 0\nstdout: {stdout}");
    let json: Value = serde_json::from_str(&stdout).expect("simulate output is JSON");
    let mut decisions = serde_json::Map::new();
    for rule in json["rules"].as_array().expect("simulate rules array") {
        let id = rule["rule_id"].as_str().expect("rule_id").to_string();
        decisions.insert(id, rule["decision"].clone());
    }
    Value::Object(decisions)
}

/// `dcg hook --batch`'s rows, one per command, in order.
fn batch_rows(config: &str, commands: &[&str]) -> Vec<Value> {
    let (stdout, code) = run(config, &["hook", "--batch"], &[], &|cwd| {
        commands
            .iter()
            .map(|c| payload::pre_tool_use(cwd, c).to_string() + "\n")
            .collect()
    });
    assert_eq!(code, 0, "batch exits 0\nstdout: {stdout}");
    let mut rows: Vec<Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("batch row is JSON"))
        .collect();
    rows.sort_by_key(|r| r["index"].as_u64());
    assert_eq!(rows.len(), commands.len(), "one batch row per command");
    rows
}

/// A batch row's `(decision, mode)`.
fn batch_answer(config: &str, command: &str) -> (Option<String>, Option<String>) {
    let row = &batch_rows(config, &[command])[0];
    (
        row["decision"].as_str().map(str::to_string),
        row["mode"].as_str().map(str::to_string),
    )
}

/// `dcg test --format json`: the JSON body and the exit code.
fn test_json(config: &str, command: &str) -> (Value, i32) {
    let (stdout, code) = run(config, &["test", "--format", "json", command], &[], &|_| {
        String::new()
    });
    let json = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dcg test JSON for {command:?}: {e}\n{stdout}"));
    (json, code)
}

/// `dcg test` in its default (pretty) format: the exit code.
fn test_pretty_exit(config: &str, command: &str) -> i32 {
    run(config, &["test", command], &[], &|_| String::new()).1
}

/// `dcg scan`'s findings for a shell script containing `command`.
fn scan_findings(config: &str, command: &str) -> Vec<Value> {
    let script = format!("#!/bin/sh\n{command}\n");
    let (stdout, _code) = run(
        config,
        &["scan", "--paths", "run.sh", "--format", "json"],
        &[("run.sh", &script)],
        &|_| String::new(),
    );
    let json: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("dcg scan JSON: {e}\n{stdout}"));
    json["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("scan findings array: {json}"))
        .clone()
}

#[test]
fn simulate_counts_what_the_policy_decides() {
    let with = simulate_rule_decisions(DENY_MEDIUM, &[MEDIUM_COMMAND]);
    assert_eq!(with[MEDIUM_RULE], "deny", "policy deny on Medium: {with}");
    let without = simulate_rule_decisions(NO_POLICY, &[MEDIUM_COMMAND]);
    assert_eq!(
        without[MEDIUM_RULE], "warn",
        "control, severity warns: {without}"
    );

    let with = simulate_rule_decisions(WARN_HIGH, &[HIGH_COMMAND]);
    assert_eq!(with[HIGH_RULE], "warn", "policy warn on High: {with}");
    let without = simulate_rule_decisions(NO_POLICY, &[HIGH_COMMAND]);
    assert_eq!(
        without[HIGH_RULE], "deny",
        "control, severity denies: {without}"
    );
}

#[test]
fn batch_answers_what_the_policy_decides() {
    let answer = |d: &str, m: &str| (Some(d.to_string()), Some(m.to_string()));
    assert_eq!(
        batch_answer(DENY_MEDIUM, MEDIUM_COMMAND),
        answer("deny", "deny")
    );
    // Control: the hook only warns on a Medium rule, so batch allows it.
    assert_eq!(
        batch_answer(NO_POLICY, MEDIUM_COMMAND),
        answer("allow", "warn")
    );

    assert_eq!(
        batch_answer(WARN_HIGH, HIGH_COMMAND),
        answer("allow", "warn")
    );
    assert_eq!(
        batch_answer(NO_POLICY, HIGH_COMMAND),
        answer("deny", "deny")
    );

    assert_eq!(
        batch_answer(NO_POLICY, CLEAN_COMMAND),
        (Some("allow".to_string()), None)
    );
}

#[test]
fn dcg_test_json_and_exit_code_follow_the_policy() {
    let (json, code) = test_json(DENY_MEDIUM, MEDIUM_COMMAND);
    assert_eq!(
        (json["decision"].as_str(), json["mode"].as_str(), code),
        (Some("deny"), Some("deny"), 1),
        "policy deny on Medium: {json}"
    );
    let (json, code) = test_json(NO_POLICY, MEDIUM_COMMAND);
    assert_eq!(
        (json["decision"].as_str(), json["mode"].as_str(), code),
        (Some("allow"), Some("warn"), 0),
        "control, severity warns: {json}"
    );
    assert_eq!(
        json["rule_id"], MEDIUM_RULE,
        "a warned match still names its rule"
    );

    let (json, code) = test_json(WARN_HIGH, HIGH_COMMAND);
    assert_eq!(
        (json["decision"].as_str(), json["mode"].as_str(), code),
        (Some("allow"), Some("warn"), 0),
        "policy warn on High: {json}"
    );
    let (json, code) = test_json(NO_POLICY, HIGH_COMMAND);
    assert_eq!(
        (json["decision"].as_str(), json["mode"].as_str(), code),
        (Some("deny"), Some("deny"), 1),
        "control, severity denies: {json}"
    );

    let (json, code) = test_json(NO_POLICY, CLEAN_COMMAND);
    assert_eq!((json["decision"].as_str(), code), (Some("allow"), 0));
    assert!(json.get("mode").is_none(), "no match, no mode: {json}");

    // TOON carries the same fields as JSON.
    let (toon, code) = run(
        NO_POLICY,
        &["test", "--format", "toon", MEDIUM_COMMAND],
        &[],
        &|_| String::new(),
    );
    let lines: Vec<&str> = toon.lines().map(str::trim).collect();
    assert_eq!(code, 0, "TOON exit: {toon}");
    assert!(lines.contains(&"decision: allow"), "TOON decision: {toon}");
    assert!(lines.contains(&"mode: warn"), "TOON mode: {toon}");
}

#[test]
fn dcg_test_pretty_exit_code_follows_the_policy() {
    assert_eq!(test_pretty_exit(DENY_MEDIUM, MEDIUM_COMMAND), 1);
    assert_eq!(test_pretty_exit(NO_POLICY, MEDIUM_COMMAND), 0, "control");
    assert_eq!(test_pretty_exit(WARN_HIGH, HIGH_COMMAND), 0);
    assert_eq!(test_pretty_exit(NO_POLICY, HIGH_COMMAND), 1, "control");
}

/// A `log` policy is its own mode: allowed everywhere, and named "log" where a
/// surface names the mode -- not folded into warn.
#[test]
fn a_log_policy_allows_and_is_named_log() {
    assert!(
        !hook_denies(LOG_HIGH, HIGH_COMMAND),
        "precondition: the hook allows"
    );
    let simulate = simulate_rule_decisions(LOG_HIGH, &[HIGH_COMMAND]);
    assert_eq!(simulate[HIGH_RULE], "allow", "simulate: {simulate}");
    assert_eq!(
        batch_answer(LOG_HIGH, HIGH_COMMAND),
        (Some("allow".to_string()), Some("log".to_string()))
    );
    let (json, code) = test_json(LOG_HIGH, HIGH_COMMAND);
    assert_eq!(
        (json["decision"].as_str(), json["mode"].as_str(), code),
        (Some("allow"), Some("log"), 0),
        "dcg test: {json}"
    );
}

/// `dcg scan` applies confidence as the hook does. Its own copy of the policy
/// step stopped at the policy, so a rule the policy denies and confidence
/// downgrades was a scan Deny while the hook only warned.
#[test]
fn scan_decides_with_confidence_as_the_hook_does() {
    // The config loaded: its `log` rule lets a High command through the hook
    // and scan, which severity alone would deny.
    assert!(!hook_denies(DENY_MEDIUM_CONFIDENCE_ON, HIGH_COMMAND));
    let marker = scan_findings(DENY_MEDIUM_CONFIDENCE_ON, HIGH_COMMAND);
    assert_eq!(marker[0]["decision"], "allow", "config loaded: {marker:?}");

    assert!(
        !hook_denies(DENY_MEDIUM_CONFIDENCE_ON, MEDIUM_COMMAND),
        "precondition: confidence downgrades the hook's deny to a warn"
    );
    let findings = scan_findings(DENY_MEDIUM_CONFIDENCE_ON, MEDIUM_COMMAND);
    assert_eq!(findings.len(), 1, "one finding: {findings:?}");
    assert_eq!(findings[0]["rule_id"], MEDIUM_RULE, "{findings:?}");
    assert_eq!(findings[0]["decision"], "warn", "{findings:?}");

    // Control: with confidence off the policy's deny stands, in both.
    assert!(hook_denies(DENY_MEDIUM, MEDIUM_COMMAND));
    let findings = scan_findings(DENY_MEDIUM, MEDIUM_COMMAND);
    assert_eq!(findings[0]["decision"], "deny", "{findings:?}");
}

/// The property the bead exists for: under each config, every surface gives
/// the hook's answer on every command, and both answers occur.
#[test]
fn every_surface_gives_the_hooks_answer() {
    for config in [DENY_MEDIUM, WARN_HIGH, NO_POLICY] {
        let hook: Vec<bool> = COMMANDS.iter().map(|c| hook_denies(config, c)).collect();
        assert!(
            hook.contains(&true) && hook.contains(&false),
            "both answers occur under {config:?}: {hook:?}"
        );

        let batch = batch_rows(config, &COMMANDS);
        let simulate = simulate_rule_decisions(config, &COMMANDS);
        for (i, command) in COMMANDS.iter().enumerate() {
            let denied = hook[i];
            let verdict = if denied { "deny" } else { "allow" };
            let ctx = format!("{command:?} under {config:?}: hook denied={denied}");

            assert_eq!(batch[i]["decision"], verdict, "batch disagrees: {ctx}");

            let (json, code) = test_json(config, command);
            assert_eq!(json["decision"], verdict, "test JSON: {ctx} {json}");
            assert_eq!(code, i32::from(denied), "test JSON exit: {ctx}");
            let pretty = test_pretty_exit(config, command);
            assert_eq!(pretty, i32::from(denied), "test pretty exit: {ctx}");

            // Every command but the clean one matches a rule, so simulate is
            // checked for each of them -- a missing rule_id fails, not skips.
            let rule = json["rule_id"].as_str();
            assert_eq!(rule.is_some(), *command != CLEAN_COMMAND, "{ctx} {json}");
            if let Some(rule) = rule {
                let sim = simulate[rule]
                    .as_str()
                    .unwrap_or_else(|| panic!("simulate has no row for {rule}: {simulate}"));
                assert_eq!(sim == "deny", denied, "simulate disagrees on {rule}: {ctx}");
            }
        }
    }
}

/// Commands for the in-process test below. `evaluate_detailed` consults the
/// ambient allow-once store, which flips a verdict only on an exact command
/// match (.agent-config-pwv0p), so these are strings no one would allow-once.
const PROBE_MEDIUM: &str = "git stash drop a56do-probe";
const PROBE_HIGH: &str = "git checkout -- a56do-probe.txt";

/// `evaluate_detailed`'s confidence is the hook's own answer: seeded with the
/// policy's mode, not the severity's, then asked the hook's confidence question.
#[test]
fn evaluate_detailed_confidence_is_seeded_by_the_policy() {
    let confidence_under = |rule: Option<(&str, PolicyMode)>, confident: bool, command: &str| {
        let mut config = Config::default();
        if let Some((id, mode)) = rule {
            config.policy.rules.insert(id.to_string(), mode);
        }
        if confident {
            // Every downgradable match downgrades (see DENY_MEDIUM_CONFIDENCE_ON).
            config.confidence.enabled = true;
            config.confidence.warn_threshold = 1.1;
        }
        let detailed =
            evaluate_detailed_with_allowlists(command, &config, &LayeredAllowlist::default());
        detailed
            .confidence
            .unwrap_or_else(|| panic!("a denied {command:?} carries a confidence result"))
    };
    let mode_under = |rule, command: &str| confidence_under(rule, false, command).mode;

    // Confidence off: the result's mode is exactly the seed.
    assert_eq!(
        mode_under(Some((MEDIUM_RULE, PolicyMode::Deny)), PROBE_MEDIUM),
        DecisionMode::Deny
    );
    assert_eq!(
        mode_under(None, PROBE_MEDIUM),
        DecisionMode::Warn,
        "control"
    );
    assert_eq!(
        mode_under(Some((HIGH_RULE, PolicyMode::Warn)), PROBE_HIGH),
        DecisionMode::Warn
    );
    assert_eq!(mode_under(None, PROBE_HIGH), DecisionMode::Deny, "control");

    // Confidence on: the policy's deny is then downgraded, as the hook does it.
    let downgraded = confidence_under(Some((MEDIUM_RULE, PolicyMode::Deny)), true, PROBE_MEDIUM);
    assert_eq!(
        (downgraded.mode, downgraded.downgraded),
        (DecisionMode::Warn, true),
        "{downgraded:?}"
    );
}
