//! Every surface that answers for the user's config evaluates the hook's pack
//! set, `[packs] custom_paths` packs included (`.agent-config-zpo5q`).
//!
//! `dcg hook --batch`, `dcg explain`, `dcg simulate` and `dcg dev debug` each
//! built their own pack set from `enabled_pack_ids()` alone, so a command the
//! single hook denies by a custom rule came back allowed from them. `dcg scan`
//! got the pack set in `.agent-config-1j0l5` and is pinned here too. Each test
//! runs the real binary with the pack and without it: the control is what
//! proves the answer came from the pack.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use serde_json::{Value, json};

#[path = "common/spawn.rs"]
mod spawn;

/// An external pack whose one rule is Critical, so severity alone denies it.
const PACK: &str = r"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
    description: Direct production deployment blocked
";
const COMMAND: &str = "deploy --env prod";
const RULE: &str = "custom.deploy:prod-deploy";

/// Run `dcg` in a fresh sandbox whose config loads `PACK` when `with_pack`.
/// `args` receives the sandbox root, for surfaces that read a file.
fn dcg(with_pack: bool, args: impl FnOnce(&Path) -> Vec<String>, stdin: &str) -> Output {
    let sandbox = spawn::sandbox();
    let root = sandbox.root();
    let pack_path = root.join("custom.yaml");
    std::fs::write(&pack_path, PACK).expect("write custom pack");
    let config = if with_pack {
        format!(
            "[packs]\ncustom_paths = [\"{}\"]\n",
            pack_path.to_string_lossy().replace('\\', "/")
        )
    } else {
        String::new()
    };
    let config_path = root.join("config.toml");
    std::fs::write(&config_path, config).expect("write config");

    let mut cmd = spawn::dcg_in(&sandbox);
    let mut child = cmd
        .args(args(root))
        .env("DCG_CONFIG", &config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("dcg stdin")
        .write_all(stdin.as_bytes())
        .expect("write dcg stdin");
    child.wait_with_output().expect("wait for dcg")
}

fn stdout_json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}):\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(ToString::to_string).collect()
}

#[test]
fn hook_batch_denies_by_a_custom_paths_rule() {
    let line = json!({"tool_name": "Bash", "tool_input": {"command": COMMAND}}).to_string() + "\n";
    let batch = |with_pack| stdout_json(&dcg(with_pack, |_| owned(&["hook", "--batch"]), &line));

    let with_pack = batch(true);
    assert_eq!(with_pack["decision"], "deny", "{with_pack}");
    assert_eq!(with_pack["rule_id"], RULE, "{with_pack}");

    let without = batch(false);
    assert_eq!(without["decision"], "allow", "{without}");
}

#[test]
fn explain_answers_with_a_custom_paths_rule() {
    let explain = |with_pack| {
        stdout_json(&dcg(
            with_pack,
            |_| owned(&["explain", "--format", "json", COMMAND]),
            "",
        ))
    };

    let with_pack = explain(true);
    assert_eq!(with_pack["decision"], "deny", "{with_pack}");
    assert_eq!(with_pack["match"]["rule_id"], RULE, "{with_pack}");

    let without = explain(false);
    assert_eq!(without["decision"], "allow", "{without}");
}

#[test]
fn simulate_counts_a_custom_paths_denial() {
    let simulate = |with_pack| {
        stdout_json(&dcg(
            with_pack,
            |root| {
                let log = root.join("commands.txt");
                std::fs::write(&log, format!("{COMMAND}\ngit status\n")).expect("write log");
                let log = log.to_string_lossy().into_owned();
                owned(&["simulate", "-f", &log, "--format", "json"])
            },
            "",
        ))
    };

    let with_pack = simulate(true);
    assert_eq!(with_pack["totals"]["commands"], 2, "{with_pack}");
    assert_eq!(with_pack["totals"]["denied"], 1, "{with_pack}");
    assert_eq!(with_pack["rules"][0]["rule_id"], RULE, "{with_pack}");

    let without = simulate(false);
    assert_eq!(without["totals"]["commands"], 2, "{without}");
    assert_eq!(without["totals"]["denied"], 0, "{without}");
}

/// `dcg scan` got the pack set through `ScanEvalContext` in
/// `.agent-config-1j0l5`; nothing pinned it until now.
#[test]
fn scan_reports_a_custom_paths_finding() {
    let scan = |with_pack| {
        stdout_json(&dcg(
            with_pack,
            |root| {
                let script = root.join("deploy.sh");
                std::fs::write(&script, format!("#!/bin/sh\n{COMMAND}\n")).expect("write script");
                let script = script.to_string_lossy().into_owned();
                owned(&["scan", "--paths", &script, "--format", "json"])
            },
            "",
        ))
    };
    let rules = |report: &Value| -> Vec<String> {
        report["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("scan report has findings: {report}"))
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or_default().to_string())
            .collect()
    };

    let with_pack = scan(true);
    assert_eq!(rules(&with_pack), [RULE], "{with_pack}");

    let without = scan(false);
    assert!(rules(&without).is_empty(), "{without}");
}

#[test]
fn dev_debug_walks_a_custom_paths_pack() {
    let debug = |with_pack| {
        let output = dcg(with_pack, |_| owned(&["dev", "debug", COMMAND]), "");
        assert!(output.status.success(), "dev debug exits 0");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let with_pack = debug(true);
    // The keyword section and the pack loop each need the external pack.
    assert!(
        with_pack.contains("Keyword matched: 'deploy'"),
        "{with_pack}"
    );
    assert!(with_pack.contains("[custom.deploy]"), "{with_pack}");
    assert!(
        with_pack.contains("Destructive pattern 'prod-deploy' -> MATCH"),
        "{with_pack}"
    );

    let without = debug(false);
    assert!(!without.contains("custom.deploy"), "{without}");
    assert!(without.contains("quick-rejected"), "{without}");
}
