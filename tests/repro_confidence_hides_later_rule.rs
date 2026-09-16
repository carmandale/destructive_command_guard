//! An early return must not be downgradable AFTER it has hidden a later rule
//! (`.agent-config-dcg-confidence-downgrades-early-return-tk1gu`).
//!
//! `policy_denies` answers the POLICY's question only. main.rs runs
//! `apply_confidence_scoring` AFTER `resolve_mode` and can still turn that Deny
//! into a Warn, which the evaluator could not see. So a match the policy denied
//! ended the scan, hid every rule behind it, and was only then downgraded —
//! including over a Critical rule that `protect_critical` refuses to downgrade.
//! The command the hidden rule existed to stop then ran.
//!
//! This is the same shape as `.agent-config-5nyrn`, one layer further out: there
//! the evaluator asked SEVERITY a question only the policy could answer, and the
//! fix threaded `[policy]` in. Here it asked the policy a question only the
//! policy AND `[confidence]` together can answer, so `[confidence]` is threaded
//! the same way and `decision_blocks` asks both.
//!
//! Two choices keep this file honest about what it measures:
//!
//! - The downgradable rule is `core.git:stash-drop`, Medium, denied by an
//!   explicit `[policy.rules]` entry. Medium is what makes it downgradable at
//!   all — `core.git:reset-hard` and `clean-force` are Critical, so
//!   `protect_critical` refuses to downgrade them and a pair built from those
//!   denies with or without the fix, measuring nothing.
//! - `warn_threshold` is pinned ABOVE 1.0, the ceiling `ConfidenceScore::add_signal`
//!   clamps to, so every match confidence scoring is permitted to downgrade does
//!   downgrade. At the default 0.5 a plainly executed match scores 1.0 and is never
//!   downgraded, so the pair below would deny with or without the fix and measure
//!   nothing. Pinned this way the downgrade is a property of the configuration
//!   rather than of one span's score, and the test cannot go green because a
//!   heuristic drifted.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Confidence scoring on, a threshold that downgrades any match it is allowed to
/// downgrade, and a Medium rule the policy explicitly denies so the evaluator
/// treats its match as one that blocks. Critical stays protected, as by default.
const CONFIDENCE_ON: &str = "[confidence]\n\
                             enabled = true\n\
                             warn_threshold = 1.1\n\
                             protect_critical = true\n\
                             \n\
                             [policy.rules]\n\
                             \"core.git:stash-drop\" = \"deny\"\n";

fn run_hook_with_config(config_body: &str, packs: &str, command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("confidence.toml");
    std::fs::write(&config_path, config_body).expect("write config");

    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path).env("DCG_PACKS", packs);

    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(input.as_bytes()).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait for dcg");

    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Assert the hook denied `command` and named `rule`.
fn assert_denied_by(command: &str, (stdout, stderr, exit_code): (String, String, i32), rule: &str) {
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 even on deny\ncommand: {command}\nstderr: {stderr}"
    );
    assert!(
        !stdout.is_empty(),
        "a rule that blocks must produce hook JSON, not a bare stderr warning\n\
         command: {command}\nstderr: {stderr}"
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
        "the denial must name the rule that actually blocks\ncommand: {command}\nstdout: {stdout}"
    );
}

/// The control the rest of the file rests on: at this threshold, and with the
/// policy denying it, this match really is still downgraded on its own.
///
/// Without this, every assertion below would also pass with confidence scoring
/// switched off entirely — the one "fix" that must not count. It is also what
/// makes the pair below a measurement rather than a coincidence: the first match
/// is one the hook would have allowed through.
#[test]
fn the_downgradable_rule_alone_is_still_downgraded() {
    let (stdout, stderr, exit_code) =
        run_hook_with_config(CONFIDENCE_ON, "core.git", "git stash drop");

    assert_eq!(exit_code, 0, "a downgraded match still exits 0");
    assert!(
        stdout.is_empty(),
        "confidence scoring must still downgrade this match to a stderr warning; \
         if it denies here, this file no longer tests what it claims\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

/// And the Critical rule on its own is denied, and stays denied: `protect_critical`.
#[test]
fn the_critical_rule_alone_is_denied() {
    assert_denied_by(
        "git stash clear",
        run_hook_with_config(CONFIDENCE_ON, "core.git", "git stash clear"),
        "core.git:stash-clear",
    );
}

/// The bug. The downgradable match is found FIRST and must not end the scan.
///
/// Before the fix the evaluator returned `stash-drop` the moment the policy said
/// Deny, main.rs scored it below the threshold and downgraded it to Warn, and
/// `stash-clear` — Critical, and protected from that same downgrade — was never
/// reached. The hook printed a warning, exited 0 with no JSON, and the wipe ran.
#[test]
fn a_downgradable_match_does_not_hide_the_critical_rule_behind_it() {
    assert_denied_by(
        "git stash drop && git stash clear",
        run_hook_with_config(
            CONFIDENCE_ON,
            "core.git",
            "git stash drop && git stash clear",
        ),
        "core.git:stash-clear",
    );
}

/// Order is not the fix. The same pair with the downgradable rule second must
/// still deny, so a green above cannot be an artifact of scan order.
#[test]
fn the_same_pair_in_the_other_order_also_denies() {
    assert_denied_by(
        "git stash clear && git stash drop",
        run_hook_with_config(
            CONFIDENCE_ON,
            "core.git",
            "git stash clear && git stash drop",
        ),
        "core.git:stash-clear",
    );
}

/// The bead's own input.
///
/// When `3e2736f2` landed, the `"deny"` line above was inert: the heredoc AST
/// loop skipped `heredoc.python.os_system` (`Severity::Medium`) on severity
/// before `[policy.rules]` was ever consulted, and the OUTER pack scan found the
/// Critical wipe. Since `.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7`
/// the loop asks the policy first, so the line is live: the policy denies the
/// rule, confidence downgrades it, and it must be held rather than returned, so
/// that the wipe behind it still decides. It now pins the heredoc AST loop's
/// confidence question.
#[test]
fn the_beads_named_input_keeps_denying() {
    let config = format!("{CONFIDENCE_ON}\"heredoc.python:os_system\" = \"deny\"\n");
    let command = "python3 <<'EOF2' && git stash clear\nimport os\nos.system('ls')\nEOF2";

    assert_denied_by(
        command,
        run_hook_with_config(&config, "core.git", command),
        "core.git:stash-clear",
    );

    // Liveness: the heredoc alone is judged, not skipped -- the policy denies
    // os_system, confidence downgrades it, and the hook warns naming it. Were
    // the AST loop to skip it on severity again, the denial above would still
    // come from the outer scan, and only this row would notice.
    let alone = "python3 <<'EOF2'\nimport os\nos.system('ls')\nEOF2";
    let (stdout, stderr, exit_code) = run_hook_with_config(&config, "core.git", alone);
    assert_eq!(exit_code, 0, "a downgraded match still exits 0");
    assert!(
        stdout.is_empty(),
        "the downgraded os_system match must warn, not deny\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("heredoc.python:os_system"),
        "the heredoc alone must warn naming os_system\nstderr: {stderr}"
    );
}

/// The same pair inside `bash -c`. Each inner command is judged on its own
/// (Tier 2.5), and a downgradable inner denial returned at once hid the
/// Critical command after it exactly as above
/// (.agent-config-dcg-heredoc-policy-warn-hides-outer-fxck7).
#[test]
fn a_downgradable_match_inside_bash_does_not_hide_the_critical_rule_behind_it() {
    let command = "bash -c 'git stash drop; git stash clear'";
    assert_denied_by(
        command,
        run_hook_with_config(CONFIDENCE_ON, "core.git", command),
        "core.git:stash-clear",
    );
}
