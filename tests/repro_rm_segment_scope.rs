//! Every `rm` segment in a line is judged, not just the first one.
//!
//! `.agent-config-6nnw8`, found by the cold reviewer on `.agent-config-35ysf`
//! and pre-existing at dcg `3a26fc0`. `parse_rm_command` walked the line looking
//! for a command word `rm` and then `return`ed the decision of that ONE segment.
//! `RmParseDecision::Allow` makes the evaluator `continue` past the whole
//! `core.filesystem` pack, so a demonstrably harmless `rm` in front left every
//! later `rm` on the same line unexamined:
//!
//! ```text
//! rm -rf /etc                    BLOCKED
//! rm -rf /tmp/x && rm -rf /etc   ALLOWED   <- measured on the live guard
//! ```
//!
//! This is the same first-match-then-skip shape `.agent-config-it2wk` fixed for
//! the regex packs (`tests/repro_safe_pattern_scope.rs`) and `.agent-config-35ysf`
//! fixed for a regex search that gives up. The parser had its own copy of it.
//!
//! Both directions are asserted here. A fix that simply stopped returning `Allow`
//! would pass every deny case below and break the allow cases, which is what the
//! `Allow` arm exists to prevent in the first place.

use std::collections::HashSet;
use std::io::Write;
use std::process::Stdio;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Evaluate with the `core` pack family enabled, which is where
/// `core.filesystem` and its `rm` parser live.
fn is_denied(command: &str) -> bool {
    let config = Config::default();
    let enabled: HashSet<String> = HashSet::from(["core".to_string()]);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let index = REGISTRY
        .build_enabled_keyword_index(&ordered)
        .expect("keyword index should build");
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc = config.heredoc_settings();

    evaluate_command_with_pack_order(
        command,
        &keywords,
        &ordered,
        Some(&index),
        &overrides,
        &allowlists,
        &heredoc,
        config.policy(),
    )
    .is_denied()
}

/// The control. If this goes false the harness is not reaching `core.filesystem`
/// and every assertion in this file passes without judging anything.
#[test]
fn the_filesystem_pack_is_actually_reached() {
    assert!(
        is_denied("rm -rf /etc"),
        "core.filesystem is not enabled in this harness, so every other test in \
         this file would pass without evaluating anything"
    );
}

/// The control for the other direction. A safe `rm -rf` must reach the `Allow`
/// arm, or the allow-side tests below prove nothing about segment scoping —
/// they would pass on a parser that never produced `Allow` at all.
#[test]
fn a_lone_safe_rm_is_allowed() {
    assert!(
        !is_denied("rm -rf /tmp/x"),
        "a single safe rm -rf must be allowed, or the allow cases below are vacuous"
    );
}

#[test]
fn a_safe_rm_in_front_does_not_hide_a_destructive_rm_behind_it() {
    for cmd in [
        "rm -rf /tmp/x && rm -rf /etc",
        "rm -rf /tmp/x ; rm -rf /etc",
        "rm -rf /tmp/x || rm -rf /etc",
        "rm -rf /var/tmp/x && rm -rf /usr/local",
        // Three segments: the destructive one is neither first nor last.
        "rm -rf /tmp/x && rm -rf /etc && rm -rf /tmp/y",
    ] {
        assert!(
            is_denied(cmd),
            "an allowed rm segment must not skip the pack for the later ones: {cmd}"
        );
    }
}

#[test]
fn a_safe_rm_in_front_does_not_hide_a_critical_rm_behind_it() {
    for cmd in ["rm -rf /tmp/x && rm -rf /", "rm -rf /tmp/dist ; rm -rf ~"] {
        assert!(
            is_denied(cmd),
            "a critical rm must be denied from any position on the line: {cmd}"
        );
    }
}

// ---------------------------------------------------------------------------
// The other direction: judging every segment must not deny a safe line.
// ---------------------------------------------------------------------------

#[test]
fn a_line_whose_rm_segments_are_all_safe_is_still_allowed() {
    for cmd in [
        "rm -rf /tmp/x && rm -rf /tmp/y",
        "rm -rf /var/tmp/a && rm -rf /tmp/b",
        "rm -rf /tmp/x && rm -rf /tmp/y && rm -rf /var/tmp/z",
    ] {
        assert!(!is_denied(cmd), "must stay allowed: {cmd}");
    }
}

// ---------------------------------------------------------------------------
// End to end, through the real binary and the payload a real agent sends.
// ---------------------------------------------------------------------------

/// The `permissionDecision` the hook returns for `command`, over a full
/// `PreToolUse` envelope.
///
/// A hook-mode ALLOW is silent: dcg writes nothing on stdout and exits 0.
/// Measured on the real binary 2026-09-15, which is also how the bug reads from
/// the outside — `rm -rf /tmp/x && rm -rf /etc` produced no output at all. So
/// empty stdout is reported as `"allow"` here, and the exit status is asserted
/// first, or a crash would be indistinguishable from a permitted command.
fn hook_decision(command: &str) -> String {
    let (mut cmd, sandbox) = spawn::dcg();
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
        "hook mode exits 0 for either verdict; another status means dcg failed \
         rather than decided\nstdout: {stdout}\nstderr: {stderr}"
    );

    if stdout.trim().is_empty() {
        return "allow".to_string();
    }

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("hook output should be valid JSON ({err})\nstdout: {stdout}\nstderr: {stderr}")
    });

    json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_else(|| panic!("no permissionDecision in hook output: {stdout}"))
        .to_string()
}

#[test]
fn the_hook_denies_a_destructive_rm_hidden_behind_a_safe_one() {
    assert_eq!(
        hook_decision("rm -rf /tmp/x && rm -rf /etc"),
        "deny",
        "this is the exact line the live guard ALLOWED before .agent-config-6nnw8"
    );
}

#[test]
fn the_hook_still_allows_a_line_whose_rm_segments_are_all_safe() {
    assert_eq!(
        hook_decision("rm -rf /tmp/x && rm -rf /tmp/y"),
        "allow",
        "two safe rm segments must not become a denial"
    );
}
