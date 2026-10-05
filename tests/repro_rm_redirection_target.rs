//! A redirection's file is not an `rm` target.
//!
//! `.agent-config-q6ub5`, measured on the installed 0.4.2 hook 2026-10-05:
//!
//! ```text
//! rm -rf /tmp/zz-core-probe 2>/dev/null   DENY core.filesystem:rm-rf-root-home
//! rm -rf /tmp/zz-core-probe               ALLOW
//! ```
//!
//! normalize splits `2>/dev/null` into `2>` and `/dev/null` and parks the pair
//! at the end of the command; the `rm` parser then took both words as targets.
//! Neither is scratch, so the all-scratch test failed, and the /tmp target
//! itself -- absolute -- was judged `rm-rf-root-home`. The same misreading
//! denied `>/dev/null 2>&1`, `< /dev/null` and `2>&1` as root-home, and the
//! `-r -f` and long-flag spellings and a quoted `$TMPDIR` target under their
//! own High rules. pm-config counted 12 denied Bash calls carrying a
//! recursive rm and a /dev/null redirection in one week of transcripts (a
//! floor of candidates, not each proven on the redirection alone).
//!
//! Both directions are asserted, through the evaluator on the normalized
//! command (the path a real hook call takes) and through the real binary. A fix
//! that skipped too much -- every word after an operator, or a quoted `>` --
//! would pass the allow cases and fail the deny cases below.

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

/// The rule that denied `command` with the `core` packs enabled, or `None`
/// when it is allowed.
fn denying_rule(command: &str) -> Option<String> {
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

    let result = evaluate_command_with_pack_order(
        command,
        &keywords,
        &ordered,
        Some(&index),
        &overrides,
        &allowlists,
        &heredoc,
        config.policy(),
        &config.confidence,
    );
    if !result.is_denied() {
        return None;
    }
    let info = result
        .pattern_info
        .unwrap_or_else(|| panic!("a deny carries the rule that made it: {command}"));
    Some(format!(
        "{}:{}",
        info.pack_id.unwrap_or_default(),
        info.pattern_name.unwrap_or_default()
    ))
}

/// The control. If this goes `None` the harness is not reaching
/// `core.filesystem`, and every allow case below passes without judging.
#[test]
fn the_filesystem_pack_is_actually_reached() {
    assert_eq!(
        denying_rule("rm -rf /etc").as_deref(),
        Some("core.filesystem:rm-rf-root-home")
    );
    assert_eq!(denying_rule("rm -rf /tmp/zz-core-probe"), None);
}

#[test]
fn a_redirection_does_not_turn_a_scratch_delete_into_a_deny() {
    for cmd in [
        "rm -rf /tmp/zz-core-probe 2>/dev/null",
        "rm -rf /tmp/zz-core-probe >/dev/null",
        "rm -rf /tmp/zz-core-probe >/dev/null 2>&1",
        "rm -rf /tmp/zz-core-probe 2>&1",
        "rm -rf /tmp/zz-core-probe < /dev/null",
        "rm -rf /tmp/zz-core-probe >\"/dev/null\"",
        "rm 2>/dev/null -rf /tmp/zz-core-probe",
        "rm -r -f /tmp/zz-core-probe 2>/dev/null",
        "rm --recursive --force /tmp/zz-core-probe 2>/dev/null",
        "rm -rf \"$TMPDIR/zz-core-probe\" 2>/dev/null",
        "rm -rf /tmp/a 2>/dev/null && rm -rf /var/tmp/b 2>/dev/null",
    ] {
        assert_eq!(denying_rule(cmd), None, "must stay allowed: {cmd}");
    }
}

#[test]
fn a_redirection_leaves_every_real_target_judged() {
    for cmd in [
        "rm -rf /Users/someone/x 2>/dev/null",
        "rm -rf ~/x >/dev/null",
        "rm -rf 2>/dev/null /Users/someone/x",
        "rm -rf /tmp/zz-core-probe 2>/dev/null /",
        "rm -rf /tmp/zz-core-probe 2>/dev/null; rm -rf /etc",
        "rm -rf /tmp/zz-core-probe \">\" /etc",
        "rm -rf /tmp/zz-core-probe \\> /etc",
        // A glued redirection carries its own word; the next one is rm's.
        "rm -rf /tmp/zz-core-probe <<<hi ~/x",
        // These reach the parser with the real target AFTER the redirection:
        // a here-string or heredoc makes normalize leave every redirection
        // where it was written, and normalize never moves one cut at `(`.
        // Each allowed on the first draft of this fix, which set every
        // redirection aside unconditionally.
        "rm -rf /tmp/zz-core-probe 2>&1 /etc <<<x",
        "rm -rf /tmp/zz-core-probe >&2 /etc <<<x",
        "rm -rf /tmp/zz-core-probe >|/tmp/zz.log /etc <<<x",
        "rm -rf /tmp/zz-core-probe <(echo) /etc <<<x",
        "rm -rf /tmp/zz-core-probe >$(mktemp) /etc <<<x",
        "rm -rf /tmp/zz-core-probe <(echo) /etc",
        "rm -rf /tmp/zz-core-probe >$(mktemp) /etc",
        // A file name the shell runs code to compute. An Allow from the parser
        // skips the whole pack, so this must stay a parser deny: allowing it
        // would also hide the regex rule that denies the inner command.
        "rm -rf /tmp/zz-core-probe > \"$(rm -rf ~)\"",
        "rm -rf /tmp/zz-core-probe 2>`rm -rf ~`",
    ] {
        assert_eq!(
            denying_rule(cmd).as_deref(),
            Some("core.filesystem:rm-rf-root-home"),
            "must stay denied as root-home: {cmd}"
        );
    }
    assert_eq!(
        denying_rule("rm -rf ./build 2>/dev/null").as_deref(),
        Some("core.filesystem:rm-rf-general")
    );
}

/// The `permissionDecision` the real binary returns over a full `PreToolUse`
/// envelope. A hook-mode ALLOW is silent (empty stdout, exit 0), so the exit
/// status is asserted first or a crash would read as a permitted command.
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
        "hook mode exits 0 for either verdict\nstdout: {stdout}\nstderr: {stderr}"
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
fn the_hook_allows_the_measured_cleanup_and_denies_its_home_twin() {
    assert_eq!(
        hook_decision("rm -rf /tmp/zz-core-probe 2>/dev/null"),
        "allow",
        "the exact line the installed hook denied as rm-rf-root-home"
    );
    assert_eq!(hook_decision("rm -rf /Users/someone/x 2>/dev/null"), "deny");
    assert_eq!(hook_decision("rm -rf ~/x >/dev/null"), "deny");
}
