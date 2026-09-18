//! A local command after an ssh command is not a remote one.
//!
//! `.agent-config-1k7w1`. The `remote.ssh` destructive rules put
//! `(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*` between `ssh` and the
//! destructive verb. Every piece of that crosses `;`, `&&`, `||`, `|` and a
//! newline, so the gap ran past the end of the ssh command and claimed a verb
//! belonging to a later, LOCAL one. This is `.agent-config-it2wk`'s
//! false-positive arm, left behind in `remote.ssh`.
//!
//! The session that filed the bead had its own probe blocked by the live guard
//! for this reason: `remote.ssh:ssh-remote-rm-rf` fired on a command whose only
//! `rm -rf` was local and, on its own, allowed.
//!
//! These cases cannot live in `tests/corpus/`. That harness runs
//! `Config::default()`, which inserts `core` and nothing else (`src/config.rs`
//! `enabled_pack_ids`), so every case here would pass there having evaluated no
//! ssh rule at all — green over nothing. `tests/repro_safe_pattern_scope.rs` is
//! the neighbouring file with the same constraint.
//!
//! Per-rule coverage, including the deny direction for rules whose local form is
//! destructive anyway, lives in the pack's own tests in `src/packs/remote/ssh.rs`.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// The rule that denied a command, as `pack_id:pattern_name`, or `None` when it
/// was allowed.
///
/// A bare "was it denied" boolean is not enough here. `core` is evaluated before
/// `remote`, and `core.filesystem` denies `ssh host rm -rf /tmp/scratch` all by
/// itself even though bare `rm -rf /tmp/scratch` is allowed. A deny-assertion
/// written on the boolean therefore passes with the `remote` pack switched off
/// entirely, and reports nothing about the rule under test.
fn denying_rule(command: &str) -> Option<String> {
    let result = evaluate(command);
    if !result.is_denied() {
        return None;
    }
    let info = result.pattern_info.as_ref()?;
    Some(format!(
        "{}:{}",
        info.pack_id.as_deref().unwrap_or("<no pack>"),
        info.pattern_name.as_deref().unwrap_or("<unnamed>")
    ))
}

/// Evaluate with `core` + `remote` enabled, the shape this machine actually runs.
fn is_denied(command: &str) -> bool {
    evaluate(command).is_denied()
}

fn evaluate(command: &str) -> destructive_command_guard::evaluator::EvaluationResult {
    let config = Config::default();
    let enabled: HashSet<String> = ["core", "remote"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
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
        &config.confidence,
    )
}

/// The control, and it names the rule. An earlier draft asserted only that
/// `ssh user@host 'rm -rf /tmp/scratch'` was denied — measured through the hook,
/// that denial comes from `core.filesystem:rm-rf-root-home`, so the control
/// would have gone green with `remote` switched off and every allow-assertion
/// below would have been meaningless.
#[test]
fn the_ssh_pack_is_actually_reached() {
    assert_eq!(
        denying_rule("ssh host 'sudo rm -r /tmp/scratch'").as_deref(),
        Some("remote.ssh:ssh-remote-sudo-rm"),
        "remote.ssh is not enabled in this harness, so every allow-assertion in \
         this file would pass without evaluating an ssh rule"
    );
}

/// The other half of the control. Each bare command below has to be ALLOWED on
/// its own — it is what makes the deny cases attributable to `remote.ssh`, and
/// what makes the allow cases fail for the ssh gap rather than for `core`.
#[test]
fn the_bare_local_commands_are_allowed_on_their_own() {
    for command in [
        "rm -rf /var/tmp/stuff",
        "rm -rf /tmp/scratch",
        "sudo rm -r /tmp/scratch",
        "sudo rm /tmp/scratch",
        "ssh-keygen -lf known",
    ] {
        assert!(
            !is_denied(command),
            "{command:?} is denied on its own, so it cannot probe the ssh gap: a \
             deny would be core's and an allow could never happen"
        );
    }
}

/// The command the bead was measured on, verbatim.
#[test]
fn the_reported_false_positive_is_allowed() {
    let command = "ssh host uptime && ssh-keygen -lf known || rm -rf /var/tmp/stuff";
    assert!(
        !is_denied(command),
        "the only rm -rf here is LOCAL and allowed on its own; the ssh gap \
         reached past the separators and claimed it"
    );
}

#[test]
fn a_local_destructive_command_after_ssh_is_allowed() {
    for command in [
        "ssh mini-ts uptime && rm -rf /tmp/scratch",
        "ssh mini-ts uptime; rm -rf /tmp/scratch",
        "ssh mini-ts uptime || rm -rf /tmp/scratch",
        "ssh mini-ts uptime | tee /tmp/log && rm -rf /tmp/scratch",
        "ssh mini-ts uptime\nrm -rf /tmp/scratch",
        "ssh mini-ts \"uptime\" && rm -rf /tmp/scratch",
    ] {
        assert!(
            !is_denied(command),
            "{command:?}: the rm -rf is local, after a command separator"
        );
    }
}

/// The deny direction, attributed to `remote.ssh` rather than to whichever pack
/// happened to answer first.
///
/// These are all `sudo rm` shapes on purpose. `core` runs before `remote`, so a
/// remote `rm -rf` is denied by `core.filesystem` and the evaluator never names
/// the ssh rule — true, and useless as evidence about this fix. The `rm -rf`
/// direction is pinned per-rule against the pack itself in
/// `src/packs/remote/ssh.rs`, where nothing else can answer.
#[test]
fn a_genuinely_remote_destructive_command_still_denies_by_an_ssh_rule() {
    for command in [
        "ssh host 'sudo rm -r /tmp/scratch'",
        "ssh host sudo rm /tmp/scratch",
        "ssh -i key.pem user@host 'sudo rm -r /tmp/scratch'",
        // Recorded in the .agent-config-35ysf landing-cold lane log. The last
        // segment really does run sudo rm on the remote host, so the narrowing
        // must leave both of these denying.
        "ssh -V ; ssh host sudo rm x",
        "ssh-keygen -l -f known ; ssh-keygen -R host ; ssh -V ; ssh host sudo rm -r /data",
        // A second ssh after a separator is still an ssh command.
        "ssh mini-ts uptime && ssh other-host sudo rm -r /tmp/scratch",
    ] {
        assert_eq!(
            denying_rule(command).as_deref(),
            Some("remote.ssh:ssh-remote-sudo-rm"),
            "{command:?}: this sudo rm really does run on the remote host"
        );
    }
}

/// `rm -rf` through ssh must still be blocked end to end, whoever names it.
#[test]
fn a_remote_rm_rf_is_still_blocked_end_to_end() {
    for command in [
        "ssh host rm -rf /tmp/scratch",
        "ssh user@host 'rm -rf /tmp/scratch'",
        "ssh host \"cd /tmp && rm -rf scratch\"",
        "ssh -i key.pem user@host 'rm -rf /tmp/scratch'",
    ] {
        assert!(
            is_denied(command),
            "{command:?}: this rm really does run on the remote host"
        );
    }
}
