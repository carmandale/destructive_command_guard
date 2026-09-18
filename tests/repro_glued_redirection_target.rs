//! A glued redirection target is a word, and the rules that read words see it.
//!
//! `.agent-config-fhj4b`, found while fixing `.agent-config-mjtuy` and
//! pre-existing at 54c97732 -- mjtuy neither opened nor closed it.
//!
//! `split_glued_redirections` restored the word break an unquoted `>`/`<` makes
//! in FRONT of the operator (`.agent-config-6yt2i`, so the command word stayed
//! visible) but never behind it. The shell ends a word on both sides, so
//! `>/etc/passwd` is two tokens; the guard saw one. Any pattern that reaches a
//! path through `\s` -- every destructive rule in `remote.scp`, and
//! `database.sqlite`'s `sqlite3-stdin` -- therefore matched the SPACED spelling
//! and missed the glued one, though the shell runs them identically and both
//! truncate the target.
//!
//! Every glued row below was measured ALLOWED on a release build of 54c97732,
//! and every spaced row BLOCKED on that same build. The spaced rows are the
//! controls: they denied before this fix and must keep denying, so a run where
//! the harness fails to reach the pack goes red on the control instead of
//! passing silently.
//!
//! These cases cannot live in `tests/corpus/`. That harness runs
//! `Config::default()`, which enables neither `remote` nor `database`, so every
//! case here would pass by never being evaluated -- green over nothing.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// The rule that denied `command` with `packs` enabled, or `None` if allowed.
fn denying_rule_with(packs: &[&str], command: &str) -> Option<String> {
    let config = Config::default();
    let enabled: HashSet<String> = packs.iter().map(|s| (*s).to_string()).collect();
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
    Some(
        result
            .pattern_info
            .as_ref()
            .and_then(|p| p.pattern_name.clone())
            .expect("a denial from these packs always names its rule"),
    )
}

/// `core` + `remote` is the shape this machine actually runs.
fn denying_rule(command: &str) -> Option<String> {
    denying_rule_with(&["core", "remote"], command)
}

#[track_caller]
fn assert_denies_on(command: &str, rule: &str) {
    let got = denying_rule(command);
    assert!(
        got.is_some(),
        "expected {command:?} to be DENIED by {rule}, but it was ALLOWED"
    );
    assert_eq!(
        got.as_deref(),
        Some(rule),
        "expected {command:?} to be denied by {rule}"
    );
}

#[track_caller]
fn assert_allows(command: &str) {
    let got = denying_rule(command);
    assert_eq!(
        got, None,
        "expected {command:?} to be ALLOWED, but rule {got:?} denied it"
    );
}

/// Every pair: the glued spelling and the spaced one deny on the SAME rule.
///
/// The spaced half is the control. It denied on 54c97732 too, so if the harness
/// stops reaching `remote.scp` this test fails on the control rather than
/// reporting the glued half as fixed.
#[test]
fn a_glued_redirection_target_denies_on_the_rule_the_target_names() {
    for (glued, spaced, rule) in [
        (
            "scp f host:/tmp/x >/etc/passwd",
            "scp f host:/tmp/x > /etc/passwd",
            "scp-to-etc",
        ),
        (
            "scp f host:/home/u/x >/boot/vmlinuz",
            "scp f host:/home/u/x > /boot/vmlinuz",
            "scp-to-boot",
        ),
        (
            "scp f host:/home/u/x 2>/usr/bin/ld",
            "scp f host:/home/u/x 2> /usr/bin/ld",
            "scp-to-usr",
        ),
        (
            "scp f host:/home/u/x >>/var/log/syslog",
            "scp f host:/home/u/x >> /var/log/syslog",
            "scp-to-var",
        ),
        (
            "scp f host:/home/u/x >/sbin/init",
            "scp f host:/home/u/x > /sbin/init",
            "scp-to-bin",
        ),
        (
            "scp f host:/home/u/x >/lib64/libc.so",
            "scp f host:/home/u/x > /lib64/libc.so",
            "scp-to-lib",
        ),
    ] {
        assert_denies_on(spaced, rule);
        assert_denies_on(glued, rule);
    }
}

/// The same gap, in a different pack, closed by the same one-line change.
///
/// `sqlite3-stdin` spells `sqlite3\s+[^\s]+\s+<\s+` -- whitespace on BOTH sides
/// of the operator -- so the glued spelling ran the SQL file unreviewed. This is
/// the measured reason the fix belongs in the normalizer and not in the seven
/// scp rules.
#[test]
fn the_same_gap_in_the_sqlite_pack_closes_too() {
    let packs = ["core", "database"];
    // The control: spaced denied before this fix and still does.
    assert_eq!(
        denying_rule_with(&packs, "sqlite3 mydb.db < dump.sql").as_deref(),
        Some("sqlite3-stdin"),
        "the spaced control must deny, or this test proves nothing"
    );
    // The subject: glued was ALLOWED on 54c97732.
    assert_eq!(
        denying_rule_with(&packs, "sqlite3 mydb.db <dump.sql").as_deref(),
        Some("sqlite3-stdin")
    );
}

/// A redirection target that is NOT a system path stays allowed.
///
/// Spacing the target apart must not turn every redirection into a destination.
#[test]
fn an_ordinary_redirection_target_is_still_allowed() {
    assert_allows("scp f host:/tmp/x >log");
    assert_allows("scp f host:/tmp/x > log");
    assert_allows("scp f host:/tmp/x 2>/dev/null");
    assert_allows("scp f host:/home/u/x >out.txt");
    assert_allows("scp f user@host:~/docs/ >>build.log");
}

/// The bytes after the operator that must not be spaced apart.
///
/// A space inside `2>&1`, `>(bash)` or `>|out` would change what the text means
/// rather than reveal it. These are verdict-level rows; the byte-level contract
/// is `normalize::glued_redirection_tests`.
#[test]
fn fd_duplication_and_process_substitution_are_untouched() {
    assert_allows("scp f host:/home/u/x 2>&1");
    assert_allows("scp f host:/home/u/x >&2");
    assert_allows("scp f host:/home/u/x 1>&2 2>&1");
    assert_allows("tee >(cat) >/dev/null");
    assert_allows("echo hi >|out");
}

/// mjtuy's fix keeps working: a redirection is still a segment end for the
/// destination rules, now that the operator and its target are two words.
#[test]
fn the_mjtuy_anchor_still_denies_a_copy_to_a_system_path() {
    assert_denies_on("scp f host:/etc/x >log", "scp-to-etc");
    assert_denies_on("scp f host:/etc/x 2>/dev/null", "scp-to-etc");
    assert_denies_on("scp f host:\"/etc/x\" 2>/dev/null", "scp-to-etc");
}
