//! A redirection or a quote after `host:` does not defeat the scp system-path rules.
//!
//! `.agent-config-mjtuy`, found by the cold reviewer on `.agent-config-i82og`
//! and pre-existing at 5aeb5359 — `i82og` neither opened nor closed it.
//!
//! Two shapes walked through all seven destructive rules in `remote.scp`:
//!
//! 1. A REDIRECTION between the destination and the end of the segment. The
//!    anchor spelled `;`, `&`, `|` and a newline but not `>` or `<`, and
//!    `move_redirections_to_segment_end` parks a redirection exactly there, so
//!    the destination was never adjacent to the anchor.
//! 2. A QUOTE straight after `host:`. The host prefix consumes `host:` and then
//!    requires a literal `/`, which a `"` or `'` blocks, and
//!    `dequote_segment_command_words` only dequotes command WORDS, not
//!    arguments. The shell removes the quotes, so the copy really happens.
//!
//! Each case below was measured ALLOWED on a release build of 5aeb5359 before
//! the fix. Every one is paired with a control — the same command without the
//! redirection, or without the quotes — that denied on the SAME rule both
//! before and after, so a run where the pack is not reached fails on the control
//! rather than passing silently.
//!
//! These cases cannot live in `tests/corpus/`. That harness runs
//! `Config::default()`, which does not enable the `remote` pack, so every case
//! here would pass by never being evaluated — green over nothing.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// The rule that denied `command`, or `None` when it was allowed.
///
/// Returns the rule NAME, not just a bool: a case that denies on a different
/// rule than the one its destination names is a different bug, and a bool would
/// hide it.
fn denying_rule(command: &str) -> Option<String> {
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

    let result = evaluate_command_with_pack_order(
        command,
        &keywords,
        &ordered,
        Some(&index),
        &overrides,
        &allowlists,
        &heredoc,
        config.policy(),
    );

    if !result.is_denied() {
        return None;
    }
    Some(
        result
            .pattern_info
            .as_ref()
            .and_then(|p| p.pattern_name.clone())
            .expect("a denial from this pack always names its rule"),
    )
}

/// Assert `command` denies, and denies on `rule`.
///
/// Presence first, then the value: asserting only the name would let a command
/// that is ALLOWED fail with a confusing message instead of the true one.
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

/// The seven destructive rules, each with a destination it names and a rule
/// name. One row per rule family; every test below walks all seven.
const FAMILIES: &[(&str, &str, &str)] = &[
    // (flags before the destination, destination path, rule name)
    ("-r ", "/", "scp-recursive-root"),
    ("", "/etc/x", "scp-to-etc"),
    ("", "/var/lib/x", "scp-to-var"),
    ("", "/boot/x", "scp-to-boot"),
    ("", "/usr/bin/x", "scp-to-usr"),
    ("", "/sbin/x", "scp-to-bin"),
    ("", "/lib64/x", "scp-to-lib"),
];

/// The control for every case below: the plain form denies on the named rule.
///
/// If this goes red the harness is not reaching `remote.scp` at all, and every
/// other assertion in this file is green over nothing.
#[test]
fn the_plain_form_denies_on_the_rule_its_destination_names() {
    for (flags, dest, rule) in FAMILIES {
        assert_denies_on(&format!("scp {flags}f host:{dest}"), rule);
    }
}

#[test]
fn a_redirection_does_not_defeat_the_scp_system_path_rules() {
    for (flags, dest, rule) in FAMILIES {
        // A bare `>`: measured ALLOWED on 5aeb5359.
        assert_denies_on(&format!("scp {flags}f host:{dest} >log"), rule);
        // An fd-prefixed `2>`, which the anchor's separator class cannot reach
        // even with `>` in it, because the fd digit sits between the two.
        assert_denies_on(&format!("scp {flags}f host:{dest} 2>/dev/null"), rule);
        // An input redirection.
        assert_denies_on(&format!("scp {flags}f host:{dest} <in"), rule);
        // The bead's own shape: the redirection hid the newline segment end, so
        // the two-line block an agent actually writes was allowed.
        assert_denies_on(
            &format!("scp {flags}f host:{dest} 2>/dev/null\necho ok"),
            rule,
        );
    }
}

#[test]
fn a_quote_after_the_host_colon_does_not_defeat_the_scp_system_path_rules() {
    for (flags, dest, rule) in FAMILIES {
        // Double and single quotes around the whole remote path.
        assert_denies_on(&format!("scp {flags}f host:\"{dest}\""), rule);
        assert_denies_on(&format!("scp {flags}f host:'{dest}'"), rule);
        // A quote that closes after the directory name and reopens nothing --
        // `host:"/etc"/x`. The trailing `["']*` is what reaches this one; a fix
        // that only absorbed a quote straight after the colon would not.
        // `/var/lib/x` -> ("/var", "/lib/x"); "/" -> ("/", "").
        let head_len = 1 + dest[1..].find('/').unwrap_or(dest.len() - 1);
        let (head, tail) = dest.split_at(head_len);
        if !tail.is_empty() {
            assert_denies_on(&format!("scp {flags}f host:\"{head}\"{tail}"), rule);
        }
        // With a newline segment end behind it, the shape the bead names.
        assert_denies_on(&format!("scp {flags}f host:\"{dest}\"\necho ok"), rule);
    }
}

/// Both shapes at once: a quoted destination whose output is also redirected.
#[test]
fn a_quote_and_a_redirection_together_still_deny() {
    for (flags, dest, rule) in FAMILIES {
        assert_denies_on(&format!("scp {flags}f host:\"{dest}\" 2>/dev/null"), rule);
    }
}

/// The fix must not widen what counts as a destination.
///
/// Every row here was ALLOWED before the fix and must stay ALLOWED. The first
/// two are the checks the bead names by hand.
#[test]
fn the_fix_does_not_widen_what_counts_as_a_destination() {
    // A DOWNLOAD from a system path, quoted. The remote path is the source, not
    // the destination; `.` is the destination.
    assert_allows("scp host:\"/etc/hosts\" .");
    assert_allows("scp host:/etc/hosts .");
    assert_allows("scp -P 22 user@host:\"/etc/ssh/sshd_config\" .");
    // A quote inside a SAFE destination is still safe.
    assert_allows("scp f host:/tmp/\"x\"");
    assert_allows("scp f host:\"/tmp/x\"");
    assert_allows("scp f user@host:~/docs/");
    assert_allows("scp f host:/var/tmp/x");
    // A home or /tmp destination with a redirection is still safe: the safe
    // rules end at `$`, and no destructive rule names these paths.
    assert_allows("scp f host:/tmp/x >log");
    assert_allows("scp f user@host:~/docs/ 2>/dev/null");
    // A recursive copy to a non-root destination.
    assert_allows("scp -r ./project user@host:/home/user/projects/");
}

/// Why the SAFE rules were deliberately not given the same redirection anchor.
///
/// Widening them would make a safe span run up to the operator, and a span
/// starts at the command word -- so it would exempt a destructive match that
/// starts there too. These rows deny today (measured on a release build of
/// 5aeb5359) and must keep denying, which is what makes the widening unsafe.
///
/// The space used to matter here: the destructive rule reaches its path through
/// `\s`, so `> /etc/passwd` denied while the glued `>/etc/passwd` did not.
/// `.agent-config-fhj4b` closed that in `split_glued_redirections`, which now
/// restores the word break on BOTH sides of the operator, so the two spellings
/// normalize to the same text and deny alike. Both forms are pinned in
/// tests/repro_glued_redirection_target.rs; the rows below stay spaced because
/// the property THIS test exists for is the safe-span one, and the spaced form
/// is what it was measured on.
#[test]
fn a_redirection_into_a_system_path_still_denies_behind_a_safe_destination() {
    assert_denies_on("scp f host:/var/tmp/x > /etc/passwd", "scp-to-etc");
    assert_denies_on("scp f host:/tmp/x > /etc/passwd", "scp-to-etc");
}

/// The cost this fix accepts, recorded so it is not rediscovered by surprise.
///
/// `/var/tmp` is a safe destination carved out of the destructive `/var` rule by
/// a safe rule that ends at `$`. Now that the destructive rule also ends at a
/// redirection, a redirected copy to `/var/tmp` reaches `scp-to-var` before the
/// safe rule can cover it. Both rows were ALLOWED on 5aeb5359.
///
/// `.agent-config-5udyd` re-measured this and left it standing. It widened the
/// four safe anchors to the separator class (`;`, `&`, `|`, a newline), which
/// cleared the `;`-separated false deny `.agent-config-i82og` had accepted, but
/// deliberately NOT to a redirection: a separator cannot be crossed by a
/// destructive rule's `[^;&|\n]*` while `>` can, so a safe span reaching a
/// redirection would exempt the match that reaches its target — the M3 mutant
/// above. The two rows below are the price of keeping that shut, and they stay
/// green through 5udyd rather than going red as this comment once predicted.
#[test]
fn a_redirected_copy_to_var_tmp_is_the_accepted_false_deny() {
    assert_denies_on("scp f host:/var/tmp/x 2>/dev/null", "scp-to-var");
    assert_denies_on("scp f host:/var/tmp/x >log", "scp-to-var");
}
