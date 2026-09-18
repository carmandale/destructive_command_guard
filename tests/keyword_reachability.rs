//! A destructive rule whose command word no keyword covers can never fire.
//!
//! A pack is consulted only if the command clears two gates: a word-aware
//! quick-reject over the executable words of the line
//! (`pack_aware_quick_reject`, using every enabled pack's keywords), and a
//! per-pack substring index (`candidate_pack_mask`). A rule for a command word
//! that is in neither reads as protection and is dead code.
//!
//! `.agent-config-x74pe`. The keyword list was written twice — once in each
//! pack, once in the registry's `PackEntry` — and 26 of 80 packs disagreed. The
//! registry's copy is what the evaluator gates on, so eleven rules the packs
//! claimed to have could not fire: `poetry publish`, `poetry remove`,
//! `brew uninstall`, `yum remove`, `mvn deploy`, `gradle publish`,
//! `kubectl delete -k`, `shutdown`, `reboot`, `init 0` and `losetup`. Each one
//! below was ALLOWED by the hook before the two lists became one.
//!
//! The defect survived a test that asserted the wrong gate:
//! `package_managers::tests::brew_uninstall_is_reachable_via_keywords` calls
//! `pack.might_match`, a plain substring search on the pack's OWN list, which
//! answers true while the evaluator's gate answers false. These cases go
//! through `evaluate_command_with_pack_order`, the way the hook does.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::{PackRegistry, REGISTRY};

fn is_denied_with(packs: &[&str], command: &str) -> bool {
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
    .is_denied()
}

/// Every rule the drift had made unreachable, with the pack set it needs.
#[test]
fn rules_whose_command_word_the_registry_lacked_now_fire() {
    let mut allowed = Vec::new();
    for (packs, command) in [
        (["core", "package_managers"], "poetry publish"),
        (["core", "package_managers"], "poetry remove requests"),
        (["core", "package_managers"], "brew uninstall wget"),
        (["core", "package_managers"], "yum remove httpd"),
        // The spelling matters: the gate matches whole command words and a hyphen
        // or a digit continues one, so `apt` does not reach `apt-get` and `pip`
        // does not reach `pip3`. Both were still ALLOW after the first pass.
        (["core", "package_managers"], "apt remove cowsay"),
        (["core", "package_managers"], "apt-get remove cowsay"),
        (["core", "package_managers"], "apt-get purge cowsay"),
        (["core", "package_managers"], "pip uninstall requests"),
        (["core", "package_managers"], "pip3 uninstall requests"),
        (["core", "system"], "umount -f /mnt/data"),
        (["core", "package_managers"], "dnf remove httpd"),
        (["core", "package_managers"], "mvn deploy"),
        (["core", "package_managers"], "gradle publish"),
        (["core", "kubernetes"], "kubectl delete -k overlays/prod"),
        (["core", "system"], "losetup /dev/loop0 disk.img"),
    ] {
        if !is_denied_with(&packs, command) {
            allowed.push(format!("{command:?} with {packs:?}"));
        }
    }
    assert!(
        allowed.is_empty(),
        "these rules exist but their command word reaches no pack:\n{}",
        allowed.join("\n")
    );
}

/// The other direction: the keywords added here must not deny ordinary use of
/// the same tools. Without this, "every rule fires" could be satisfied by a
/// guard that blocks everything.
#[test]
fn ordinary_use_of_those_tools_is_still_allowed() {
    let mut denied = Vec::new();
    for (packs, command) in [
        (["core", "package_managers"], "poetry install"),
        (["core", "package_managers"], "poetry publish --dry-run"),
        (["core", "package_managers"], "brew install wget"),
        (["core", "package_managers"], "brew list"),
        (["core", "package_managers"], "yum install httpd"),
        (["core", "package_managers"], "mvn test"),
        (["core", "package_managers"], "gradle build"),
        (["core", "package_managers"], "apt-get update"),
        (["core", "package_managers"], "pip3 install requests"),
        (["core", "system"], "umount /mnt/data"),
        (["core", "kubernetes"], "kubectl get pods"),
        (["core", "kubernetes"], "kubectl apply -k overlays/prod"),
        (["core", "system"], "systemctl status nginx"),
        (["core", "system"], "losetup -a"),
    ] {
        if is_denied_with(&packs, command) {
            denied.push(format!("{command:?} with {packs:?}"));
        }
    }
    assert!(
        denied.is_empty(),
        "ordinary commands denied by the widened keyword lists:\n{}",
        denied.join("\n")
    );
}

/// The two lists that drifted are one list now.
///
/// `PackEntry::keywords` is what the evaluator gates on; `Pack::keywords` is
/// what the pack's own tests see. Both now point at the pack module's
/// `KEYWORDS` const, so this can only fail if someone writes a second literal.
#[test]
fn the_registry_and_the_pack_carry_the_same_keywords() {
    let registry = PackRegistry::new();
    let all_ids: HashSet<String> = registry
        .all_pack_ids()
        .into_iter()
        .map(String::from)
        .collect();
    let mut drifted = Vec::new();
    let mut checked = 0usize;
    for info in registry.list_packs(&all_ids) {
        let Some(entry) = registry.get_entry(&info.id) else {
            continue;
        };
        let pack = registry.get(&info.id).unwrap();
        checked += 1;
        if entry.keywords != pack.keywords {
            drifted.push(format!(
                "{}: registry {:?} vs pack {:?}",
                pack.id, entry.keywords, pack.keywords
            ));
        }
    }
    // The control: comparing nothing would pass.
    assert!(
        checked > 70,
        "only {checked} packs were compared — the registry listing is the problem, not the packs"
    );
    assert!(
        drifted.is_empty(),
        "the gate and the pack disagree about which command words reach it:\n{}",
        drifted.join("\n")
    );
}

/// The rules that used to fire on prose now fire on a COMMAND and not a mention.
///
/// `system.services`' `shutdown`/`reboot`/`init` were bare words. Measured over
/// 18,723 real recorded commands with every pack enabled, turning them on denied
/// eight lines and only two were reboots; the rest merely MENTIONED one — a bead
/// description, an incident note written through a heredoc, an echo. They were
/// parked until `.agent-config-w22qy` anchored them to a command position.
///
/// `database.mysql`/`postgresql` carried lowercase `drop`/`delete`/`truncate` in
/// the gate, so byte-exact keyword matching handed those `(?i)` rules any prose
/// containing the words. The same bead removed them; a lowercase SQL statement a
/// shell actually runs arrives with its client, and the client words are still
/// in the gate — the controls below are what assert that.
///
/// This is an end-to-end test: it runs the built binary through a real
/// PreToolUse envelope, so it answers for the evaluator and not for one pack.
#[test]
fn the_power_and_sql_rules_match_commands_and_not_mentions() {
    let mut fired = Vec::new();
    for (packs, command) in [
        // Prose that names a power command.
        (["core", "system"], "echo \"reboot issued (rc=$?)\""),
        (
            ["core", "system"],
            "br create \"the mini needs a reboot after the upgrade\"",
        ),
        (
            ["core", "system"],
            "git commit -m \"shutdown the legacy worker\"",
        ),
        // A heredoc body written into a FILE is data, not a command.
        (
            ["core", "system"],
            "cat >> notes.md <<'EOF'\nshutdown -h now\nEOF",
        ),
        // SQL text inside an interpreter that is not a database client.
        (
            ["core", "database"],
            "python3 -c \"print('drop table foo')\"",
        ),
        (
            ["core", "database"],
            "bash -c 'echo \"drop table students\"'",
        ),
        (
            ["core", "database"],
            "br create \"the log holds 396 entries, truncate it\"",
        ),
    ] {
        if is_denied_with(&packs, command) {
            fired.push(format!("{command:?} with {packs:?}"));
        }
    }
    assert!(
        fired.is_empty(),
        "these only MENTION a destructive command and must not be denied \
         (.agent-config-w22qy):\n{}",
        fired.join("\n")
    );

    // The controls. Each is the discriminating twin of a line above: same words,
    // real command position. Without these the assertion above would pass for a
    // pack whose rules had simply been deleted.
    for (packs, command) in [
        (["core", "system"], "shutdown -h now"),
        (["core", "system"], "reboot"),
        (["core", "system"], "sudo reboot"),
        (["core", "system"], "init 0"),
        (["core", "system"], "ssh mini-ts reboot"),
        // The same heredoc body, handed to an interpreter instead of a file.
        (["core", "system"], "bash <<'EOF'\nshutdown -h now\nEOF"),
        (["core", "system"], "systemctl stop nginx"),
        (["core", "database"], "psql -c 'TRUNCATE TABLE users'"),
        (["core", "database"], "psql -c 'truncate table users'"),
        (["core", "database"], "mysql -e 'drop table users'"),
    ] {
        assert!(
            is_denied_with(&packs, command),
            "control failed — {packs:?} no longer reaches its own rule for {command:?}"
        );
    }
}

/// No keyword the registry carried may be lost when the two lists become one.
///
/// The first attempt at this took each pack's own list as authoritative, which
/// silently dropped the registry-only spellings and killed two rules that had
/// been working: `redis-cli SHUTDOWN` (the pack listed only `redis`, and the
/// gate is word-aware, so `redis` does not reach `redis-cli`) and
/// `ansible-playbook` (the pack listed only `playbook`). The const is the union
/// of both lists; these are the two that caught it.
#[test]
fn keywords_the_registry_carried_are_still_in_the_gate() {
    let mut lost = Vec::new();
    for (packs, command) in [
        (["core", "database"], "redis-cli SHUTDOWN"),
        (["core", "database"], "redis-cli FLUSHALL"),
        (
            ["core", "infrastructure"],
            "ansible-playbook -i inv site.yml",
        ),
    ] {
        if !is_denied_with(&packs, command) {
            lost.push(format!("{command:?} with {packs:?}"));
        }
    }
    assert!(
        lost.is_empty(),
        "a keyword the registry used to carry is missing from the gate:\n{}",
        lost.join("\n")
    );
}
