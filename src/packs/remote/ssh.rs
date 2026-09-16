//! `ssh` pack - protections for destructive SSH operations.
//!
//! Covers destructive CLI operations:
//! - Remote execution of destructive commands via SSH
//! - SSH known hosts removal
//! - SSH key deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `ssh` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "remote.ssh".to_string(),
        name: "ssh",
        description: "Protects against destructive SSH operations like remote command execution and key management.",
        keywords: &["ssh", "ssh-keygen", "ssh-keyscan"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Version checks
        safe_pattern!("ssh-version", r"ssh\s+-V\b"),
        safe_pattern!("ssh-version-long", r"ssh\s+--version\b"),
        // Key fingerprint listing (read-only)
        safe_pattern!("ssh-keygen-list", r"ssh-keygen\s+[^;&|\n]*-l\b"),
        safe_pattern!("ssh-keygen-fingerprint", r"ssh-keygen\s+[^;&|\n]*-lf?\b"),
        // Key scanning (read-only)
        safe_pattern!("ssh-keyscan", r"ssh-keyscan\b"),
        // SSH agent operations (typically safe)
        safe_pattern!("ssh-add-list", r"ssh-add\s+-[lL]\b"),
        safe_pattern!("ssh-agent", r"ssh-agent\b"),
        // Help
        safe_pattern!("ssh-help", r"ssh\s+--?h(elp)?\b"),
        safe_pattern!("ssh-keygen-help", r"ssh-keygen\s+--?h(elp)?\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Remote execution of destructive commands through SSH
        // Matches: ssh host 'rm -rf ...', ssh user@host "git reset --hard", etc.
        destructive_pattern!(
            "ssh-remote-rm-rf",
            r#"ssh\s+(?:'[^']*'|"[^"]*"|[^;&|\n'"])*(?:[^\S\n]\$?['"][^'"]*)?\brm\s+-[a-zA-Z]*r[a-zA-Z]*f"#,
            "SSH remote execution contains destructive rm -rf command.",
            Critical,
            "Executing rm -rf on a remote system via SSH can cause irreversible data loss. \
             Remote systems often have different directory structures and you may not have \
             the same safety mechanisms in place.\n\n\
             Safer alternatives:\n\
             - SSH in and run commands interactively with confirmation\n\
             - Use --dry-run or preview flags when available\n\
             - Ensure backups exist on the remote system"
        ),
        destructive_pattern!(
            "ssh-remote-git-reset-hard",
            r#"ssh\s+(?:'[^']*'|"[^"]*"|[^;&|\n'"])*(?:[^\S\n]\$?['"][^'"]*)?\bgit\s+reset\s+--hard\b"#,
            "SSH remote execution contains destructive git reset --hard command.",
            High,
            "Running git reset --hard on a remote server discards all uncommitted changes. \
             On production servers, this might destroy deployment state or configuration \
             changes made directly on the server.\n\n\
             Safer alternatives:\n\
             - git stash on the remote first to save changes\n\
             - Use git status remotely to check for uncommitted work\n\
             - Consider proper deployment pipelines instead of direct remote git"
        ),
        destructive_pattern!(
            "ssh-remote-git-clean",
            r#"ssh\s+(?:'[^']*'|"[^"]*"|[^;&|\n'"])*(?:[^\S\n]\$?['"][^'"]*)?\bgit\s+clean\s+-[a-zA-Z]*f"#,
            "SSH remote execution contains destructive git clean -f command.",
            High,
            "Running git clean -f on a remote server permanently removes untracked files. \
             This might delete logs, uploads, or configuration files that were never \
             committed to the repository.\n\n\
             Safer alternatives:\n\
             - Run git clean -n first to preview what would be deleted\n\
             - Use .gitignore to protect important untracked files\n\
             - Back up untracked files before cleaning"
        ),
        // Known hosts removal
        destructive_pattern!(
            "ssh-keygen-remove-host",
            r"ssh-keygen[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*-R\b",
            "ssh-keygen -R removes entries from known_hosts file.",
            Medium,
            "Removing entries from known_hosts weakens protection against man-in-the-middle \
             attacks. The next connection will trust any key presented by the remote host.\n\n\
             Safer alternatives:\n\
             - Verify the new host key fingerprint before removing old entry\n\
             - Use ssh-keyscan to preview the new key\n\
             - Update entry rather than removing (add new key, then remove old)"
        ),
        // SSH key deletion
        destructive_pattern!(
            "ssh-add-delete-all",
            r"ssh-add\s+-[dD]\b",
            "ssh-add -d/-D removes identities from the SSH agent.",
            Medium,
            "Removing SSH identities from the agent will require re-authentication for \
             subsequent connections. Using -D removes ALL identities, which may interrupt \
             active sessions or scripts.\n\n\
             Safer alternatives:\n\
             - Use -d to remove specific keys rather than -D for all\n\
             - List keys with ssh-add -l before removing\n\
             - Re-add keys immediately if needed"
        ),
        // Remote sudo operations (high risk)
        destructive_pattern!(
            "ssh-remote-sudo-rm",
            r#"ssh\s+(?:'[^']*'|"[^"]*"|[^;&|\n'"])*(?:[^\S\n]\$?['"][^'"]*)?\bsudo\s+rm\b"#,
            "SSH remote execution with sudo rm is high-risk.",
            Critical,
            "Executing sudo rm on a remote system bypasses normal permission restrictions \
             and can delete system files. Combined with SSH, there's no interactive \
             confirmation and errors may not be visible.\n\n\
             Safer alternatives:\n\
             - SSH in and run sudo commands interactively\n\
             - Use mv to a backup location instead of rm\n\
             - Implement proper cleanup scripts with safety checks"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "remote.ssh");
        assert_eq!(pack.name, "ssh");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"ssh"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Version checks
        assert_safe_pattern_matches(&pack, "ssh -V");
        assert_safe_pattern_matches(&pack, "ssh --version");
        // Key listing
        assert_safe_pattern_matches(&pack, "ssh-keygen -l");
        assert_safe_pattern_matches(&pack, "ssh-keygen -lf ~/.ssh/id_rsa.pub");
        // Key scanning
        assert_safe_pattern_matches(&pack, "ssh-keyscan github.com");
        // Agent operations
        assert_safe_pattern_matches(&pack, "ssh-add -l");
        assert_safe_pattern_matches(&pack, "ssh-add -L");
        assert_safe_pattern_matches(&pack, "ssh-agent");
        // Help
        assert_safe_pattern_matches(&pack, "ssh --help");
        assert_safe_pattern_matches(&pack, "ssh -h");
        assert_safe_pattern_matches(&pack, "ssh-keygen --help");
        // Interactive session (not matched by destructive patterns)
        assert_allows(&pack, "ssh user@host");
        assert_allows(&pack, "ssh -i key.pem user@host");
        // Safe remote commands
        assert_allows(&pack, "ssh user@host 'ls -la'");
        assert_allows(&pack, "ssh user@host 'cat /etc/hostname'");
    }

    #[test]
    fn blocks_remote_rm_rf() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'rm -rf /tmp/data'",
            "ssh-remote-rm-rf",
        );
        assert_blocks_with_pattern(&pack, "ssh host \"rm -rf ./build\"", "ssh-remote-rm-rf");
        assert_blocks_with_pattern(
            &pack,
            "ssh -i key.pem user@host 'rm -rf /var/log'",
            "ssh-remote-rm-rf",
        );
    }

    #[test]
    fn blocks_remote_git_destructive() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'git reset --hard HEAD'",
            "ssh-remote-git-reset-hard",
        );
        assert_blocks_with_pattern(
            &pack,
            "ssh host \"cd repo && git reset --hard\"",
            "ssh-remote-git-reset-hard",
        );
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'git clean -fd'",
            "ssh-remote-git-clean",
        );
    }

    #[test]
    fn blocks_keygen_remove_host() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "ssh-keygen -R hostname", "ssh-keygen-remove-host");
        assert_blocks_with_pattern(
            &pack,
            "ssh-keygen -f ~/.ssh/known_hosts -R 192.168.1.1",
            "ssh-keygen-remove-host",
        );
    }

    #[test]
    fn blocks_ssh_add_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "ssh-add -d", "ssh-add-delete-all");
        assert_blocks_with_pattern(&pack, "ssh-add -D", "ssh-add-delete-all");
    }

    #[test]
    fn blocks_piped_destructive() {
        let pack = create_pack();
        // Piped commands with ssh and rm -rf are caught by ssh-remote-rm-rf
        assert_blocks_with_pattern(
            &pack,
            "cat script.sh | ssh host rm -rf /data",
            "ssh-remote-rm-rf",
        );
    }

    #[test]
    fn blocks_remote_sudo_rm() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh root@host 'sudo rm /etc/passwd'",
            "ssh-remote-sudo-rm",
        );
    }

    /// `.agent-config-1k7w1`. One row per remote-execution rule: the rule name,
    /// a command it must still deny, and the bare verb that must NOT be read as
    /// remote once a command separator sits in front of it.
    ///
    /// The table is the coupling. The narrowed gap is spelled out in four
    /// separate literals, because `destructive_pattern!` takes a `literal` and
    /// will not accept `concat!`, and `every_remote_execution_rule_has_a_row`
    /// reds when a new rule arrives without one.
    const REMOTE_EXECUTION_RULES: &[(&str, &str, &str)] = &[
        (
            "ssh-remote-rm-rf",
            "ssh host rm -rf /tmp/x",
            "rm -rf /tmp/x",
        ),
        (
            "ssh-remote-git-reset-hard",
            "ssh host 'git reset --hard'",
            "git reset --hard",
        ),
        (
            "ssh-remote-git-clean",
            "ssh host 'git clean -fd'",
            "git clean -fd",
        ),
        (
            "ssh-remote-sudo-rm",
            "ssh host 'sudo rm /etc/x'",
            "sudo rm /etc/x",
        ),
    ];

    #[test]
    fn every_remote_execution_rule_has_a_row() {
        let pack = create_pack();
        let remote_rules: Vec<&str> = pack
            .destructive_patterns
            .iter()
            .filter_map(|p| p.name)
            .filter(|name| name.starts_with("ssh-remote-"))
            .collect();
        assert!(
            !remote_rules.is_empty(),
            "no remote-execution rules found, so this coverage check proves nothing"
        );
        for name in remote_rules {
            assert!(
                REMOTE_EXECUTION_RULES
                    .iter()
                    .any(|(rule, _, _)| *rule == name),
                "remote-execution rule '{name}' has no row in REMOTE_EXECUTION_RULES, \
                 so nothing proves its gap cannot cross a command separator"
            );
        }
    }

    /// The defect. The gap between `ssh` and the destructive verb used to be
    /// `(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*`, and every piece of
    /// that crosses `;`, `&&`, `||`, `|` and a newline, so a LOCAL command after
    /// an ssh command read as a remote one.
    ///
    /// These call `matches_destructive`, never `check`. `check` consults the
    /// safe patterns first, so a command carrying `ssh-keygen -lf` comes back
    /// allowed on the strength of `ssh-keygen-fingerprint` while the destructive
    /// rule still matches underneath it — green over nothing.
    #[test]
    fn a_local_verb_after_a_separator_is_not_a_remote_one() {
        let pack = create_pack();
        for (rule, _, local_verb) in REMOTE_EXECUTION_RULES {
            for sep in ["&&", "||", ";", "|", "\n"] {
                let command = format!("ssh host uptime {sep} {local_verb}");
                assert!(
                    pack.matches_destructive(&command).is_none(),
                    "rule {rule} reached across {sep:?} to a local command: \
                     {command:?} matched {:?}",
                    pack.matches_destructive(&command).and_then(|m| m.name),
                );
            }
        }
    }

    /// The other direction: narrowing the gap must not let a genuinely remote
    /// destructive command through.
    #[test]
    fn a_remote_destructive_command_still_denies() {
        let pack = create_pack();
        for (rule, remote_command, _) in REMOTE_EXECUTION_RULES {
            assert_eq!(
                pack.matches_destructive(remote_command)
                    .and_then(|m| m.name),
                Some(*rule),
                "{remote_command:?} must still match {rule}"
            );
        }
    }

    /// The quoting edges the narrowing could plausibly have broken, both ways.
    #[test]
    fn the_quoting_edges_of_the_narrowed_gap() {
        let pack = create_pack();

        // Must still DENY: the remote command is inside the quotes, separators
        // and all, and a quoted option before the host must not break the reach.
        for (command, expected) in [
            ("ssh host \"cd /srv && rm -rf build\"", "ssh-remote-rm-rf"),
            ("ssh host \"cd /srv\nrm -rf build\"", "ssh-remote-rm-rf"),
            (
                "ssh -o \"StrictHostKeyChecking=no\" host rm -rf /srv",
                "ssh-remote-rm-rf",
            ),
            ("ssh host $'rm -rf /srv'", "ssh-remote-rm-rf"),
            (
                "ssh -i key.pem user@host 'rm -rf /var/log'",
                "ssh-remote-rm-rf",
            ),
            ("cat script.sh | ssh host rm -rf /data", "ssh-remote-rm-rf"),
        ] {
            assert_eq!(
                pack.matches_destructive(command).and_then(|m| m.name),
                Some(expected),
                "{command:?} must still match {expected}"
            );
        }

        // Must ALLOW: a CLOSED quote belongs to the ssh command, and what follows
        // the separator after it does not. An apostrophe in prose must not open a
        // quote that swallows the separator.
        for command in [
            "ssh host \"uptime\" && rm -rf /tmp/scratch",
            "ssh host 'uptime' ; rm -rf /tmp/scratch",
            "ssh host uptime # don't && rm -rf /tmp/scratch",
            // The command this bead was measured on. This session's own probe
            // was blocked by the live guard for exactly this reason.
            "ssh host uptime && ssh-keygen -lf known || rm -rf /var/tmp/stuff",
        ] {
            assert!(
                pack.matches_destructive(command).is_none(),
                "{command:?} matched {:?}, but its destructive verb is local",
                pack.matches_destructive(command).and_then(|m| m.name),
            );
        }
    }

    /// `ssh-keygen -R` carried the same token walk: `(?:\S+\s+)*` let `-R` be
    /// claimed from a different command. `-R` is destructive wherever it really
    /// belongs to ssh-keygen, so the probe hands it to another command.
    #[test]
    fn ssh_keygen_does_not_claim_a_neighbours_flag() {
        let pack = create_pack();
        for command in [
            "ssh-keygen -lf known_hosts && ssh-keyscan -R example.com",
            "ssh-keygen -lf known_hosts; grep -R pattern .",
            "ssh-keygen -lf known_hosts\ngrep -R pattern .",
        ] {
            assert!(
                pack.matches_destructive(command).is_none(),
                "{command:?} matched {:?}, but that -R belongs to the second command",
                pack.matches_destructive(command).and_then(|m| m.name),
            );
        }
        for command in [
            "ssh-keygen -R hostname",
            "ssh-keygen -f ~/.ssh/known_hosts -R 192.168.1.1",
        ] {
            assert_eq!(
                pack.matches_destructive(command).and_then(|m| m.name),
                Some("ssh-keygen-remove-host"),
                "{command:?} must still match ssh-keygen-remove-host"
            );
        }
    }
}
