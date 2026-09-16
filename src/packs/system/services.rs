//! Services patterns - protections against dangerous service operations.
//!
//! This includes patterns for:
//! - systemctl stop/disable on critical services
//! - service stop on critical services
//! - init system modifications

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Command words that let this pack be consulted at all.
///
/// The registry's `PackEntry` points at this same const. They used to be two
/// lists, and 26 of 80 packs had drifted: the pack claimed a keyword the
/// registry gate did not carry, so rules for those words could never run
/// (`.agent-config-x74pe`).
/// `shutdown`, `reboot` and `init` are here again. They were parked because
/// their rules were bare words (`\bshutdown\b`), and over 18,723 real recorded
/// commands turning them on denied six lines that only MENTIONED a reboot — a
/// bead description, an incident note written through a heredoc — against two
/// that were reboots. `.agent-config-w22qy` anchored the three rules to a
/// command position, which is what a keyword can be trusted to gate again.
///
/// The `ssh` arm of that anchor is not decoration. The two REAL reboots in
/// that population are `ssh -o ConnectTimeout=10 <host> 'sudo -n shutdown -r
/// now'` -- the command word sits inside a quoted remote script, after flags
/// that take their own argument. An anchor without it denies nothing that
/// population actually contains.
/// They need a command-position anchor and heredoc-body masking first:
/// `.agent-config-w22qy` holds that, with the measurement.
pub const KEYWORDS: &[&str] = &[
    "systemctl",
    "service",
    "upstart",
    "shutdown",
    "reboot",
    "init",
];

/// Create the Services pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.services".to_string(),
        name: "Services",
        description: "Protects against dangerous service operations like stopping critical \
                      services and modifying init configuration",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // status commands are safe
        safe_pattern!("systemctl-status", r"systemctl\s+status"),
        safe_pattern!("service-status", r"service\s+\S+\s+status"),
        // list commands are safe
        safe_pattern!(
            "systemctl-list",
            r"systemctl\s+list-(?:units|unit-files|sockets|timers)"
        ),
        // show is safe
        safe_pattern!("systemctl-show", r"systemctl\s+show"),
        // is-active/is-enabled are safe
        safe_pattern!("systemctl-is", r"systemctl\s+is-(?:active|enabled|failed)"),
        // daemon-reload is generally safe
        safe_pattern!("systemctl-reload", r"systemctl\s+daemon-reload"),
        // cat is safe (view unit file)
        safe_pattern!("systemctl-cat", r"systemctl\s+cat"),
        // journalctl is safe (logs)
        safe_pattern!("journalctl", r"\bjournalctl\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // systemctl stop/disable critical services
        destructive_pattern!(
            "systemctl-stop-critical",
            r"systemctl\s+(?:stop|disable|mask)\s+(?:ssh|sshd|network|networking|firewalld|ufw|docker|containerd)",
            "Stopping/disabling critical services can cause system access loss or outage.",
            High,
            "Stopping, disabling, or masking a critical system service can lock you out \
             of the machine or cause cascading failures. For example, stopping sshd severs \
             remote access, stopping networking drops all connections, and stopping docker \
             kills every running container.\n\n\
             Check current state first:\n  \
             systemctl status <service>\n\n\
             If you need to restart rather than stop:\n  \
             systemctl restart <service>"
        ),
        // systemctl stop/disable any service
        destructive_pattern!(
            "systemctl-stop",
            r"systemctl\s+(?:stop|disable|mask)\b",
            "systemctl stop/disable/mask affects service availability. Verify service name.",
            High,
            "Stopping a service immediately terminates it; disabling prevents it from \
             starting at boot; masking makes it impossible to start even manually. Each \
             has different severity and reversibility.\n\n\
             Check what depends on the service:\n  \
             systemctl list-dependencies --reverse <service>\n\n\
             To temporarily stop without disabling:\n  \
             systemctl stop <service>  (restarts on reboot)"
        ),
        // service stop critical
        destructive_pattern!(
            "service-stop-critical",
            r"service\s+(?:ssh|sshd|network|networking|docker)\s+stop",
            "Stopping critical services can cause system access loss.",
            High,
            "The legacy 'service' command stops a critical service immediately. Stopping \
             sshd terminates remote access, stopping networking drops all connections. \
             If you are connected remotely, you may be unable to reconnect.\n\n\
             Check status first:\n  \
             service <name> status\n\n\
             Prefer systemctl on systemd systems:\n  \
             systemctl status <name>"
        ),
        // systemctl isolate (changes runlevel)
        destructive_pattern!(
            "systemctl-isolate",
            r"systemctl\s+isolate",
            "systemctl isolate changes the system state significantly.",
            High,
            "Isolating a target stops all services not required by that target. For \
             example, isolating rescue.target drops to single-user mode, stopping \
             networking, display managers, and most daemons. This is equivalent to \
             changing the runlevel and can be very disruptive.\n\n\
             Check current target:\n  \
             systemctl get-default\n\n\
             List active targets:\n  \
             systemctl list-units --type=target"
        ),
        // systemctl poweroff/reboot/halt
        destructive_pattern!(
            "systemctl-power",
            r"systemctl\s+(?:poweroff|reboot|halt|suspend|hibernate)",
            "systemctl poweroff/reboot/halt will shut down or restart the system.",
            Critical,
            "This immediately initiates a system power state change. Poweroff and halt \
             shut down the machine, reboot restarts it, and suspend/hibernate save state \
             to RAM or disk. Any unsaved work, running processes, or active connections \
             will be interrupted.\n\n\
             Check who is logged in:\n  \
             who\n\n\
             Schedule a graceful shutdown instead:\n  \
             shutdown +5 \"Rebooting for maintenance\""
        ),
        // shutdown command
        destructive_pattern!(
            "shutdown",
            r#"(?:^|[\n;&|])[ \t]*(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?(?:ssh[ \t]+(?:(?:[^'\"\s]+[ \t]+){1,12}?['\"]|(?:-[a-zA-Z](?:[ \t]+\S+)?[ \t]+)*\S+[ \t]+)(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?)?(?:-\S+[ \t]+)*shutdown\b"#,
            "shutdown will power off or restart the system.",
            Critical,
            "The shutdown command powers off or restarts the machine. All running \
             processes receive SIGTERM then SIGKILL, all filesystems are unmounted, \
             and the system goes down. Remote users lose access immediately.\n\n\
             To cancel a pending shutdown:\n  \
             shutdown -c\n\n\
             To schedule with warning:\n  \
             shutdown +10 \"System going down for maintenance\""
        ),
        // reboot command
        destructive_pattern!(
            "reboot",
            r#"(?:^|[\n;&|])[ \t]*(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?(?:ssh[ \t]+(?:(?:[^'\"\s]+[ \t]+){1,12}?['\"]|(?:-[a-zA-Z](?:[ \t]+\S+)?[ \t]+)*\S+[ \t]+)(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?)?(?:-\S+[ \t]+)*reboot\b"#,
            "reboot will restart the system.",
            Critical,
            "Reboot restarts the machine immediately. All processes are terminated, \
             connections are dropped, and the system goes through a full restart cycle. \
             Any unsaved work is lost and services will be briefly unavailable.\n\n\
             Check uptime and load before deciding:\n  \
             uptime\n\n\
             For a delayed reboot with notice:\n  \
             shutdown -r +5 \"Rebooting in 5 minutes\""
        ),
        // init 0/6 (shutdown/reboot)
        destructive_pattern!(
            "init-level",
            r#"(?:^|[\n;&|])[ \t]*(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?(?:ssh[ \t]+(?:(?:[^'\"\s]+[ \t]+){1,12}?['\"]|(?:-[a-zA-Z](?:[ \t]+\S+)?[ \t]+)*\S+[ \t]+)(?:(?:sudo|doas)[ \t]+(?:-\S+[ \t]+)*)?)?(?:-\S+[ \t]+)*init\s+[06]\b"#,
            "init 0 shuts down, init 6 reboots the system.",
            Critical,
            "Changing the init level to 0 halts the system and to 6 reboots it. This \
             is the legacy SysV method for power management and takes effect immediately. \
             All processes are killed and the machine goes down.\n\n\
             On systemd systems, prefer:\n  \
             systemctl poweroff  (instead of init 0)\n  \
             systemctl reboot    (instead of init 6)\n\n\
             Check current runlevel:\n  \
             runlevel"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three power rules fire on a COMMAND and not on a mention of one.
    ///
    /// They were parked (`.agent-config-w22qy`) because the rules were bare
    /// words: over 18,723 real recorded commands, turning them on denied six
    /// lines that only MENTIONED a reboot against two that were reboots. The
    /// rules are now anchored to a command position, so the keyword is safe to
    /// carry again. Each pair below is one of those measured shapes.
    #[test]
    fn power_rules_match_a_command_and_not_a_mention() {
        let pack = create_pack();
        for cmd in [
            "shutdown -h now",
            "reboot",
            "sudo reboot",
            "sudo -i shutdown -r now",
            "init 0",
            "ssh mini-ts reboot",
            "systemctl stop nginx && reboot",
            // The two real reboots in the spec-333 population: the command word
            // is inside a quoted remote script, behind flags that take an
            // argument of their own.
            "ssh -o ConnectTimeout=10 mini-ts 'sudo -n shutdown -r now'",
            "ssh -p 22 host sudo shutdown -h now",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "a real power command must still be denied: {cmd}"
            );
        }
        for cmd in [
            // The measured false positives: prose that names a reboot.
            r#"echo "reboot issued (rc=$?)""#,
            r#"br create "the mini needs a reboot after the upgrade""#,
            r#"git commit -m "shutdown the legacy worker""#,
            "rg -n 'init 0' docs/",
            // `ssh` must not license a power word anywhere later on the line:
            // these name a reboot inside the REMOTE command, and run nothing.
            r#"ssh mini-ts 'echo "the reboot worked"'"#,
            r#"ssh mini-ts "did the reboot survive""#,
            "ssh host echo the reboot worked",
            // Measured in the population: prose in a quoted argument, and a
            // Python tuple. `(` is a command position in shell, not in Python.
            r#"br close x --reason="remote reboot (sudo shutdown -r): fixed""#,
            r#"for word in ("shutdown", "exit"):"#,
            // `init` is a very common word; only runlevel 0 and 6 are the rule.
            "terraform init",
            "npm init -y",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "a mention of a power command must not be denied: {cmd}"
            );
        }
    }

    /// The keyword gate carries the three words the rules above match on.
    ///
    /// A rule whose command word the gate lacks can never run
    /// (`.agent-config-x74pe`); this is the half of that invariant this pack
    /// owns.
    #[test]
    fn power_command_words_are_in_the_gate() {
        for word in ["shutdown", "reboot", "init"] {
            assert!(
                KEYWORDS.contains(&word),
                "`{word}` must be in the gate or its rule cannot fire"
            );
        }
    }

    #[test]
    fn keyword_absent_skips_pack() {
        let pack = create_pack();
        assert!(!pack.might_match("echo hello"));
        assert!(pack.check("echo hello").is_none());
    }
}
