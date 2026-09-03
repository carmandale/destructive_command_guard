//! Heredoc RECEIVER RESOLUTION, which is what these cases are really about:
//! `grep pattern . <<'EOF'` must resolve to `grep` and not to the `.` argument,
//! and `cat bash <<'EOF'` must resolve to `cat` and not to the `bash` filename.
//!
//! EVERY DELIMITER IS QUOTED, AND THAT IS LOAD-BEARING. Spec 333 /
//! `.agent-config-u06z` masks a body only when the delimiter is quoted, so with
//! `<<EOF` nothing is masked no matter which receiver wins — every assertion
//! below would hold with receiver resolution completely broken. These cases were
//! written before the gate and asserted masking on unquoted delimiters, so they
//! were both FALSE and, had they somehow passed, vacuous. Two of the suite's
//! standing reds, fixed under `.agent-config-izbto`.

#[cfg(test)]
#[allow(clippy::uninlined_format_args)]
mod tests {
    use destructive_command_guard::heredoc::{
        is_non_executing_heredoc_command, mask_non_executing_heredocs,
    };

    #[test]
    fn test_grep_argument_masking() {
        // "grep" is a non-executing command
        assert!(is_non_executing_heredoc_command("grep"));

        // Case 1: Simple grep
        // grep reads from stdin (heredoc), pattern provided as arg
        let cmd = "grep pattern <<'EOF'\nrm -rf /\nEOF";
        let masked = mask_non_executing_heredocs(cmd);
        // Should be masked because grep is non-executing.
        // For heredocs, masking replaces content with spaces to preserve alignment.
        assert!(
            !masked.contains("rm -rf"),
            "Leaked dangerous content in grep: '{}'",
            masked
        );
        assert!(masked.contains("EOF"), "Should still contain delimiters");

        // Case 2: Grep with dot argument
        // grep pattern . <<'EOF'
        // Here "." is a file argument, but extract_heredoc_target_command might mistake it for the command
        let cmd_dot = "grep pattern . <<'EOF'\nrm -rf /\nEOF";
        let masked_dot = mask_non_executing_heredocs(cmd_dot);
        assert!(
            !masked_dot.contains("rm -rf"),
            "Leaked dangerous content in grep with dot arg: '{}'",
            masked_dot
        );
    }

    #[test]
    fn test_cat_filename_masking() {
        // "cat" is non-executing
        assert!(is_non_executing_heredoc_command("cat"));

        // Case 3: cat with a filename that looks like a command
        // "bash" is a known command. If we mistake the argument "bash" for the command,
        // we might think it IS executing (since bash executes input).
        // But the real command is "cat", which is non-executing.
        let cmd_bash_arg = "cat bash <<'EOF'\nrm -rf /\nEOF";
        let masked_bash = mask_non_executing_heredocs(cmd_bash_arg);
        assert!(
            !masked_bash.contains("rm -rf"),
            "Leaked dangerous content in cat with 'bash' filename: '{}'",
            masked_bash
        );
    }

    /// The other half of quoting the three cases above. Without this, flipping
    /// any of those delimiters back to `<<EOF` would turn nothing red and would
    /// look like a harmless edit — while quietly making all three vacuous again.
    ///
    /// The unquoted body is expanded by the outer shell BEFORE the receiver
    /// reads it, so a substitution in it really runs and its bytes must stay
    /// visible to the matcher. That is the recorded trade, not an oversight
    /// (u06z-replay-summary.md). If you are changing this, change that file and
    /// re-measure the safe-class corpus first.
    #[test]
    fn an_unquoted_delimiter_is_not_masked_for_any_of_these_receivers_izbto() {
        for cmd in [
            "grep pattern <<EOF\nrm -rf /\nEOF",
            "grep pattern . <<EOF\nrm -rf /\nEOF",
            "cat bash <<EOF\nrm -rf /\nEOF",
        ] {
            let masked = mask_non_executing_heredocs(cmd);
            assert!(
                masked.contains("rm -rf"),
                "an unquoted delimiter expands before the receiver reads it, so the \
                 body must stay visible to the matcher: '{}'",
                masked
            );
        }
    }
}
