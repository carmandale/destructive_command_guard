#[cfg(test)]
mod tests {
    use destructive_command_guard::config::Config;
    use destructive_command_guard::evaluator::evaluate_command;
    use destructive_command_guard::load_default_allowlists;
    use destructive_command_guard::packs::REGISTRY;

    fn get_eval_components() -> (
        Config,
        Vec<&'static str>,
        destructive_command_guard::config::CompiledOverrides,
        destructive_command_guard::allowlist::LayeredAllowlist,
    ) {
        let config = Config::default();
        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled = config.overrides.compile();
        let allowlists = load_default_allowlists();
        (config, enabled_keywords, compiled, allowlists)
    }

    /// A backslash-escaped delimiter is a QUOTED delimiter, and is treated as one.
    ///
    /// This test used to assert the opposite — that `cat <<\EOF` with a
    /// destructive body is DENIED — and it was correct when it was written,
    /// before the spec 333 gate. It is stale for the same reason as the two in
    /// `.agent-config-3kpp5`: the shipped contract is now "mask a heredoc body
    /// when its delimiter is quoted and its receiver cannot execute it", and
    /// the identically-shaped `<<'EOF'` and `<<"EOF"` spellings of this very
    /// command have ALLOWED since that gate landed.
    ///
    /// Measured before this test was touched, on the untouched parent build and
    /// on the then-live binary (artifacts/oiwua-testcontract-output.txt in
    /// agent-config spec 333):
    ///
    ///   cat <<'EOF' / rm -rf / / EOF    ALLOW
    ///   cat <<"EOF" / rm -rf / / EOF    ALLOW
    ///   cat <<\EOF  / rm -rf / / EOF    DENY   <- this test
    ///   cat <<EOF   / rm -rf / / EOF    DENY   (unquoted: by design)
    ///
    /// So the backslash row was not being PROTECTED, it was being MISSED: the
    /// parser did not recognise the spelling, so the body was never masked and
    /// the deny was an accident of that gap rather than a decision. Making it
    /// agree with its own siblings is `.agent-config-oiwua`.
    ///
    /// The test keeps the job its name promises. The backslash spelling must
    /// not become a way AROUND the receiver vetoes, so the rows that must still
    /// deny are pinned here too — re-widening them turns this red instead of
    /// widening allow in silence.
    #[test]
    fn test_heredoc_backslash_delimiter_is_quoted() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Quoted delimiter, receiver cannot execute the body: masked, allowed.
        let inert = "\ncat <<\\EOF\nrm -rf /\nEOF\n";
        let result = evaluate_command(inert, &config, &keywords, &compiled, &allowlists);
        assert!(
            !result.is_denied(),
            "A backslash delimiter is quoted, so an inert receiver's body is data: {inert}"
        );

        // Same body, same delimiter, receiver that DOES execute it.
        let piped = "cat <<\\EOF | bash\nrm -rf /\nEOF\n";
        let result = evaluate_command(piped, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "A backslash delimiter must not carry a body past an executor: {piped}"
        );

        // The unquoted spelling stays denied — the outer shell expands it.
        let unquoted = "\ncat <<EOF\nrm -rf /\nEOF\n";
        let result = evaluate_command(unquoted, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "An UNQUOTED delimiter is expanded before the sink sees it: {unquoted}"
        );

        // And the hazard issued directly is unaffected by any of this.
        let direct = "rm -rf /";
        let result = evaluate_command(direct, &config, &keywords, &compiled, &allowlists);
        assert!(result.is_denied(), "control: {direct}");
    }

    #[test]
    fn test_command_internal_escape_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g\it" exactly like "git".
        // If normalization doesn't handle this, regexes looking for "\bgit\b" will fail.
        let cmd = r"g\it reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with internal backslash escaping: {cmd}"
        );
    }

    #[test]
    fn test_command_mixed_quoting_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g'i't" exactly like "git".
        let cmd = r"g'i't reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with mixed quoting: {cmd}"
        );
    }
}
