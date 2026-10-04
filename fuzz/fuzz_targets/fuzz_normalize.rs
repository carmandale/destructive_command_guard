//! Fuzz target for command normalization.
//!
//! This fuzzes `normalize_command` which strips path prefixes from commands.
//! It tests for:
//! - Panics from unusual paths
//! - Regex issues with adversarial input
//! - Idempotence violations

#![no_main]

use libfuzzer_sys::fuzz_target;

use destructive_command_guard::packs::normalize_command;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs
        if command.len() > 10_000 {
            return;
        }

        // Normalize the command - this should never panic
        let normalized = normalize_command(command);

        // Verify idempotence: normalize(normalize(x)) == normalize(x)
        let normalized_again = normalize_command(&normalized);
        assert_eq!(
            normalized.as_ref(),
            normalized_again.as_ref(),
            "Normalization is not idempotent for: {:?}",
            command
        );

        // Normalization may add whitespace but never content. Since d19a7226
        // (.agent-config-6yt2i, .agent-config-fhj4b) it writes the word break
        // the shell already implies around a glued redirection, so `>%` comes
        // back as `> %` and plain length can grow; the first nightly that
        // really fuzzed found exactly that (.agent-config-j1qwb). Moving a
        // redirection keeps its bytes and every other step strips, so the
        // non-whitespace bytes can only stay or shrink.
        let content = |s: &str| s.bytes().filter(|b| !b.is_ascii_whitespace()).count();
        assert!(
            content(&normalized) <= content(command),
            "Normalization added non-whitespace content to: {command:?} -> {normalized:?}"
        );
    }
});
