//! The Debug spelling of `MatchSource::ConfigOverride` crosses a file boundary
//! as a bare string, and nothing else couples the two ends.
//!
//! `src/main.rs` writes `format!("{:?}", info.source)` into the pending record's
//! `source` field. `src/cli.rs::handle_allow_once_command` then gates the
//! "This denial came from your config blocklist; re-run with --force to
//! override." refusal on `selected.source.as_deref() == Some("ConfigOverride")`.
//! Renaming the variant leaves every `matches!` call site compiling — including
//! the `allow_once_suffices` one added by `.agent-config-a6jka` — while silently
//! unhitching that string comparison.
//!
//! Measured under `.agent-config-a6jka`, by rewriting the stored `source` field
//! in the pending store, which is exactly the bytes a rename would produce:
//!
//! ```text
//! control (source as dcg wrote it)   dcg allow-once <code> --yes   rc=1, hook after: DENY
//! renamed to "ConfigBlocklist"       dcg allow-once <code> --yes   rc=0, hook after: DENY
//! control,  --force --yes            force_allow_config=true       hook after: ALLOW
//! renamed,  --force --yes            force_allow_config=false      hook after: DENY
//! ```
//!
//! So a broken coupling is NOT a bypass: the evaluator independently requires
//! `force_allow_config` on the stored entry, and the config block held in every
//! arm. The actual consequence is the opposite — `dcg allow-once <code> --force
//! --yes` prints "✓ Allow-once entry created", exits 0, and does nothing. A
//! silent no-op on the override path is worth one assertion to prevent.
//!
//! This test lives in its own file rather than beside either end because both
//! `src/evaluator.rs` and `src/cli.rs` are large and frequently edited; a
//! failure here should name the coupling, not a neighbour.

use destructive_command_guard::evaluator::MatchSource;

/// The literal `src/cli.rs::handle_allow_once_command` compares against.
const CLI_EXPECTS: &str = "ConfigOverride";

#[test]
fn config_override_debug_spelling_matches_what_cli_compares_against() {
    assert_eq!(
        format!("{:?}", MatchSource::ConfigOverride),
        CLI_EXPECTS,
        "src/cli.rs gates the --force refusal on the pending record's `source` \
         equalling {CLI_EXPECTS:?}. You renamed MatchSource::ConfigOverride \
         without updating that comparison, which makes `dcg allow-once <code> \
         --force --yes` a silent no-op on config-blocklist denials."
    );
}

/// A control: the assertion above must be capable of failing.
///
/// If `format!("{:?}", ..)` did not produce the variant's name at all — a
/// `#[derive(Debug)]` removed, a manual impl added — the test above could pass
/// for the wrong reason only if the replacement happened to be the same string.
/// This pins that the Debug output really is variant-discriminating.
#[test]
fn match_source_debug_output_discriminates_variants() {
    assert_ne!(
        format!("{:?}", MatchSource::ConfigOverride),
        format!("{:?}", MatchSource::Pack),
        "MatchSource's Debug output must distinguish variants, or the spelling \
         guard above is comparing against a constant"
    );
}
