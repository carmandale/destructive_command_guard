//! A SEARCH command's redirection is not its pattern. `.agent-config-y5eor`.
//!
//! `sanitize_for_pattern_matching` masks a search command's first positional
//! argument, because for `rg`/`grep`/`ag`/`ack` that argument is a regex and a
//! regex is data. With NO pattern present the first positional token is the
//! heredoc OPERATOR, and masking `<<'EOF'` to spaces destroyed the `<<`.
//!
//! That matters because of ORDER. Heredoc masking runs LATER, on this
//! function's output — evaluator.rs step 5 (sanitize) -> step 6 (normalize) ->
//! step 7 (`mask_non_executing_heredocs`). With the operator gone there is no
//! heredoc left to find, so the body was never masked and every rule in every
//! pack read it as command text:
//!
//!     grep <<'EOF'     DENY      grep pat <<'EOF'   ALLOW
//!     rg   <<'EOF'     DENY      rg foo   <<'EOF'   ALLOW
//!     ag   <<'EOF'     DENY
//!     ack  <<'EOF'     DENY
//!
//! The verdict inverted on whether a pattern token happened to be there to be
//! eaten INSTEAD of the operator, which is why `cat`, `head`, `sort`, `sed -n p`
//! and `jq .` were unaffected — none of them is a search command.
//!
//! The pins below are written against the composed chain rather than against
//! `sanitize_for_pattern_matching` alone, because the defect is not visible in
//! either layer on its own: sanitize's output looks like a reasonable masking,
//! and the heredoc masker is correct about the string it is handed.

use destructive_command_guard::context::sanitize_for_pattern_matching;
use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::normalize::normalize_command;

const HAZ: &str = "rm -rf /Users/dalecarman/dcg-probe-target";

/// The evaluator's own order: sanitize, then normalize, then mask heredocs.
fn packs_would_see(command: &str) -> String {
    let sanitized = sanitize_for_pattern_matching(command);
    let normalized = normalize_command(sanitized.as_ref());
    mask_non_executing_heredocs(normalized.as_ref()).into_owned()
}

#[test]
fn search_receiver_without_a_pattern_still_masks_its_heredoc_body() {
    // All four search commands, no positional pattern. Each one is the bug.
    for cmd in ["grep", "rg", "ag", "ack"] {
        let full = format!("{cmd} <<'EOF'\n{HAZ}\nEOF");
        let seen = packs_would_see(&full);
        assert!(
            !seen.contains("rm -rf"),
            "{cmd} <<'EOF' leaked its heredoc body to the packs: {seen:?}"
        );
        assert!(
            seen.contains("<<"),
            "{cmd} <<'EOF' lost the heredoc operator to pattern masking: {seen:?}"
        );
    }
}

#[test]
fn a_search_pattern_is_still_masked_when_one_is_actually_present() {
    // The fix must not buy its ALLOW by switching pattern masking off: a real
    // pattern is data and must still be stripped. A mutant that simply skips
    // the whole search arm passes the test above and fails this one.
    let seen = packs_would_see(&format!("grep rm-rf-in-a-pattern <<'EOF'\n{HAZ}\nEOF"));
    assert!(
        !seen.contains("rm-rf-in-a-pattern"),
        "the positional pattern stopped being masked: {seen:?}"
    );
    assert!(!seen.contains("rm -rf"), "body leaked: {seen:?}");

    // ... and the pattern is still found when a redirection precedes it.
    let seen = packs_would_see("grep > out.txt needle-pattern");
    assert!(
        !seen.contains("needle-pattern"),
        "a redirection before the pattern swallowed the pattern search: {seen:?}"
    );
    assert!(
        seen.contains("out.txt"),
        "a bare redirection's TARGET was masked as if it were the pattern: {seen:?}"
    );
}

#[test]
fn the_flag_spellings_of_a_pattern_still_suppress_positional_masking() {
    // `-e PAT` supplies the pattern, so the following positional is a FILE.
    // This is the pre-existing contract; it is pinned here because the fix adds
    // a second `continue` to the same arm and could plausibly reorder it.
    let seen = packs_would_see(&format!("grep -e p <<'EOF'\n{HAZ}\nEOF"));
    assert!(!seen.contains("rm -rf"), "body leaked with -e: {seen:?}");
    assert!(seen.contains("<<"), "operator lost with -e: {seen:?}");
}

#[test]
fn a_search_receiver_piped_to_an_interpreter_is_still_denied_material() {
    // The direction control. The fix must not make a body inert just because the
    // receiver is a search command -- when the SAME body reaches an interpreter
    // it has to stay visible. If this ever goes green-by-masking, the fix has
    // traded a false positive for a hole, which is the trade this spec refuses.
    for cmd in ["grep", "rg", "ag", "ack"] {
        let full = format!("{cmd} <<'EOF' | bash\n{HAZ}\nEOF");
        let seen = packs_would_see(&full);
        assert!(
            seen.contains("rm -rf"),
            "{cmd} <<'EOF' | bash masked a body that REACHES AN INTERPRETER: {seen:?}"
        );
    }
}

#[test]
fn non_search_receivers_were_never_affected_and_still_are_not() {
    // The rows that were already correct. They are here so a regression in the
    // shared heredoc masker shows up in this file too, rather than only in a
    // suite nobody runs alongside it.
    for cmd in ["cat", "head", "sort", "tee /tmp/y5eor-pin.md", "jq .", "sed -n p"] {
        let full = format!("{cmd} <<'EOF'\n{HAZ}\nEOF");
        let seen = packs_would_see(&full);
        assert!(
            !seen.contains("rm -rf"),
            "{cmd} <<'EOF' leaked its heredoc body: {seen:?}"
        );
    }
}
