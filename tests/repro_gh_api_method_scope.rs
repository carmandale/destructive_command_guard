//! A `GET` safe pattern must not exempt a destructive method in the SAME command.
//!
//! `.agent-config-nh7t4`. The `gh`/`glab` `api` safe patterns say "this call is a
//! GET, so it is safe". Both they and the destructive `api ... DELETE` patterns
//! begin at the command word, and the exemption rule asks whether a destructive
//! match STARTS inside a safe span. Two spans that both start at `gh` satisfy
//! that unconditionally, so ANY `-X GET` anywhere in the command exempted EVERY
//! `-X DELETE` in it -- in either order, and even when the GET was only a
//! literal inside a quoted `--field` value:
//!
//!     gh api -X DELETE /repos/o/r/hooks/7                  DENY   (correct)
//!     gh api -X GET /user -X DELETE /repos/o/r/hooks/7     ALLOW  <- bypass
//!     gh api -X DELETE /repos/o/r -X GET /user             ALLOW  <- deletes a REPO
//!
//! The bead was filed the other way round -- as a false POSITIVE, because
//! `gh api "/x?a=1&b=2" -X GET /user -X DELETE ...` denied while the same line
//! without the `&` allowed. That difference is real but the reading was
//! inverted: `[^;&|\n]*` in the safe pattern cannot cross a `&`, so a quoted `&`
//! merely DEFEATS the over-broad safe match and lets the destructive rule fire.
//! The deny was the guard working; the allow next to it was the defect.
//!
//! Measured, not assumed: a genuinely safe single command carrying a quoted `&`
//! (`gh api "/repos/o/r/issues?state=open&per_page=100" --method GET`) ALLOWED
//! both before and after this fix, so there was never a false positive on a
//! command that only reads. `still_allows_genuine_gets` is that half of the pin.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// The packs the reporting session ran: `DCG_PACKS=core,cicd.github_actions,platform.github`.
fn is_denied(command: &str) -> bool {
    let config = Config::default();
    let enabled: HashSet<String> = ["core", "cicd.github_actions", "platform.github"]
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

/// The control. Without it every `is_denied` assertion below could pass by never
/// reaching the github packs at all -- green over nothing.
#[test]
fn the_github_packs_are_actually_reached() {
    assert!(
        is_denied("gh api -X DELETE /repos/o/r/hooks/7"),
        "the github packs are not enabled in this harness, so every other \
         assertion in this file would pass without evaluating anything"
    );
}

#[test]
fn a_get_does_not_exempt_a_delete_in_the_same_command() {
    for cmd in [
        // GET before the DELETE.
        "gh api -X GET /user -X DELETE /repos/o/r/hooks/7",
        "gh api --method GET /user -X DELETE /repos/o/r/hooks/7",
        // GET after the DELETE.
        "gh api -X DELETE /repos/o/r/hooks/7 -X GET /user",
        // The GET is not even a flag of this command -- it is text inside a
        // quoted value, which is the cheapest spelling to craft.
        "gh api -X DELETE /repos/o/r/hooks/7 --field q=\"-X GET\"",
        // Deploy keys and secrets, same shape, different destructive rule.
        "gh api -X GET /user -X DELETE /repos/o/r/keys/1",
        "gh api -X GET /user -X DELETE /repos/o/r/actions/secrets/TOKEN",
    ] {
        assert!(
            is_denied(cmd),
            "a GET elsewhere in the command must not exempt the destructive \
             method: {cmd}"
        );
    }
}

/// The `&` row the bead was filed on. It denies -- and it denied before the fix
/// too. It is here so a future change that "fixes" the `&` by widening the safe
/// pattern cannot pass silently.
#[test]
fn a_quoted_ampersand_does_not_reopen_the_bypass() {
    assert!(
        is_denied("gh api \"/x?a=1&b=2\" -X GET /user -X DELETE /repos/o/r/hooks/7"),
        "the quoted & must not become a way to exempt the DELETE"
    );
}

// ---------------------------------------------------------------------------
// The other direction: the guard must not deny a command that only reads.
// This half is what makes the fix a narrowing rather than a blanket deny.
// ---------------------------------------------------------------------------

#[test]
fn still_allows_genuine_gets() {
    for cmd in [
        "gh api \"/repos/o/r/issues?state=open\" --method GET",
        // The bead's own spelling: a quoted & in the query string.
        "gh api \"/repos/o/r/issues?state=open&per_page=100\" --method GET",
        "gh api '/repos/o/r/issues?state=open&per_page=100' --method GET",
        "gh api /repos/o/r/issues?state=open --method GET",
        "gh api \"/repos/o/r/hooks\" -X GET",
        // A GET against a path a DELETE rule governs is still only a read.
        "gh api -X GET /repos/o/r/hooks/7",
        "gh --repo o/r api \"/x?a=1&b=2\" --method GET",
        "gh api /user --method GET && gh api /repos/o/r --method GET",
        // gitlab_ci.rs carries the same pattern and the same fix.
        "glab api \"/projects?per_page=100&x=1\" -X GET",
    ] {
        assert!(!is_denied(cmd), "must stay allowed: {cmd}");
    }
}
