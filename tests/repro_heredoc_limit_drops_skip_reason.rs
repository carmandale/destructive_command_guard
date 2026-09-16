//! Content past an extraction limit must be judged or denied, never silently
//! allowed (`.agent-config-1227x`).
//!
//! Found 2026-09-15 by a cold reviewer on `.agent-config-6cwlr`, outside that
//! diff and present in both `origin/main` 3a26fc0 and the 6cwlr build. Measured
//! then with release binaries at `hook_timeout_ms=5000`, on k copies of
//! `python3 -c 'print(1)'; ` in front of a python heredoc ending in
//! `shutil.rmtree('/srv/data')`:
//!
//! ```text
//!   k=9   -> DENY  (heredoc.python:shutil_rmtree)
//!   k=10  -> ALLOW      <- the whole defect, 540 bytes
//!   k=11  -> ALLOW
//!   k=10 with fallback_on_parse_error=false and fallback_on_timeout=false -> ALLOW
//! ```
//!
//! Ten harmless prefixes fill `max_heredocs` (10), so the destructive eleventh
//! script is never extracted. `extract_content` recorded that as
//! `SkipReason::ExceededHeredocLimit` and then returned
//! `ExtractionResult::Extracted(first 10)` -- dropping the reason on the floor.
//! `Extracted` is the evaluator's word for "this command was judged in full", so
//! nothing downstream could know that anything went unread. `Partial` existed,
//! carried exactly that information, and was constructed nowhere in `src`: its
//! whole arm in the evaluator was dead code.
//!
//! The fix is three sites, because the reason was dropped in three places:
//!
//!   1. `extract_content`'s terminal arm returned `Extracted(extracted)` when
//!      BOTH extraction and skips happened, discarding the reasons. It now
//!      returns `Partial { extracted, skipped }`, as do the two early
//!      timeout returns above it.
//!   2. `extract_herestrings` and `extract_heredocs` bailed at a full cap with
//!      `return; // Already hit limit, don't add another skip reason`. At k=10
//!      there IS no other reason: the inline-script pass fills the last slot
//!      exactly, so its loop ends normally and records nothing. Fixing only
//!      site 1 closed k=11 and left k=10 ALLOW. All six limit sites now route
//!      through `record_heredoc_limit`, which de-duplicates in one place.
//!   3. The evaluator keys its rudimentary raw-command fallback check on
//!      "anything went unread" rather than on `ExceededSizeLimit` alone, and
//!      that check now masks inert heredoc bodies first (see the INERTNESS
//!      section below for what that cost and why it is not optional).
//!
//! WHY NOT fail closed on a full limit: denying every command that carries more
//! than ten scripts is a false-positive surface change, and this guard's cost is
//! measured in blocked-but-harmless commands. Judging the raw text is the option
//! that closes the hole without spending that. The harmless rows below are that
//! promise, and they go red if a later change swaps judgement for a blanket
//! deny.
//!
//! PRICED before landing, on spec 333's own corpora, base vs candidate, one
//! sample per unique command at `hook_timeout_ms=5000`:
//!
//!   - `heredoc-blocks.jsonl`, 1191 rows: 0 disagreements.
//!   - `bash-sample.jsonl`, 18723 real Bash invocations: see the bead.
//!
//! An earlier candidate WITHOUT the masking in site 3 moved two of those
//! `heredoc-blocks.jsonl` rows ALLOW -> DENY. Both were `cat >> file <<'EOF'`
//! prose. That is the measurement that shaped the fix, not a hypothetical.
//!
//! WHAT KILLS WHICH ROW, measured on this tree 2026-09-15 by reverting each
//! site alone and running both binaries separately (`cargo test --test <one>`,
//! never two at once -- their output order is not fixed, and reading it with
//! head/tail once mislabelled which binary a result belonged to):
//!
//! ```text
//!   revert                                 | red rows
//!   ---------------------------------------|------------------------------------
//!   terminal arm -> Extracted              | extraction_reports_the_limit_it_hit,
//!                                          | k=10, k=11
//!   fallback keyed on ExceededSizeLimit    | k=10, k=11
//!   entry guards bail silently             | extraction_reports_the_limit_it_hit,
//!                                          | k=10   (k=11 stays GREEN)
//!   no `<<<` phantom skip                  | golden_isomorphism x3, none here
//!   no inert-body masking                  | prose_in_an_inert_body_survives_a_full_cap
//! ```
//!
//! Read the third row: reverting the entry guards leaves k=11 green, because a
//! pass that runs INTO the cap mid-loop still records it. Only k=10 -- where the
//! cap is filled exactly and the loop ends normally -- catches that site. That
//! is the whole reason both rows exist.
//!
//! `one_filler_under_the_cap_denies` (k=9) and `a_size_limit_still_denies` went
//! red under NO mutant above. They are floors -- they say the payload and the
//! harness work, so a k=10 red means the cap and not a broken fixture -- and
//! they are not proof of anything. Do not cite them as coverage.
//!
//! The `<<<` row lives in `golden_isomorphism`, not here: this file has no
//! here-string case, and that corpus already carried one.

use destructive_command_guard::heredoc::{ExtractionLimits, ExtractionResult, SkipReason};
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The destructive payload. `shutil.rmtree` is both an AST rule
/// (`heredoc.python:shutil_rmtree`) and a fallback pattern, which is what makes
/// the k=9 / k=10 pair a clean A/B: the payload never changes, only how many
/// harmless scripts sit in front of it.
const DESTRUCTIVE_HEREDOC: &str =
    "python3 <<'PY'\nimport shutil\nimport sys\nprint('cleaning')\nshutil.rmtree('/srv/data')\nPY";

/// Same shape, nothing destructive in it. Pins that filling the limit does not
/// by itself deny.
const HARMLESS_HEREDOC: &str =
    "python3 <<'PY'\nimport sys\nimport os\nprint('hello')\nsys.exit(0)\nPY";

/// One harmless inline script. k of these fill `max_heredocs`.
const FILLER: &str = "python3 -c 'print(1)'; ";

fn command_with_prefix_count(k: usize, tail: &str) -> String {
    format!("{}{tail}", FILLER.repeat(k))
}

fn evaluate(cmd: &str) -> destructive_command_guard::evaluator::EvaluationResult {
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    config.packs.enabled = vec!["core".to_string()];

    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    evaluate_command(cmd, &config, &keywords, &overrides, &allowlists)
}

fn assert_denied(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_denied(),
        "should be DENIED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

fn assert_allowed(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        !result.is_denied(),
        "should be ALLOWED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

/// The cap the whole file is written against. Read from the shipped default so
/// that raising it moves the rows below with it instead of quietly making them
/// test nothing.
fn max_heredocs() -> usize {
    ExtractionLimits::default().max_heredocs
}

// ---------------------------------------------------------------------------
// The measured defect.
// ---------------------------------------------------------------------------

#[test]
fn one_filler_under_the_cap_denies() {
    // The k=9 control. Green before the fix too -- it is the proof that the
    // payload and the harness work at all, so a k=10 red means the cap, not a
    // broken fixture.
    let cmd = command_with_prefix_count(max_heredocs() - 1, DESTRUCTIVE_HEREDOC);
    assert_denied(&cmd, "under the cap, the heredoc is extracted and judged");
}

#[test]
fn filling_the_cap_does_not_buy_a_free_destructive_heredoc() {
    // The defect itself: k=10 was ALLOW.
    let cmd = command_with_prefix_count(max_heredocs(), DESTRUCTIVE_HEREDOC);
    assert_denied(
        &cmd,
        "the heredoc went unread, so the raw command must still be checked",
    );
}

#[test]
fn overflowing_the_cap_does_not_buy_one_either() {
    // k=11. One past the cap behaves like ten, so the fix is not an off-by-one.
    let cmd = command_with_prefix_count(max_heredocs() + 1, DESTRUCTIVE_HEREDOC);
    assert_denied(
        &cmd,
        "past the cap is the same unread content as at the cap",
    );
}

#[test]
fn a_size_limit_still_denies() {
    // The one reason the old predicate DID name, kept so a later narrowing of
    // the fix cannot quietly drop it while the count rows pass.
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    config.heredoc.max_body_bytes = Some(16);
    config.packs.enabled = vec!["core".to_string()];

    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let result = evaluate_command(
        DESTRUCTIVE_HEREDOC,
        &config,
        &keywords,
        &overrides,
        &allowlists,
    );
    assert!(
        result.is_denied(),
        "a body too large to read must still be checked: reason {:?}",
        result.reason()
    );
}

// ---------------------------------------------------------------------------
// The cost side. These are what a blanket deny-on-limit would break, and they
// are the reason the fix judges the text instead.
// ---------------------------------------------------------------------------

#[test]
fn filling_the_cap_harmlessly_is_still_allowed() {
    let cmd = command_with_prefix_count(max_heredocs(), HARMLESS_HEREDOC);
    assert_allowed(
        &cmd,
        "nothing here is destructive; the cap alone is not a verdict",
    );
}

#[test]
fn overflowing_the_cap_harmlessly_is_still_allowed() {
    let cmd = command_with_prefix_count(max_heredocs() + 5, HARMLESS_HEREDOC);
    assert_allowed(
        &cmd,
        "well past the cap and still harmless: unread is not the same as guilty",
    );
}

// ---------------------------------------------------------------------------
// The mechanism, pinned directly so it cannot regress behind a coincidence.
// ---------------------------------------------------------------------------

#[test]
fn extraction_reports_the_limit_it_hit() {
    let cmd = command_with_prefix_count(max_heredocs(), DESTRUCTIVE_HEREDOC);
    let limits = ExtractionLimits {
        // Generous on purpose: this row is about the COUNT limit, and a 50ms
        // default could otherwise make it report a timeout on a loaded machine.
        timeout_ms: 20_000,
        ..ExtractionLimits::default()
    };

    match destructive_command_guard::heredoc::extract_content(&cmd, &limits) {
        ExtractionResult::Partial { extracted, skipped } => {
            assert_eq!(
                extracted.len(),
                limits.max_heredocs,
                "the cap is what stopped extraction, so exactly max_heredocs came back"
            );
            assert!(
                skipped
                    .iter()
                    .any(|r| matches!(r, SkipReason::ExceededHeredocLimit { .. })),
                "the surviving reason must name the count limit: {skipped:?}"
            );
        }
        other => panic!(
            "content went unread, so extraction must say so with Partial, not {}",
            match other {
                ExtractionResult::Extracted(_) => "Extracted (the defect: reason dropped)",
                ExtractionResult::Skipped(_) => "Skipped",
                ExtractionResult::NoContent => "NoContent",
                ExtractionResult::Failed(_) => "Failed",
                ExtractionResult::Partial { .. } => unreachable!(),
            }
        ),
    }
}

#[test]
fn extraction_with_nothing_skipped_is_still_plain_extracted() {
    // The control for the row above: `Partial` must mean something. If
    // `extract_content` started returning it unconditionally, the assertion
    // above would pass while saying nothing.
    let limits = ExtractionLimits {
        timeout_ms: 20_000,
        ..ExtractionLimits::default()
    };
    let result = destructive_command_guard::heredoc::extract_content(HARMLESS_HEREDOC, &limits);
    assert!(
        matches!(result, ExtractionResult::Extracted(_)),
        "a fully read command must report Extracted, not Partial: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// INERTNESS. The fallback check reads the RAW command, so it has to mask what
// the rest of the pipeline masks. Measured 2026-09-15: widening the trigger
// without masking moved two real `expected_verdict: allow` rows of
// heredoc-blocks.jsonl to DENY -- 6282e467884ba582 and 11ddfc7847fefd14, both
// prose in a `cat` body. These two rows are that pair, in shape.
// ---------------------------------------------------------------------------

/// Kept verbatim in shape from row 6282e467884ba582: a receipt being appended to
/// a file, whose text discusses a destructive command as an example.
const PROSE_ABOUT_A_DESTRUCTIVE_COMMAND: &str =
    "| A. `git reset --hard origin/main` at shell position | **deny** <- positive control |";

#[test]
fn prose_in_an_inert_body_survives_a_full_cap() {
    let cmd = format!(
        "{}cat >> receipt.md <<'RECEIPT'\n{PROSE_ABOUT_A_DESTRUCTIVE_COMMAND}\nRECEIPT",
        FILLER.repeat(max_heredocs())
    );
    assert_allowed(
        &cmd,
        "a cat body is data: writing ABOUT a command is not running it",
    );
}

#[test]
fn the_same_text_in_an_executing_body_still_denies() {
    // The control that makes the row above mean something. Identical payload,
    // identical cap, different receiver -- so only inertness can explain the
    // verdict difference. Without this, masking everything would score green.
    let cmd = format!(
        "{}bash <<'EOF'\ngit reset --hard origin/main\nEOF",
        FILLER.repeat(max_heredocs())
    );
    assert_denied(&cmd, "a bash body really does reach a shell");
}
