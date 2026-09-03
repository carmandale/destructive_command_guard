//! One veto set, three readers — `.agent-config-c29fn`.
//!
//! Deciding that a heredoc body is inert takes five questions: is the RECEIVER a
//! data sink, and then four vetoes — does the body reach an executor through the
//! heredoc's own pipeline, through the enclosing compound's pipeline, through a
//! substitution, or by being written into a file a shell will later run. Three
//! separate places used to ask all five independently:
//!
//! * `mask_non_executing_heredocs`, at the here-string masking site;
//! * `mask_non_executing_heredocs`, at the heredoc masking site;
//! * `evaluate_command`, at the tier-2 extracted-content site.
//!
//! Nothing forced them to agree, and over one day the SAME root cause — "the
//! first whitespace token is not the command word" — was found and fixed three
//! separate times, once per reader (`.agent-config-baqrr` finding 1,
//! `.agent-config-41wu8` cause (g), and 41wu8's own close). The last of those is
//! the one worth remembering: with the two masking sites fixed,
//! `{ cat <<<'...'; } | bash` still ALLOWED on the binary while its unit test
//! passed green, because a here-string's content reaches the matcher through
//! extraction rather than through the masked command text, so the EVALUATOR is
//! the oracle there and the masking assertion was measuring the wrong one.
//!
//! `heredoc_body_is_inert` is now the single reader, which is the fix — a veto
//! cannot be added to fewer than three sites when there is only one site. This
//! file is the behavioural half: one test per reader, so deleting a clause from
//! the shared predicate goes red in ALL THREE rather than in whichever one the
//! author happened to look at. Each test reports every row it failed instead of
//! aborting at the first, because "one reader still red" and "three readers
//! still red" are the two answers this file exists to tell apart.
//!
//! Written from both sides. The first three tests pin that each of the five
//! questions is still asked; the last two pin that spec 333's whole point —
//! documentation text is DATA — survived. A predicate that vetoed everything
//! would score perfectly on the first three alone.
//!
//! **What the rest of the tree already covers, and what it does not.** Delete
//! any one veto and 9 to 22 pre-existing tests go red on their own, so on those
//! this file is belt-and-braces. Its unique coverage is one route: give the
//! evaluator only the receiver check and leave both masking sites whole — the
//! historical 41wu8 shape — and `cat <<<'rm -rf /' | bash` ALLOWs on the binary
//! while `repro_heredoc_pipe_to_shell.rs`'s here-string case still reports green,
//! because that one asserts on `mask_non_executing_heredocs` rather than on
//! `evaluate_command`. Nothing else in `tests/` denies that route.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every row carries. Identical across rows on purpose, so a verdict
/// difference can only come from the plumbing, never from the payload.
const TRIGGER: &str = "rm -rf /";

/// Heredoc shapes, one per question, each reaching an executor by exactly one
/// route. These exercise the heredoc masking site.
const HEREDOC_REACHES_AN_EXECUTOR: &[(&str, &str)] = &[
    // is_non_executing_heredoc_command — the receiver runs the body itself, and
    // no veto is involved. Without this row every table here uses `cat`, so
    // nothing distinguishes "the receiver is a data sink" from "there is a
    // receiver": a predicate reading `is_some_and(|_| true)` scores 5/5 while
    // `bash <<'EOF'`, `sh <<'EOF'` and `bash <<<'…'` all turn ALLOW.
    ("executing receiver", "bash <<'EOF'\nrm -rf /\nEOF"),
    // heredoc_output_reaches_executor — the pipe is on the heredoc's own line.
    ("pipeline", "cat <<'EOF' | bash\nrm -rf /\nEOF"),
    // compound_output_reaches_executor — the pipe belongs to the GROUP, two
    // lines down, where the heredoc's own scan has long since stopped.
    ("compound", "{ cat <<'EOF'\nrm -rf /\nEOF\n} | bash"),
    // heredoc_substitution_result_is_executed — the body is spliced into a
    // command that runs its argument.
    ("substitution", "eval \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\""),
    // heredoc_body_sinks_into_shell_script — nothing runs now, but the bytes
    // land in a file whose extension says they will.
    ("script sink", "cat <<'EOF' > deploy.sh\nrm -rf /\nEOF"),
];

/// The same five questions in here-string shapes. These exercise the
/// here-string masking site, and `compound` is the row that stayed open on the
/// binary when two of the three readers had been fixed and the third had not.
const HERESTRING_REACHES_AN_EXECUTOR: &[(&str, &str)] = &[
    ("executing receiver", "bash <<<'rm -rf /'"),
    ("pipeline", "cat <<<'rm -rf /' | bash"),
    ("compound", "{ cat <<<'rm -rf /'; } | bash"),
    ("substitution", "eval \"$(cat <<<'rm -rf /')\""),
    ("script sink", "cat <<<'rm -rf /' > deploy.sh"),
];

/// The false positives spec 333 exists to remove. Each is the nearest RUNNABLE
/// neighbour of a row above with that row's reason to execute taken away, and
/// the pairing is meant to be complete — a veto with no neighbour here is
/// unpinned in the false-positive direction, which is how an over-firing
/// substitution gate (`echo` treated as executing its argument) could turn
/// documentation text into a denial while this file scored 5/5.
const HEREDOC_STAYS_DATA: &[(&str, &str)] = &[
    ("bare", "cat <<'EOF'\nrm -rf /\nEOF"),
    (
        "group into a file",
        "{ cat <<'EOF'\nrm -rf /\nEOF\n} > notes.md",
    ),
    (
        "substitution into a data sink",
        "echo \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
    ),
    (
        "sink that is not a script",
        "cat <<'EOF' > notes.md\nrm -rf /\nEOF",
    ),
    // The safety argument for resuming the executor scan past a compound's
    // closer: a LATER, unrelated pipeline belongs to a different command and
    // must not be read as this body's.
    (
        "an unrelated later pipeline",
        "cat <<'EOF'\nrm -rf /\nEOF\nls | wc -l",
    ),
];

const HERESTRING_STAYS_DATA: &[(&str, &str)] = &[
    ("bare", "cat <<<'rm -rf /'"),
    ("group into a file", "{ cat <<<'rm -rf /'; } > notes.md"),
    (
        "substitution into a data sink",
        "echo \"$(cat <<<'rm -rf /')\"",
    ),
    ("sink that is not a script", "cat <<<'rm -rf /' > notes.md"),
];

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

/// Report EVERY failing row, not just the first. A mutant that removes one veto
/// from the shared predicate has to be seen failing at all three readers; a loop
/// of bare `assert!`s aborts at row one and hides the rest.
fn report(reader: &str, failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} row(s) failed at the {reader}:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

fn body_visible_failures(rows: &[(&str, &str)]) -> Vec<String> {
    rows.iter()
        .filter(|(_, cmd)| !mask_non_executing_heredocs(cmd).contains(TRIGGER))
        .map(|(veto, cmd)| format!("[{veto}] body masked away, no rule can read it: {cmd:?}"))
        .collect()
}

fn body_masked_failures(rows: &[(&str, &str)]) -> Vec<String> {
    rows.iter()
        .filter(|(_, cmd)| mask_non_executing_heredocs(cmd).contains(TRIGGER))
        .map(|(veto, cmd)| format!("[{veto}] body left visible, this is a false positive: {cmd:?}"))
        .collect()
}

fn denied_failures(rows: &[(&str, &str)]) -> Vec<String> {
    rows.iter()
        .filter(|(_, cmd)| !evaluate(cmd).is_denied())
        .map(|(veto, cmd)| format!("[{veto}] ALLOWED, the body reaches an executor: {cmd:?}"))
        .collect()
}

fn allowed_failures(rows: &[(&str, &str)]) -> Vec<String> {
    rows.iter()
        .filter(|(_, cmd)| evaluate(cmd).is_denied())
        .map(|(veto, cmd)| format!("[{veto}] DENIED, this is documentation text: {cmd:?}"))
        .collect()
}

/// Reader 1 — the heredoc masking site in `mask_non_executing_heredocs`.
#[test]
fn every_veto_is_read_at_the_heredoc_masking_site() {
    report(
        "heredoc masking site",
        body_visible_failures(HEREDOC_REACHES_AN_EXECUTOR),
    );
}

/// Reader 2 — the here-string masking site in `mask_non_executing_heredocs`.
#[test]
fn every_veto_is_read_at_the_herestring_masking_site() {
    report(
        "here-string masking site",
        body_visible_failures(HERESTRING_REACHES_AN_EXECUTOR),
    );
}

/// Reader 3 — the evaluator's extracted-content site, and the one the binary
/// answers with for a here-string. Both shapes go through it, so a veto that
/// reached only the masking sites is red here and nowhere else.
#[test]
fn every_veto_is_read_at_the_evaluator() {
    let mut failures = denied_failures(HEREDOC_REACHES_AN_EXECUTOR);
    failures.extend(denied_failures(HERESTRING_REACHES_AN_EXECUTOR));
    report("evaluator", failures);
}

/// The other side at the masking sites: documentation text still gets masked.
#[test]
fn data_still_masks_at_both_masking_sites() {
    let mut failures = body_masked_failures(HEREDOC_STAYS_DATA);
    failures.extend(body_masked_failures(HERESTRING_STAYS_DATA));
    report("masking sites", failures);
}

/// The other side at the evaluator: documentation text is still allowed.
#[test]
fn data_is_still_allowed_at_the_evaluator() {
    let mut failures = allowed_failures(HEREDOC_STAYS_DATA);
    failures.extend(allowed_failures(HERESTRING_STAYS_DATA));
    report("evaluator", failures);
}
