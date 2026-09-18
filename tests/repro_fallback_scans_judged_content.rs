//! The fallback check must read only the content nobody judged
//! (`.agent-config-dcg-fallback-scans-judged-content-zc6tb`).
//!
//! `check_fallback_patterns` exists for content that went UNREAD: when
//! extraction is `Partial`, something was skipped, and the rudimentary regex
//! sweep is the only thing standing between an unread body and the shell. It
//! ran over the WHOLE raw command, which includes every body that WAS
//! extracted and judged. So a rule the AST pass looked at and cleared could be
//! re-decided by a regex, as `denied_by_legacy` -- which carries no ruleId, so
//! `main.rs` always denies it, past `[policy.rules]`, and tells the agent
//! "Unjudged command content contains destructive pattern" about content that
//! was judged.
//!
//! LIVE INSTANCE, 2026-09-18 (session 0f12628d, the installed guard): an
//! agent's own `python3 - <<'PY'` call was blocked. Its body was pure data --
//! Python string literals quoting a commit message that mentioned `rm -rf`,
//! and `1 << 20`. The `<< 20` makes the context-free extractor see a heredoc
//! opening a body delimited by `20` that never terminates, so extraction is
//! `Partial`, and the fallback regex then matched `rm -rf` inside the judged
//! string data. That is `live_instance_*` below, and it is the row that was
//! RED before the fix on this tree.
//!
//! WHICH ROW IS A KILL, measured on this tree 2026-09-18 by running this file
//! against `main` 9ebd1032 before the fix and after it:
//!
//! ```text
//!   row                                          | pre-fix | post-fix
//!   ---------------------------------------------|---------|---------
//!   live_instance_...rm_rf_is_not_denied          | RED     | green
//!   a_warned_rmtree_in_a_judged_inline_script     | green   | green
//!   a_warned_reset_hard_in_a_judged_inline_script | green   | green
//!   a_skipped_body_holding_rm_rf_still_denies (x2)| green   | green
//! ```
//!
//! Read that honestly: on THIS tree only the live instance kills the defect.
//! The two `a_warned_*` rows are the inputs the bead names, and on `main` the
//! sweep never reaches them -- a judged body whose match blocks by default ends
//! the evaluation before the sweep runs, so the policy downgrade is applied by
//! `main.rs` and the sweep is moot. They become reachable on the `fxck7` tree,
//! where a policy-WARNED match is HELD instead of returned and the evaluation
//! runs on into the sweep. They are regression pins for that landing, not
//! coverage of this one. Do not cite them as proof the fix works.
//!
//! The `a_skipped_body_*` rows are the fail-closed controls: they are what a
//! mask that is too wide would break, and they were green on both sides, so
//! they prove the fix did not buy its green by switching the sweep off.
//!
//! The fix masks the byte ranges of the content that actually reached the
//! matchers before the sweep runs. It masks what was JUDGED, not what was
//! EXTRACTED: the loop in `evaluate_heredoc` skips extracted entries for six
//! reasons (a disabled language, a content allowlist hit, an inert receiver, a
//! nested-in-inert span, a budget stop, an AST match error), and masking one
//! of those would be a fail-open -- the sweep would stop reading a body no
//! matcher ever read. So the mask is collected INSIDE the loop, at the point
//! each entry has been matched, and nowhere else.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// One harmless inline script. Ten of these fill `max_heredocs` (10), so the
/// eleventh piece of content is skipped and `fallback_needed` is set. This is
/// the same filler `repro_heredoc_limit_drops_skip_reason.rs` uses, on purpose:
/// that file pins that a SKIPPED body is still caught, and this one pins that a
/// JUDGED body is not re-decided. They share the trigger so neither can drift
/// into testing a different mechanism than the other.
const FILLER: &str = "python3 -c 'print(1)'; ";

fn fillers(k: usize) -> String {
    FILLER.repeat(k)
}

fn run_hook(
    mut cmd: std::process::Command,
    sandbox: &spawn::Sandbox,
    command: &str,
) -> (String, String, i32) {
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");
    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }
    let output = child.wait_with_output().expect("failed to wait for dcg");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Default policy, `core` packs. The live instance ran under no rule downgrade
/// at all, so this is the harness that shows the defect does not need one.
fn run_default(command: &str) -> (String, String, i32) {
    let (cmd, sandbox) = spawn::dcg();
    run_hook(cmd, &sandbox, command)
}

/// The live config's shape: the two rules Dale actually downgrades.
fn run_with_warned_rules(command: &str) -> (String, String, i32) {
    let sandbox = spawn::sandbox();
    let config_path = sandbox.root().join("policy.toml");
    std::fs::write(
        &config_path,
        "[policy.rules]\n\
         \"core.git:reset-hard\" = \"warn\"\n\
         \"heredoc.python:shutil_rmtree\" = \"warn\"\n",
    )
    .expect("write policy config");
    let mut cmd = spawn::dcg_in(&sandbox);
    cmd.env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem");
    run_hook(cmd, &sandbox, command)
}

/// The exact text the fallback denial carries. Asserted by SUBSTRING and
/// nothing else, because this string is the whole complaint: no ruleId, and a
/// reason naming content that was read.
const LEGACY_FALLBACK_REASON: &str = "Unjudged command content contains destructive pattern";

/// The rule `.agent-config-8xx4u` is about, spelled once. It is also a
/// `FALLBACK_PATTERNS` entry, which is the whole collision: the sweep and the
/// `core.git` pack both recognise it, and only one of them answers to
/// `[policy.rules]`.
const RESET_HARD: &str = "git reset --hard";

fn assert_not_denied_as_unjudged(
    command: &str,
    (stdout, stderr, exit_code): (String, String, i32),
    why: &str,
) {
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains(LEGACY_FALLBACK_REASON),
        "the fallback check re-decided content that was judged ({why})\n\
         command: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_denied_as_unjudged(
    command: &str,
    (stdout, stderr, exit_code): (String, String, i32),
    why: &str,
) {
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(LEGACY_FALLBACK_REASON),
        "unread content holding a destructive pattern must still be denied by the \
         fallback ({why})\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The measured defect. This row was RED before the fix.
// ---------------------------------------------------------------------------

/// The live instance, in shape: a python body that is pure data, made `Partial`
/// by a `<<` the extractor cannot tell from a heredoc operator.
const LIVE_INSTANCE: &str = "python3 - <<'PY'\n\
     note = \"the commit said: cleanup ran rm -rf /tmp/build-cache\"\n\
     chunk = 1 << 20\n\
     print(note, chunk)\n\
     PY";

#[test]
fn live_instance_python_data_mentioning_rm_rf_is_not_denied_as_unjudged() {
    assert_not_denied_as_unjudged(
        LIVE_INSTANCE,
        run_default(LIVE_INSTANCE),
        "the PY body WAS extracted and judged; only the phantom `20` body went unread",
    );
}

/// The floor under the row above: the `<< 20` really does make extraction
/// partial. Without this, a change that stopped producing `Partial` here would
/// turn the row above green while testing nothing at all.
#[test]
fn the_live_instance_really_does_go_partial() {
    use destructive_command_guard::heredoc::{ExtractionLimits, ExtractionResult, SkipReason};

    let limits = ExtractionLimits {
        timeout_ms: 20_000,
        ..ExtractionLimits::default()
    };
    match destructive_command_guard::heredoc::extract_content(LIVE_INSTANCE, &limits) {
        ExtractionResult::Partial {
            extracted, skipped, ..
        } => {
            assert!(
                extracted.iter().any(|c| c.content.contains("rm -rf")),
                "the body holding the text IS one of the extracted, judged entries: {extracted:?}"
            );
            assert!(
                skipped
                    .iter()
                    .any(|r| matches!(r, SkipReason::UnterminatedHeredoc { .. })),
                "the `<< 20` is what goes unread: {skipped:?}"
            );
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The two inputs the bead names. Both put a policy-WARNED rule in content that
// was judged, behind a full `max_heredocs` cap.
// ---------------------------------------------------------------------------

#[test]
fn a_warned_reset_hard_in_a_judged_inline_script_keeps_its_rule() {
    // Cold reviewer N3: `bash -c 'git reset --hard'` is the first inline
    // script, so it is extracted and judged. The eleventh filler overflows the
    // cap, so the sweep runs -- and used to re-decide the judged script as
    // unjudged, denying past `"core.git:reset-hard" = "warn"`.
    let cmd = format!("bash -c 'git reset --hard'; {}", fillers(11));
    assert_not_denied_as_unjudged(
        &cmd,
        run_with_warned_rules(&cmd),
        "the bash script was judged; the policy warns on that rule",
    );
}

#[test]
fn a_warned_rmtree_in_a_judged_inline_script_keeps_its_rule() {
    // Challenger B, in its measured shape: the destructive script is INLINE and
    // first, so it lands inside `max_heredocs` and is judged. Ten harmless
    // scripts follow; the eleventh overflows the cap and is what goes unread.
    //
    // A heredoc here instead of an inline script does NOT test this: measured
    // 2026-09-18, the inline-script pass fills the cap first, so with eleven
    // fillers the heredoc is the SKIPPED content and the sweep is right to read
    // it. That version of this row was red before AND after the fix, for the
    // correct reason, and it was testing the control, not the defect.
    let rmtree = format!(
        "python3 -c 'import shutil; {}(\"/srv/data\")'; ",
        "shutil.rmtree"
    );
    let cmd = format!("{rmtree}{}", fillers(10));
    assert_not_denied_as_unjudged(
        &cmd,
        run_with_warned_rules(&cmd),
        "the inline script was judged; the policy warns on that rule",
    );
}

// ---------------------------------------------------------------------------
// The controls. These are what a mask that is too wide breaks, and they are the
// reason the mask is collected inside the matching loop rather than from the
// extraction result.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `.agent-config-8xx4u`: the sweep read OUTER command text and hard-denied it
// as unjudged, past the policy that warned on it. Both rows were RED before
// that fix and are the reason `unread_extents` exists.
// ---------------------------------------------------------------------------

/// The bead's P2, measured on `main` 76d93747: a `1 << 20` anywhere in the
/// line made extraction `Partial`, and the sweep then hard-denied the outer
/// `RESET_HARD` -- which `"core.git:reset-hard" = "warn"` warns on, and which
/// the pack scan is about to judge under exactly that rule. P3 (the same
/// command with the python prefix removed) WARNs on both sides, which is what
/// makes the DENY a defect rather than a policy.
#[test]
fn an_outer_warned_rule_is_not_denied_as_unjudged_behind_a_phantom_heredoc() {
    let cmd = format!("python3 -c \"print(1 << 20)\" && {}", RESET_HARD);
    assert_not_denied_as_unjudged(
        &cmd,
        run_with_warned_rules(&cmd),
        "the `<< 20` is inside the JUDGED python script; the outer command is the \
         pack scan's to judge",
    );
}

/// The same claim behind a GENUINE skip, so the row above cannot be read as
/// "phantom heredocs only". Ten fillers fill the cap, so the `bash` heredoc
/// really did go unread -- and the outer command after its terminator still
/// belongs to the pack scan.
#[test]
fn a_real_unread_body_does_not_make_the_outer_command_unjudged() {
    let cmd = format!("{}bash <<'EOF'\necho hi\nEOF\n{}", fillers(10), RESET_HARD);
    assert_not_denied_as_unjudged(
        &cmd,
        run_with_warned_rules(&cmd),
        "what went unread is the `echo hi` body, not the command after it",
    );
}

#[test]
fn a_skipped_body_holding_rm_rf_still_denies() {
    // The bead's DONE WHEN. Ten fillers fill the cap, so the bash heredoc is
    // never extracted and never judged. Nothing masks it, so the sweep sees it.
    let cmd = format!("{}bash <<'EOF'\nrm -rf /srv/data\nEOF", fillers(10));
    assert_denied_as_unjudged(
        &cmd,
        run_default(&cmd),
        "the body past the cap went unread: the sweep is the only reader it has",
    );
}

#[test]
fn a_skipped_body_holding_rm_rf_still_denies_under_the_warned_config() {
    // The same input under the downgrade config, so that "the policy warns" can
    // never be read as "the fallback is off". The fallback is a fail-closed
    // backstop for UNREAD text and stays one.
    let cmd = format!("{}bash <<'EOF'\nrm -rf /srv/data\nEOF", fillers(10));
    assert_denied_as_unjudged(
        &cmd,
        run_with_warned_rules(&cmd),
        "a downgrade applies to judged rules, not to text no matcher read",
    );
}
