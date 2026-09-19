//! `git commit -F -` reads its MESSAGE on stdin, so the heredoc is data
//! (`.agent-config-dcg-git-commit-f-stdin-heredoc-fp-2kp4c`).
//!
//! FOUND 2026-09-19 in real use: a session's own commit was denied because the
//! message said the rows "carry their `rm -rf` in a python body". The receiver
//! WORD is `git`, `git` is not in `NON_EXECUTING_HEREDOC_COMMANDS`, so the veto
//! set judged the message as code and `core.filesystem:rm-rf-general` denied a
//! commit. Writing the message to a file and using `git commit -F <file>` was
//! the workaround; this file is the fix.
//!
//! The answer is not "git is a data sink". `git` is a hundred subcommands, and
//! only the message ones take stdin as text — so the receiver clause asks for
//! the spelling, not the word: a `git` whose subcommand is `commit`, `tag` or
//! `notes` AND whose message flag names stdin (`-F -`, `--file -`, `--file=-`,
//! `-F-`). Everything else about the body is unchanged: the four vetoes still
//! run, so a message that really does reach an interpreter is still judged.
//!
//! WHICH ROW IS A KILL, measured by running this file against main's
//! `src/heredoc.rs` and `src/evaluator.rs` (d97ba8e1) and restoring:
//!
//! ```text
//!   row                                                        | pre-fix
//!   -------------------------------------------------------------|--------
//!   a_commit_message_on_stdin_is_data                            | RED
//!   the_long_file_spelling_is_the_same_sink                      | RED
//!   a_tag_message_on_stdin_is_data                               | RED
//!   a_note_on_stdin_is_data                                      | RED
//!   the_sink_survives_a_wrapper_a_path_and_a_global_option       | RED
//!   every CONTROL row below                                      | green
//! ```
//!
//! THE MUTANTS, each one change, each run on this tree and restored after:
//!
//! ```text
//!   mutant                                                  | rows it turns red
//!   ---------------------------------------------------------|------------------
//!   drop the `receiver_reads_stdin_as_a_message` clause      | all five kill rows
//!   accept any `-F`, not only `-F -`                         | a_message_file_that_is_not_stdin_is_not_this_sink
//!   drop the `git` name test                                 | a_foreign_command_taking_dash_f_is_not_a_git_sink
//!   drop the subcommand test                                 | a_git_subcommand_that_is_not_a_message_sink_is_not_inert
//!   drop the global-option value skip                        | the_sink_survives_a_wrapper_a_path_and_a_global_option
//! ```
//!
//! The scope rows are synthetic on purpose: they ARE the scope of the clause,
//! and only one other thing in the suite notices when it widens — the `-F`
//! mutant also turns `.agent-config-0awpo`'s two warned rows red, because
//! those rows carry their prose on `git commit -F msg.txt` and a wider sink
//! would mask it. That coupling is deliberate and named in both files.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every row carries, so a verdict difference can only come from
/// the receiver.
const TRIGGER: &str = "rm -rf /";

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

fn assert_allowed(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        !result.is_denied(),
        "should be ALLOWED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

fn assert_denied(cmd: &str, why: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_denied(),
        "should be DENIED ({why}): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

// ---------------------------------------------------------------------------
// The kill rows: a message on stdin is data.
// ---------------------------------------------------------------------------

/// The bead's own row, with the pathspec the session actually used.
#[test]
fn a_commit_message_on_stdin_is_data() {
    let cmd = format!(
        "cd /tmp/x && git commit -q -F - -- a.rs <<'EOF'\n\
         test: the rows carry their {TRIGGER} in a python body\n\nbody\nEOF"
    );
    assert_allowed(&cmd, "git stores the message, it does not run it");
}

#[test]
fn the_long_file_spelling_is_the_same_sink() {
    let cmd = format!("git commit --file=- <<'EOF'\nmessage mentioning {TRIGGER}\nEOF");
    assert_allowed(&cmd, "--file=- is -F - spelled long");
}

#[test]
fn a_tag_message_on_stdin_is_data() {
    let cmd = format!("git tag -a v1 -F - <<'EOF'\ntag message mentioning {TRIGGER}\nEOF");
    assert_allowed(&cmd, "an annotated tag's message is text");
}

#[test]
fn a_note_on_stdin_is_data() {
    let cmd = format!("git notes add -F - <<'EOF'\nnote mentioning {TRIGGER}\nEOF");
    assert_allowed(&cmd, "a note is text");
}

/// The receiver is resolved from the operator's own line, so the spellings the
/// fleet writes have to survive: a wrapper, an absolute path, and a global
/// option before the subcommand.
#[test]
fn the_sink_survives_a_wrapper_a_path_and_a_global_option() {
    for receiver in [
        "sudo git commit -F -",
        "/usr/bin/git commit -F -",
        "git -C /repo commit -F -",
    ] {
        let cmd = format!("{receiver} <<'EOF'\nmessage mentioning {TRIGGER}\nEOF");
        assert_allowed(&cmd, "the same sink, spelled differently");
    }
}

// ---------------------------------------------------------------------------
// CONTROLS. Every row here denies before the fix and must deny after it.
// ---------------------------------------------------------------------------

/// The four vetoes still run. A message that reaches a shell is code.
#[test]
fn a_message_piped_into_a_shell_is_still_code() {
    let cmd = format!("git commit -F - <<'EOF' | bash\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the body reaches bash whatever git would do with it");
}

/// An UNQUOTED delimiter expands the body before git ever sees it, so a
/// substitution in it runs.
#[test]
fn an_unquoted_delimiter_still_expands_its_substitution() {
    let cmd = format!("git commit -F - <<EOF\nmsg $({TRIGGER})\nEOF");
    assert_denied(&cmd, "the substitution runs at expansion time");
}

/// The rule, the pack and this harness can all produce the deny the kill rows
/// claim was wrong: the same body handed to a shell.
#[test]
fn the_same_body_handed_to_a_shell_denies() {
    let cmd = format!("bash <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "control: bash runs its stdin");
}

/// Scope: the sink is git's. A foreign command that happens to take `-F -` is
/// not known to store its stdin.
#[test]
fn a_foreign_command_taking_dash_f_is_not_a_git_sink() {
    let cmd = format!("notes add -F - <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "an unknown receiver is not a message sink");
}

/// Scope: the sink is the MESSAGE subcommands. Synthetic, because no shipping
/// git subcommand outside the list takes `-F -` — which is exactly why this
/// row has to be written by hand rather than found.
#[test]
fn a_git_subcommand_that_is_not_a_message_sink_is_not_inert() {
    let cmd = format!("git hook run x -F - <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "only commit, tag and notes take a message on stdin");
}

/// Scope: stdin, not a file. `-F msg.txt` leaves the heredoc unread, and this
/// row records that dcg still denies it — a boundary, not a claim that denying
/// it is right. Nothing filed writes that shape; widen it when something does.
#[test]
fn a_message_file_that_is_not_stdin_is_not_this_sink() {
    let cmd = format!("git commit -F msg.txt <<'EOF'\nmessage mentioning {TRIGGER}\nEOF");
    assert_denied(&cmd, "boundary: the message does not come from stdin");
}
