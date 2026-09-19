//! A `"` inside a substitution inside a `" "` argument does not end that
//! argument (`.agent-config-dcg-walk-nested-dquote-veto-bypass-xr4v2`).
//!
//! `heredoc_output_reaches_executor` walks the line a heredoc or here-string
//! sits on to find where its output goes. Its quote arm skipped a `" "` span to
//! the next bare `"`. Inside double quotes, `$(`, `${` and a backtick each open
//! a construct whose quotes are its own, so in `"$(printf "a;b")"` that next
//! `"` opens a string INSIDE the substitution. The span ended there, `;b")"`
//! was read as unquoted, the `;` ended the pipeline, and the `| bash` after the
//! argument was never reached: a data-sink receiver whose output really feeds a
//! shell was cleared, and the body's destructive command allowed. Real bash
//! runs each kill row below as ONE pipeline (`cat <<'EOF' - "$(printf "a;b")"
//! | tr a-z A-Z` with body `hello` prints `HELLO`).
//!
//! FOUND 2026-09-19 by the cold review of `.agent-config-y2d40` (finding S3);
//! it predates that change.
//!
//! Every kill row has a single-quote twin: the same command with the inner
//! quotes made single, which never desynced. The twin proves the harness, the
//! pack and the rule can all produce the DENY a kill row claims was missing,
//! so a kill row's green means the walk changed, not that the probe went blind.
//!
//! WHICH ROW IS A KILL, measured by running this file with `src/heredoc.rs`
//! swapped for main's (305f6802) and restored:
//!
//! ```text
//!   row                                                                | pre-fix
//!   --------------------------------------------------------------------|--------
//!   a_quote_inside_a_substitution_does_not_end_the_argument             | RED
//!   a_herestring_line_is_walked_the_same_way                            | RED
//!   a_quote_inside_a_redirection_target_does_not_end_it                 | RED
//!   a_quote_inside_a_backtick_substitution_does_not_end_the_argument    | RED
//!   a_quote_inside_a_parameter_expansion_does_not_end_the_argument      | RED
//!   a_paren_does_not_close_a_parameter_expansion                        | RED
//!   an_escaped_quote_inside_the_substitution_does_not_end_its_string    | RED
//!   a_double_quote_inside_single_quotes_in_the_substitution_is_literal  | RED
//!   a_pipe_inside_the_substitution_is_not_this_pipeline                 | RED
//!   the five twins, and the_same_argument_into_a_data_sink_allows       | green
//! ```
//!
//! All fifteen are green after it. The last kill row is the other direction:
//! the desynced span read the `|` inside the substitution as a pipe and DENIED
//! a heredoc written to a file.
//!
//! THE MUTANTS, each one change, each run on this tree and restored after:
//!
//! ```text
//!   mutant                                                    | rows it turns red
//!   -----------------------------------------------------------|------------------
//!   the walk's quote arm back to "skip to the next bare quote" | all nine kill rows
//!   skip_quoted_span without its `$(` / `${` arm               | eight: not backtick
//!   skip_quoted_span without its backtick arm                  | the backtick row
//!   skip_quoted_span's `$(` arm without `${`                   | both expansion rows
//!   skip_balanced_paren counting `(` for a `${`                | the paren row only
//!   skip_balanced_paren's quote arm ignoring `\"`              | the escaped-quote row
//! ```
//!
//! The counting mutant is caught only by the paren row: without a `)` in the
//! word, a paren count runs to the end of input and the unterminated-span
//! fallback denies by accident. That is why the paren row exists.
//! `skip_quoted_span`'s own `\` step is pinned by
//! `a_pipe_inside_the_quoted_span_is_still_not_a_pipeline` in
//! tests/repro_heredoc_gate_composition.rs, which the same mutant turns red.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The rule every deny row must be decided by: the body's own `rm -rf`, read
/// because the walk found the shell. A deny by anything else would prove
/// nothing about the walk.
const RM_RF: &str = "core.filesystem:rm-rf-root-home";

/// The destructive body, assembled at run time so this file can be written
/// through a shell guarded by the binary it tests.
fn body() -> String {
    format!("{} -{} /srv/data", "rm", "rf")
}

/// `head` on its own line, then the body, then the terminator.
fn heredoc(head: &str) -> String {
    format!("{head}\n{}\nEOF", body())
}

fn run_hook(command: &str) -> (String, String, i32) {
    let (mut cmd, sandbox) = spawn::dcg();
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

fn assert_denied(command: &str, why: &str) {
    let (stdout, stderr, exit_code) = run_hook(command);
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(RM_RF),
        "expected a deny by {RM_RF} ({why})\ncommand: {command:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (stdout, stderr, exit_code) = run_hook(command);
    assert_eq!(
        exit_code, 0,
        "hook mode exits 0 whatever the verdict ({why})\nstderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "expected an allow (empty stdout) ({why})\ncommand: {command:?}\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The kill rows, each beside its single-quote twin.
// ---------------------------------------------------------------------------

/// The bead's first row: an argument after `-`.
#[test]
fn a_quote_inside_a_substitution_does_not_end_the_argument() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "$(printf "a;b")" | bash"#),
        "the `;` is inside the substitution, so `| bash` is this pipeline's",
    );
}

#[test]
fn the_single_quote_twin_of_the_argument_row_denies() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "$(printf 'a;b')" | bash"#),
        "control: single inner quotes never desynced",
    );
}

/// The same walk reads a here-string's line.
#[test]
fn a_herestring_line_is_walked_the_same_way() {
    assert_denied(
        &format!(r#"cat <<< '{}' - "$(printf "a;b")" | bash"#, body()),
        "a here-string's output reaches `| bash` past the same argument",
    );
}

#[test]
fn the_single_quote_twin_of_the_herestring_row_denies() {
    assert_denied(
        &format!(r#"cat <<< '{}' - "$(printf 'a;b')" | bash"#, body()),
        "control: single inner quotes never desynced",
    );
}

/// A redirection target is a quoted word too.
#[test]
fn a_quote_inside_a_redirection_target_does_not_end_it() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' 2>"$(echo "e;log")" | bash"#),
        "the `;` is inside the target's substitution",
    );
}

#[test]
fn the_plain_twin_of_the_redirection_row_denies() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' 2>"$(echo e.log)" | bash"#),
        "control: no inner quote at all",
    );
}

/// A backtick substitution inside `" "` has quotes of its own as well.
#[test]
fn a_quote_inside_a_backtick_substitution_does_not_end_the_argument() {
    assert_denied(
        &heredoc("cat <<'EOF' - \"`printf \"a;b\"`\" | bash"),
        "the `;` is inside the backtick substitution",
    );
}

#[test]
fn the_single_quote_twin_of_the_backtick_row_denies() {
    assert_denied(
        &heredoc("cat <<'EOF' - \"`printf 'a;b'`\" | bash"),
        "control: single inner quotes never desynced",
    );
}

/// `${NAME:-word}` quotes nest the same way.
#[test]
fn a_quote_inside_a_parameter_expansion_does_not_end_the_argument() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "${X:-"a;b"}" | bash"#),
        "the `;` is inside the expansion's default word",
    );
}

/// A bare `)` in the word is a literal to bash: a `${` is closed by its `}`,
/// not by the first `)` a parenthesis count would stop at.
#[test]
fn a_paren_does_not_close_a_parameter_expansion() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "${X:-)"a;b"}" | bash"#),
        "a `)` does not close a `${`",
    );
}

/// Inside the substitution, `\"` is an escaped quote in the inner string, not
/// its end -- whether or not the substitution is itself inside `" "`.
#[test]
fn an_escaped_quote_inside_the_substitution_does_not_end_its_string() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "$(printf "a\";b")" | bash"#),
        "the inner string is `a\";b`, and the `;` is inside it",
    );
    assert_denied(
        &heredoc(r#"cat <<'EOF' - $(printf "a\";b") | bash"#),
        "the same substitution, unquoted",
    );
}

/// A `"` inside single quotes inside the substitution is a literal, and it
/// ended the outer span just the same. Its twin is the argument row's.
#[test]
fn a_double_quote_inside_single_quotes_in_the_substitution_is_literal() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "$(printf 'a";b')" | bash"#),
        "the substitution's argument is the literal `a\";b`",
    );
}

#[test]
fn the_single_quote_twin_of_the_expansion_row_denies() {
    assert_denied(
        &heredoc(r#"cat <<'EOF' - "${X:-'a;b'}" | bash"#),
        "control: single inner quotes never desynced",
    );
}

// ---------------------------------------------------------------------------
// The data side: the fix must not buy its denies by reading more pipes.
// ---------------------------------------------------------------------------

/// The same argument feeding a data sink is still data.
#[test]
fn the_same_argument_into_a_data_sink_allows() {
    assert_allowed(
        &heredoc(r#"cat <<'EOF' - "$(printf "a;b")" | wc -l"#),
        "`wc` executes nothing",
    );
}

/// A `|` inside the substitution is the inner command's, not this pipeline's.
/// The desynced span read it as a pipe into the stage `b")"` -- an unknown
/// command, so an executor -- and denied a heredoc written to a file.
#[test]
fn a_pipe_inside_the_substitution_is_not_this_pipeline() {
    assert_allowed(
        &heredoc(r#"cat <<'EOF' - "$(printf "a|b")" > out.txt"#),
        "the only `|` is inside the substitution",
    );
}
