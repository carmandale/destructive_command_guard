//! A here-string is ALSO read in its receiver's language (`.agent-config-7vu4q`).
//!
//! `extract_herestrings` labelled every here-string `ScriptLanguage::Bash`
//! whatever received it, from the day Tier 2 landed (891722e8, commented
//! "Here-strings are bash-specific"). The OPERATOR is bash; the bytes it
//! carries are read by the command on its left. So `python3 <<< "<a python
//! rmtree>"` handed a python program to the bash readers, no python rule ran,
//! and the command was ALLOWED -- while the same body as a heredoc or as
//! `python3 -c` denied by `heredoc.python:shutil_rmtree`.
//!
//! The fix ADDS the receiver's reading beside the bash one. Three shapes were
//! tried, each measured in hook mode on a 76d93747 build (the last column's two
//! cap rows by the cold review; a blank cell was not measured):
//!
//! ```text
//!   row                                          | base  | receiver-only | slot per reading
//!   ---------------------------------------------|-------|---------------|-----------------
//!   python3 <<< "import shutil; rmtree"          | ALLOW | DENY python   | DENY python
//!   python3 -c 'os.system(stdin)' <<< '<rm -rf>' | DENY  | ALLOW         | DENY
//!   perl -e 'system(<STDIN>)' <<< '<rm -rf>'     | DENY  | ALLOW         | DENY
//!   8 scripts; -c 'os.system(stdin)' <<< clean   | DENY  |               | ALLOW
//!   5x python3 <<< 'print(1)'; bash <<< clean    | DENY  |               | ALLOW
//! ```
//!
//! Receiver-only dropped the bash reading, which is what catches a program
//! that hands its stdin to a shell. Reserving a `max_heredocs` slot for each
//! reading dropped both readings when one slot was left, and five harmless
//! python here-strings filled a cap of ten (found by the cold review). So the
//! receiver reading rides on the construct the cap already admitted, and the
//! cap counts constructs. The double-quoted `"$(...)"` expansion the bead
//! worried about never needed the bash reading: it denies in every column, from
//! the ordinary pack evaluation over the unmasked command.
//!
//! The language comes from `heredoc_language`, the reader heredoc bodies use,
//! its pipeline stage read from the first `|` after the operand. One reader,
//! so its residuals are both forms' (`.agent-config-a09gf`, `.agent-config-y2d40`
//! and the others its doc names); each twin row here asserts the heredoc form
//! denies by the named rule before it asserts the here-string does. The
//! receiver reading carries no span, so it masks nothing from the fallback
//! sweep (the bash reading may have been dropped unread) and is never
//! confidence-scored as quoted data.
//!
//! WHICH ROW KILLS WHICH MUTANT is recorded in the bead's close reason and the
//! coordinator log with the raw runner output, not here, so this header cannot
//! drift from a run nobody repeated. The controls and floors are green under
//! every mutant: they say the harness can deny at all and that the fix did not
//! buy its green by changing what data sinks and `$(...)` answer.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::{Command, Stdio};

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The python body the python rows carry. Identical across rows on purpose,
/// so a verdict difference can only come from how the body reaches python.
const IMPORT_RMTREE: &str = "import shutil; shutil.rmtree('/srv/data')";

/// The same call with no `import` line, spelled for a single-quoted operand.
/// Content heuristics call any body with an `import` line python, so only this
/// body proves the COMMAND side named the language.
const BARE_RMTREE: &str = "shutil.rmtree(\"/srv/data\")";

const PYTHON_RMTREE_RULE: &str = "heredoc.python:shutil_rmtree";
const GIT_CLEAN_RULE: &str = "core.git:clean-force";

/// One harmless inline script: one construct against `max_heredocs` (10).
const FILLER: &str = "python3 -c 'print(1)'; ";

/// A program that runs its stdin as shell.
const EXEC_STDIN: &str = "python3 -c 'import os,sys; os.system(sys.stdin.read())'";

/// Ordinary python that shells out through a pipeline, then deletes. The `|`
/// is inside a string literal: it is code, not a pipeline the here-string feeds.
const PIPE_IN_CODE: &str = "os.system(\"ls | node x.js\"); shutil.rmtree(\"/srv/data\")";

/// Run the real hook in the spawn sandbox. `None` is an allow; `Some` is the
/// deny's `(ruleId, stdout)` -- an empty ruleId is the fallback sweep.
fn hook(command: &str) -> Option<(String, String)> {
    let (cmd, sandbox) = spawn::dcg();
    hook_in(cmd, &sandbox, command)
}

/// The same, with `config` as the sandbox's `$XDG_CONFIG_HOME/dcg/config.toml`.
fn hook_with_config(command: &str, config: &str) -> Option<(String, String)> {
    let sandbox = spawn::sandbox();
    let dir = sandbox.dcg_config_dir();
    std::fs::create_dir_all(&dir).expect("create sandbox dcg config dir");
    std::fs::write(dir.join("config.toml"), config).expect("write sandbox config");
    hook_in(spawn::dcg_in(&sandbox), &sandbox, command)
}

fn hook_in(mut cmd: Command, sandbox: &spawn::Sandbox, command: &str) -> Option<(String, String)> {
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write hook input");
    let output = child.wait_with_output().expect("wait for dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // dcg exits 0 for an allow AND for a deny, so a non-zero status is dcg
    // failing to answer at all. Without this, a crash reads as an allow.
    assert!(
        output.status.success(),
        "dcg exited {:?} on {command:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    if stdout.trim().is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hook output is JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "non-empty hook output must be a deny: {stdout}"
    );
    let rule = json["hookSpecificOutput"]["ruleId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Some((rule, stdout))
}

fn assert_denied_by(command: &str, want_rule: &str) {
    match hook(command) {
        Some((rule, stdout)) => assert_eq!(
            rule, want_rule,
            "denied, but by the wrong rule: {command:?}\n{stdout}"
        ),
        None => panic!("ALLOWED, want a deny by {want_rule}: {command:?}"),
    }
}

fn assert_denied(command: &str) {
    assert!(hook(command).is_some(), "ALLOWED, want a deny: {command:?}");
}

fn assert_allowed(command: &str) {
    if let Some((rule, stdout)) = hook(command) {
        panic!("DENIED as {rule:?}, want allow: {command:?}\n{stdout}");
    }
}

// ---------------------------------------------------------------------------
// The two rows the bead measured ALLOW.
// ---------------------------------------------------------------------------

#[test]
fn a_double_quoted_here_string_to_python_is_read_as_python() {
    assert_denied_by(
        &format!("python3 <<< \"{IMPORT_RMTREE}\""),
        PYTHON_RMTREE_RULE,
    );
}

#[test]
fn a_single_quoted_here_string_to_python_is_read_as_python() {
    assert_denied_by(&format!("python3 <<< '{BARE_RMTREE}'"), PYTHON_RMTREE_RULE);
}

// ---------------------------------------------------------------------------
// Receivers the word reader does not resolve. They are read by
// `heredoc_language`, the reader heredoc bodies use, so each row's heredoc twin
// denies too. Every body here has no `import` line, so the command side is
// what named python -- not content heuristics.
// ---------------------------------------------------------------------------

/// The here-string and its heredoc twin must both deny, by `rule` -- the
/// language rule, so a language-blind deny (the fallback sweep, a budget stop)
/// cannot pass for the receiver reading. The twin is asserted first: if it does
/// not deny by `rule`, the row cannot see anything.
fn assert_denied_like_its_heredoc_twin(herestring: &str, heredoc: &str, rule: &str) {
    match hook(heredoc) {
        Some((twin_rule, stdout)) => assert_eq!(
            twin_rule, rule,
            "control: the heredoc twin denied by another rule, so this row proves \
             nothing: {heredoc:?}\n{stdout}"
        ),
        None => panic!("control: the heredoc twin ALLOWED, so this row proves nothing: {heredoc:?}"),
    }
    match hook(herestring) {
        Some((got, stdout)) => assert_eq!(
            got, rule,
            "denied, but not like its heredoc twin: {herestring:?}\n{stdout}"
        ),
        None => panic!("ALLOWED while its heredoc twin denied by {rule}: {herestring:?}"),
    }
}

#[test]
fn receivers_the_word_reader_misses_are_read_like_their_heredoc_twins() {
    for (herestring, heredoc) in [
        // skipped by the word reader as a file with an extension
        (
            format!("python3.11 <<< '{BARE_RMTREE}'"),
            format!("python3.11 <<'PY'\n{BARE_RMTREE}\nPY"),
        ),
        // resolves to sudo's user; the head reader strips sudo
        (
            format!("sudo -u root python3 <<< '{BARE_RMTREE}'"),
            format!("sudo -u root python3 <<'PY'\n{BARE_RMTREE}\nPY"),
        ),
        // resolves to `cat`; the pipeline the operand feeds names python
        (
            format!("cat <<< '{BARE_RMTREE}' | python3"),
            format!("cat <<'PY' | python3\n{BARE_RMTREE}\nPY"),
        ),
        // an earlier interpreter on the line must not decide it
        (
            format!("node -e '1'; cat <<< '{BARE_RMTREE}' | python3"),
            format!("node -e '1'; cat <<'PY' | python3\n{BARE_RMTREE}\nPY"),
        ),
        (
            format!("bash -c 'echo hi'; cat <<< '{BARE_RMTREE}' | python3"),
            format!("bash -c 'echo hi'; cat <<'PY' | python3\n{BARE_RMTREE}\nPY"),
        ),
    ] {
        assert_denied_like_its_heredoc_twin(&herestring, &heredoc, PYTHON_RMTREE_RULE);
    }
}

/// A `|` inside the operand is the operand's text, not the pipeline. The
/// pipeline step now reads from the first `|` after the operand, as a heredoc's
/// reads from its operator (a here-string read from its operator on let the
/// operand pick the language, cold review 3). Both forms can still make this
/// mistake through the last step, `detect`, when the line's head names no
/// interpreter (`.agent-config-vp3z1`); every row here has a resolvable head.
#[test]
fn a_pipe_inside_the_operand_does_not_pick_the_language() {
    const RUBY_PIPE: &str =
        "require 'fileutils'; system('ls | python3 x.py'); FileUtils.rm_rf('/srv/data')";
    for (herestring, heredoc, rule) in [
        (
            format!("sudo -u root python3 <<< '{PIPE_IN_CODE}'"),
            format!("sudo -u root python3 <<'PY'\n{PIPE_IN_CODE}\nPY"),
            PYTHON_RMTREE_RULE,
        ),
        (
            format!("python3.11 <<< '{PIPE_IN_CODE}'"),
            format!("python3.11 <<'PY'\n{PIPE_IN_CODE}\nPY"),
            PYTHON_RMTREE_RULE,
        ),
        (
            format!("cat <<< '{PIPE_IN_CODE}' | python3"),
            format!("cat <<'PY' | python3\n{PIPE_IN_CODE}\nPY"),
            PYTHON_RMTREE_RULE,
        ),
        (
            format!("sudo -u root ruby <<< \"{RUBY_PIPE}\""),
            format!("sudo -u root ruby <<'RB'\n{RUBY_PIPE}\nRB"),
            "heredoc.ruby:fileutils_rm_rf.catastrophic",
        ),
    ] {
        assert_denied_like_its_heredoc_twin(&herestring, &heredoc, rule);
    }
}

/// An argument between the operand and the first `|` is not a pipeline stage.
/// Read from the operand's end, the span's first segment was the arguments, so
/// `node`, `sh` or `ruby` below named the body's language (cold review 4). A
/// heredoc's first segment is its operator, which names nothing.
#[test]
fn an_argument_after_the_operand_does_not_pick_the_language() {
    for (herestring, heredoc) in [
        (
            format!("sudo -u root python3 - <<< '{BARE_RMTREE}' node | cat"),
            format!("sudo -u root python3 - <<'PY' node | cat\n{BARE_RMTREE}\nPY"),
        ),
        (
            format!("sudo -u root python3 - <<< \"{IMPORT_RMTREE}\" node | cat"),
            format!("sudo -u root python3 - <<'PY' node | cat\n{IMPORT_RMTREE}\nPY"),
        ),
        (
            format!("sudo -u root python3 - <<< '{BARE_RMTREE}' sh | cat"),
            format!("sudo -u root python3 - <<'PY' sh | cat\n{BARE_RMTREE}\nPY"),
        ),
        (
            format!("python3.11 - <<< '{BARE_RMTREE}' ruby | tee log"),
            format!("python3.11 - <<'PY' ruby | tee log\n{BARE_RMTREE}\nPY"),
        ),
    ] {
        assert_denied_like_its_heredoc_twin(&herestring, &heredoc, PYTHON_RMTREE_RULE);
    }
}

/// The spelling `.agent-config-gt800` made extractable, end to end. Both
/// readings are built from the UNESCAPED operand, so python reads what bash
/// hands it; gt800 deferred this hook row to the receiver-language work.
#[test]
fn an_escaped_quote_in_a_double_quoted_operand_is_read_as_python() {
    assert_denied_like_its_heredoc_twin(
        "python3 <<< \"import shutil; shutil.rmtree(\\\"/srv/data\\\")\"",
        "python3 <<'PY'\nimport shutil; shutil.rmtree(\"/srv/data\")\nPY",
        PYTHON_RMTREE_RULE,
    );
}

// ---------------------------------------------------------------------------
// What a receiver-only label would lose.
// ---------------------------------------------------------------------------

/// The bash reading is what sees shell text a program hands to a shell. A
/// python label alone reads `<rm -rf>` as python, matches nothing, and allows.
#[test]
fn a_program_running_its_stdin_as_shell_still_denies_the_shell_text() {
    assert_denied_by(
        &format!("{EXEC_STDIN} <<< 'rm -rf /srv/data'"),
        "core.filesystem:rm-rf-root-home",
    );
}

/// With python the only enabled heredoc language, the bash reading is dropped
/// before any matcher, and a body over `max_body_lines` elsewhere makes the
/// extraction Partial with no locatable unread extents, so the fallback sweep
/// reads the whole command minus what was judged. Had the python reading
/// carried the shared `content_range`, it would have masked the shell text the
/// sweep is the only reader of. The `mytool` control has no receiver reading,
/// and is what says this config's sweep denies at all.
#[test]
fn a_receiver_reading_does_not_hide_the_bash_text_from_the_fallback_sweep() {
    const PYTHON_ONLY: &str = "[heredoc]\nlanguages = [\"python\"]\nmax_body_lines = 2\n";
    const OVER_THE_LINE_LIMIT: &str = "; cat <<'EOF'\na\nb\nc\nEOF";
    for receiver in ["mytool", EXEC_STDIN] {
        let command = format!("{receiver} <<< 'rm -rf /srv/data'{OVER_THE_LINE_LIMIT}");
        match hook_with_config(&command, PYTHON_ONLY) {
            // The sweep's own answer carries no ruleId. A ruleId here would mean
            // the config did not load and a pack rule answered instead, which
            // would leave this row blind to the mask it exists to catch.
            Some((rule, stdout)) => assert_eq!(
                rule, "",
                "denied, but not by the fallback sweep: {command:?}\n{stdout}"
            ),
            None => panic!("ALLOWED under a python-only config: {command:?}"),
        }
    }
}

/// A span inside the operand's quotes is confidence-scored as quoted data.
/// With `protect_critical = false` that downgraded the python deny to a WARN
/// while the heredoc twin, whose body is not quoted on the command line,
/// denied (cold review 3, B3). The receiver reading carries no span.
#[test]
fn confidence_scoring_does_not_downgrade_the_receiver_reading() {
    const CONFIDENCE: &str = "[confidence]\nenabled = true\nprotect_critical = false\n";
    for command in [
        format!("python3 <<'PY'\n{IMPORT_RMTREE}\nPY"),
        format!("python3 <<< \"{IMPORT_RMTREE}\""),
        format!("python3 <<< '{BARE_RMTREE}'"),
    ] {
        match hook_with_config(&command, CONFIDENCE) {
            Some((rule, stdout)) => assert_eq!(
                rule, PYTHON_RMTREE_RULE,
                "denied, but by the wrong rule: {command:?}\n{stdout}"
            ),
            None => panic!("ALLOWED (downgraded?) under confidence scoring: {command:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The cap counts constructs, not readings. `git clean -fdx` is not in the
// fallback sweep's pattern list, so a here-string the cap drops is ALLOWED
// here, not swept -- that is what makes these rows able to see a dropped one.
// ---------------------------------------------------------------------------

/// Five here-strings to python are five constructs, not ten.
#[test]
fn harmless_python_here_strings_do_not_fill_the_cap_for_what_follows() {
    let five = "python3 <<< 'print(1)'; ".repeat(5);
    assert_denied_by(&format!("{five}bash <<< 'git clean -fdx'"), GIT_CLEAN_RULE);
}

/// Nine constructs leave one slot, and the here-string's bash reading gets it.
#[test]
fn the_last_slot_still_admits_a_here_strings_bash_reading() {
    let eight = FILLER.repeat(8);
    assert_denied_by(
        &format!("{eight}{EXEC_STDIN} <<< 'git clean -fdx'"),
        GIT_CLEAN_RULE,
    );
}

/// And its receiver reading with it. Admitting only the bash reading would
/// mark the body read, so the fallback sweep would skip the python too.
#[test]
fn the_last_slot_admits_the_receiver_reading_with_it() {
    let nine = FILLER.repeat(9);
    assert_denied_by(
        &format!("{nine}python3 <<< \"{IMPORT_RMTREE}\""),
        PYTHON_RMTREE_RULE,
    );
}

// ---------------------------------------------------------------------------
// Controls: the same body through the two spellings that always denied. They
// are what say this hook can produce the python deny at all, so a red row
// above is the here-string path and not the harness.
// ---------------------------------------------------------------------------

#[test]
fn control_the_same_body_as_a_heredoc_denies_by_the_same_rule() {
    assert_denied_by(
        &format!("python3 <<'PY'\n{IMPORT_RMTREE}\nPY"),
        PYTHON_RMTREE_RULE,
    );
}

#[test]
fn control_the_same_body_as_dash_c_denies_by_the_same_rule() {
    assert_denied_by(
        &format!("python3 -c \"{IMPORT_RMTREE}\""),
        PYTHON_RMTREE_RULE,
    );
}

// ---------------------------------------------------------------------------
// Floors: the outer shell expands a double-quoted or bare here-string before
// python reads it, and data sinks are still data.
// ---------------------------------------------------------------------------

#[test]
fn a_substitution_in_a_here_string_to_python_still_denies() {
    assert_denied("python3 <<< \"$(rm -rf /srv/data)\"");
    assert_denied("python3 <<< \"x = 1; $(rm -rf /srv/data)\"");
    assert_denied("python3 <<< $(rm -rf /srv/data)");
    assert_denied("python3 <<< \"`rm -rf /srv/data`\"");
}

#[test]
fn a_here_string_to_a_data_sink_is_still_data() {
    assert_allowed("cat <<<'rm -rf /home/user'");
    assert_allowed("cat <<<\"rm -rf /home/user\"");
    assert_allowed("python3 <<< 'print(1)'");
    assert_allowed(&format!("read -r x <<< \"{IMPORT_RMTREE}\""));
    assert_allowed(&format!("grep shutil <<< \"{IMPORT_RMTREE}\""));
}
