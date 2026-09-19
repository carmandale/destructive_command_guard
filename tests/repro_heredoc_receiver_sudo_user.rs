//! A heredoc receiver is resolved through its wrapper's OPTIONS, not stopped by
//! them (`.agent-config-a09gf`).
//!
//! `extract_heredoc_target_command` skipped `sudo` (a shell wrapper) and `-u`
//! (a flag) but never the flag's ARGUMENT, so `sudo -u root python3 <<'PY'`
//! resolved its receiver to `root`. Since `88777c5c` (`.agent-config-w7xjw`)
//! `heredoc_language` asks the receiver FIRST, which made that one miss
//! reachable two ways:
//!
//!   * a user name that names no language (`root`) sends the body to a
//!     whole-line fallback, and that fallback takes the language of whatever
//!     OTHER interpreter starts the same line;
//!   * a user name that IS an interpreter (`sudo -u node python3` -- `node` is
//!     the default user in the official Node images) maps straight to that
//!     language, so the fallback never runs and nothing corrects it.
//!
//! # Why almost every row carries a `node -e '1';` prefix
//!
//! Without one these rows do not test anything. When the receiver fails to
//! resolve, `heredoc_language` falls back to `ScriptLanguage::detect` on the
//! operator's line, and `detect`'s head reader ALREADY calls
//! `normalize::strip_wrapper_prefixes` -- which has always parsed `-H`,
//! `-u root`, `--` and `env -u NAME` correctly. So a bare
//! `sudo -H -u root python3 <<'PY'` denies on a build with the fix reverted,
//! and pins nothing.
//!
//! The prefix separates the two readers. `tokenize_backwards` stops at `;`, so
//! `node` is NOT among the receiver's tokens -- but the fallback reads the
//! whole physical line and does see it. A row with the prefix can therefore
//! only deny if the receiver itself resolved to `python3`.
//!
//! The mutant this file is written against disables the delegation branch in
//! `extract_heredoc_target_command` (`if false && depth < ...`), which is the
//! pre-fix reader with a well-formed body. Under it 8 of these 16 rows go red
//! and the other 8 are named below or are controls that always denied.
//!
//! The RECEIVER rows carry no `import` line for the same reason: content
//! heuristics must not be able to rescue one. The DENY controls at the bottom
//! may and do carry one -- they assert a deny that was already there, so an
//! extra path to it cannot make them lie.
//!
//! Measured in hook mode, sandboxed like this file, `DCG_PACKS=core.git,
//! core.filesystem`, default config. The `pre` column is this file run against
//! a build with the delegation branch disabled -- the mutant, not a guess:
//!
//! ```text
//!   row                                                      | pre   | fixed
//!   ---------------------------------------------------------|-------|------
//!   node -e '1'; sudo -u root python3 <<'PY'                  | ALLOW | DENY
//!   node -e '1'; sudo -Hu root python3 <<'PY'   (bundled)     | ALLOW | DENY
//!   node -e '1'; sudo -u root -- python3 <<'PY' (terminator)  | ALLOW | DENY
//!   node -e '1'; sudo --user root python3 <<'PY' (long form)  | ALLOW | DENY
//!   node -e '1'; /usr/bin/sudo -u root python3 <<'PY' (path)  | ALLOW | DENY
//!   node -e '1'; env -u FOO python3 <<'PY'      (env's table) | ALLOW | DENY
//!   sudo -u node python3 <<'PY'    (user named node)          | ALLOW | DENY
//!   sudo -u bash python3 <<'PY'    (user named bash)          | ALLOW | DENY
//!   node -e '1'; sudo -uroot python3 <<'PY'     (glued)       | DENY  | DENY
//!   node -e '1'; sudo --user=root python3 <<'PY' (glued long) | DENY  | DENY
//!   env -S cat <<'EOF'             (argument IS the command)  | ALLOW | ALLOW
//!   sudo -u deploy python3 <<'PY'  (control)                  | DENY  | DENY
//!   sudo -u node python3 -c        (-c twin control)          | DENY  | DENY
//!   sudo -u root cat <<'EOF'       (data sink, short)         | ALLOW | ALLOW
//!   sudo --user root cat <<'EOF'   (data sink, LONG)          | DENY  | ALLOW
//!   node -e '1'; sudo --auth-type pam python3 <<'PY'          | ALLOW | DENY
//! ```
//!
//! # Two rows that do NOT discriminate, and are kept anyway
//!
//! The GLUED spellings (`-uroot`, `--user=root`) were already correct before
//! this change, for a reason that has nothing to do with it: the argument sits
//! inside the option word, so the old reader's "skip anything starting with
//! `-`" skipped the argument along with the flag. They are kept because they
//! are the spellings a careless fix breaks -- a table that always consumed the
//! next token would eat `python3` here -- but they pin the absence of a
//! regression, not the presence of the fix. Do not count them as coverage.
//!
//! # The masking widening: where it is real, and the review it was owed
//!
//! `.agent-config-a09gf` predicted that `sudo -u root cat <<'EOF'` was judged
//! before this change and masked after, and asked for the
//! `heredoc_body_is_inert` readers' review of that widening.
//!
//! In the SHORT spelling the prediction is wrong. Measured against the mutant,
//! `sudo -u root cat <<'EOF'` ALLOWs on both sides -- `strip_sudo` already
//! parsed `-u root` before this bead, so that spelling could never have shown
//! a widening. Reading only it is what made an earlier draft of this file
//! record "the widening did not reproduce".
//!
//! In the LONG spelling it is real, and the `LONG_ARG_FLAGS` table added for
//! this bead is what causes it (DENY on HEAD, ALLOW now):
//!
//! ```text
//!   sudo --user root cat <<'EOF'  + a recursive-delete body   DENY -> ALLOW
//!   sudo --user root tee FILE <<'EOF'  + the same body        DENY -> ALLOW
//!   sudo --auth-type root cat <<'EOF'  + the same body        DENY -> DENY
//! ```
//!
//! The third row is the control: `--auth-type` reached the tables only after
//! cold review 2, so on the tree those rows were measured against it still
//! took the pre-change path. On HEAD `strip_sudo` returned `None` for every
//! `--` word, so the command kept its `sudo --user root` prefix, the receiver
//! resolved to `root`, nothing was masked, and the body denied.
//!
//! **The review, recorded rather than skipped.** What newly becomes maskable
//! is exactly the members of `NON_EXECUTING_HEREDOC_COMMANDS` that survive the
//! `heredoc_body_is_inert` vetoes. None of them executes its body: `cat`
//! writes it to stdout, `tee` and `dd` write it to a file, and `sh`/`bash` are
//! not on the list. Every one was ALREADY masked in the bare `cat <<'EOF'` and
//! `sudo -u root cat <<'EOF'` spellings, so no new class of body becomes
//! inert; the long spelling stops disagreeing with the short one, which was an
//! accident of the option table and not a policy. A body handed to a receiver
//! that DOES execute still denies, and the row below measures that before it
//! asserts either ALLOW.
//!
//! What this does not make safe is `sudo --user root tee` writing a dangerous
//! FILE. Masking has never judged a data sink's payload; that is the standing
//! contract, not something this bead changed.
//!
//! Every interpreter DENY is `heredoc.python:shutil_rmtree` -- the rule the
//! body itself names -- so a deny from some other reader cannot carry a row.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

const RULE: &str = "heredoc.python:shutil_rmtree";

/// A javascript command on the same line, before the `;`. See the module docs:
/// this is what makes a row fail on a build without the fix.
const JS_PREFIX: &str = "node -e '1'; ";

/// Assembled at runtime so this source file is not itself a payload.
fn rmtree() -> String {
    format!("shutil.{}('/srv/data')", "rmtree")
}

/// A shell body, for the data-sink rows. Assembled for the same reason.
fn rm_rf() -> String {
    format!("r{} -rf /srv/data", "m")
}

/// `(ruleId, stdout, stderr)` from the hook; `ruleId` is `None` when it
/// allowed. Default policy, `core` packs, as `tests/common/spawn.rs` sets them.
fn hook(command: &str) -> (Option<String>, String, String) {
    let (mut cmd, sandbox) = spawn::dcg();
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");
    child
        .stdin
        .as_mut()
        .expect("failed to get stdin")
        .write_all(input.as_bytes())
        .expect("failed to write to stdin");
    let output = child.wait_with_output().expect("failed to wait for dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook mode exits 0 whatever the verdict\nstderr: {stderr}"
    );
    if stdout.trim().is_empty() {
        return (None, stdout, stderr);
    }
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hook stdout is not JSON ({e}): {stdout}"));
    let hook = &json["hookSpecificOutput"];
    assert_eq!(
        hook["permissionDecision"].as_str(),
        Some("deny"),
        "a printed verdict is a deny\nstdout: {stdout}"
    );
    let rule = hook["ruleId"]
        .as_str()
        .unwrap_or_else(|| panic!("deny without a ruleId: {stdout}"))
        .to_string();
    (Some(rule), stdout, stderr)
}

fn assert_denied_by_the_body(command: &str, why: &str) {
    let (rule, stdout, stderr) = hook(command);
    assert_eq!(
        rule.as_deref(),
        Some(RULE),
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (rule, stdout, stderr) = hook(command);
    assert_eq!(
        rule, None,
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// A python heredoc behind `receiver`, with a javascript command opening the
/// same line. Only a receiver that resolves to `python3` can deny this.
fn only_the_receiver_can_deny(receiver: &str) -> String {
    format!("{JS_PREFIX}{receiver} <<'PY'\n{}\nPY", rmtree())
}

// ---------------------------------------------------------------------------
// The bead's ALLOW rows, and every other spelling of the same option. Each one
// needs the receiver resolved THROUGH the wrapper's options; the fallback
// answers javascript for all of them.
// ---------------------------------------------------------------------------

#[test]
fn a_separate_sudo_user_argument_does_not_become_the_receiver() {
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo -u root python3"),
        "`root` is -u's argument; python3 receives the body",
    );
}

#[test]
fn a_bundled_sudo_option_word_does_not_become_the_receiver() {
    // `-Hu` really is one option word: -H takes nothing, -u takes `root`.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo -Hu root python3"),
        "bundled options still end at -u's argument",
    );
}

#[test]
fn a_glued_sudo_user_argument_does_not_swallow_the_interpreter() {
    // `-uroot` carries its argument inside the option word, so the NEXT token
    // is the receiver. Consuming one here would resolve to nothing at all.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo -uroot python3"),
        "-uroot carries its own argument",
    );
}

#[test]
fn the_double_dash_terminator_still_finds_the_interpreter() {
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo -u root -- python3"),
        "`--` ends sudo's options",
    );
}

#[test]
fn the_long_user_option_does_not_become_the_receiver() {
    // sudo uses getopt_long: `--user root` is as real as `-u root`, and it was
    // the spelling that survived the first fix for this bead.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo --user root python3"),
        "--user takes a separate argument",
    );
}

#[test]
fn the_glued_long_user_option_does_not_become_the_receiver() {
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo --user=root python3"),
        "--user=root carries its own argument",
    );
}

#[test]
fn the_long_auth_type_option_does_not_become_the_receiver() {
    // `-a` was in the short table from the start; its long spelling was not,
    // so this allowed while `sudo -a pam python3 <<'PY'` denied. Every entry
    // in the short ARG list needs its long twin or the gap just moves.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("sudo --auth-type pam python3"),
        "--auth-type takes a separate argument",
    );
}

#[test]
fn a_long_option_user_named_node_does_not_make_a_python_body_javascript() {
    // The interpreter-named-user regression, in the long spelling. No prefix
    // needed: the wrong receiver answers javascript by itself.
    let cmd = format!("sudo --auth-type node python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "`node` here is --auth-type's argument");
}

#[test]
fn a_path_spelled_sudo_is_still_a_wrapper() {
    // The exact-token wrapper test sent this to the file-path branch, which
    // returned `sudo` as the receiver.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("/usr/bin/sudo -u root python3"),
        "/usr/bin/sudo is sudo",
    );
}

#[test]
fn an_env_unset_argument_does_not_swallow_the_interpreter() {
    // The same defect read off `env`'s option table: `-u NAME` unsets a
    // variable, so `FOO` is an argument and `python3` is the receiver.
    assert_denied_by_the_body(
        &only_the_receiver_can_deny("env -u FOO python3"),
        "FOO is -u's argument, not the receiver",
    );
}

// ---------------------------------------------------------------------------
// The regression the receiver-first order introduced: a user NAMED after an
// interpreter is mapped to that language, and the fallback never runs. These
// need no prefix -- the wrong receiver answers by itself.
// ---------------------------------------------------------------------------

#[test]
fn a_sudo_user_named_node_does_not_make_a_python_body_javascript() {
    let cmd = format!("sudo -u node python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "`node` here is a USER, not the receiver");
}

#[test]
fn a_sudo_user_named_bash_does_not_make_a_python_body_shell() {
    let cmd = format!("sudo -u bash python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "`bash` here is a USER, not the receiver");
}

// ---------------------------------------------------------------------------
// `env -S`'s argument IS the command word, so a local flag table that "skipped
// the argument" would eat the receiver here. Kept as a smoke test and
// deliberately NOT as the design argument: masking is applied to the
// NORMALIZED command, where `strip_wrapper_prefixes` has already removed
// `env -S`, so that hypothetical reader would mask and ALLOW too. This row
// would not have caught it (cold review 2).
// ---------------------------------------------------------------------------

#[test]
fn env_dash_s_does_not_lose_its_command_to_an_argument_skip() {
    let cmd = format!("env -S cat <<'EOF'\n{}\nEOF", rm_rf());
    assert_allowed(
        &cmd,
        "-S's argument is the command word; cat still receives and masks this",
    );
}

// ---------------------------------------------------------------------------
// Controls that already denied, so the rows above are not carried by a change
// that simply denies more.
// ---------------------------------------------------------------------------

#[test]
fn a_sudo_user_that_names_no_interpreter_still_denies() {
    let cmd = format!("sudo -u deploy python3 <<'PY'\n{}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "the row that always denied");
}

#[test]
fn the_dash_c_twin_still_denies() {
    let cmd = format!("sudo -u node python3 -c \"import shutil; {}\"", rmtree());
    assert_denied_by_the_body(&cmd, "-c never went through the receiver reader");
}

#[test]
fn sudo_without_a_user_flag_still_denies() {
    let cmd = format!("sudo python3 <<'PY'\nimport shutil; {}\nPY", rmtree());
    assert_denied_by_the_body(&cmd, "no flag argument to mis-resolve");
}

// ---------------------------------------------------------------------------
// The widening this fix deliberately carries: `cat` is a data sink again.
// ---------------------------------------------------------------------------

#[test]
fn a_sudo_u_cat_body_is_masked_exactly_like_a_bare_cat_body() {
    // NOTE: measured, this row does not change across the fix -- see the
    // module docs. It guards the data-sink reading, not a widening.
    let body = rm_rf();
    let sudo_cat = format!("sudo -u root cat <<'EOF'\n{body}\nEOF");
    let bare_cat = format!("cat <<'EOF'\n{body}\nEOF");
    let sudo_bash = format!("sudo -u root bash <<'SH'\n{body}\nSH");

    // Both halves of this row assert ALLOW, so on their own they would stay
    // green if the RULE simply stopped matching. Measure that first: handed to
    // a receiver that executes, this same body must still deny.
    let (executed_rule, ex_out, ex_err) = hook(&sudo_bash);
    // Pinned by EQUALITY, not by a prefix: the matching rule lives in the
    // filesystem pack, not a `heredoc.` namespace. What proves the body went
    // through the heredoc reader is the deny reason, which reads
    // "(line 1 of heredoc)" -- the receiver resolved to `bash`, the body was
    // extracted, and the extracted line matched. A different id here means
    // either masking swallowed an EXECUTING receiver's body or the rule
    // stopped matching, and in both cases the two ALLOW rows below would be
    // green over nothing.
    assert_eq!(
        executed_rule.as_deref(),
        Some("core.filesystem:rm-rf-root-home"),
        "`sudo -u root bash` executes this body, so it must still deny\n\
         stdout: {ex_out}\nstderr: {ex_err}"
    );

    // The masking baseline, measured rather than assumed.
    assert_allowed(&bare_cat, "cat never executes its body");

    assert_allowed(
        &sudo_cat,
        "`sudo -u root cat` is the same data sink as `cat`; resolving the \
         receiver past -u's argument is what makes the two agree",
    );
}

/// The widening, pinned in the spelling where it is REAL. See the module docs:
/// this row is DENY on HEAD and ALLOW here, and it is the one the tracker
/// asked to have reviewed. The `bash` half measures that the same body still
/// denies at a receiver that executes, so this cannot go green because the
/// rule stopped matching.
#[test]
fn a_long_option_sudo_cat_body_is_masked_like_a_bare_cat_body() {
    let body = rm_rf();

    let (executed, ex_out, ex_err) = hook(&format!("sudo --user root bash <<'SH'\n{body}\nSH"));
    assert_eq!(
        executed.as_deref(),
        Some("core.filesystem:rm-rf-root-home"),
        "`sudo --user root bash` executes this body, so it must still deny\n\
         stdout: {ex_out}\nstderr: {ex_err}"
    );

    assert_allowed(
        &format!("sudo --user root cat <<'EOF'\n{body}\nEOF"),
        "cat is a data sink however the user option is spelled",
    );
    assert_allowed(
        &format!("sudo --user root tee /tmp/a09gf-x <<'EOF'\n{body}\nEOF"),
        "tee writes this body to a file; nothing runs it",
    );
}

#[test]
fn a_benign_sudo_u_python_body_is_still_allowed() {
    assert_allowed(
        "sudo -u root python3 <<'PY'\nprint(1)\nPY",
        "reading the body as python is not denying every python body",
    );
}
