//! A non-literal element INSIDE a python argv list moved every word after it
//! (`.agent-config-2uqwz`).
//!
//! The python argv reader (`.agent-config-ei4it`) judges the literal SKELETON
//! of the list: an element it cannot read -- a variable, a call -- is dropped.
//! That keeps a composed target (`os.path.join("/srv", "data")` names `/srv`),
//! but it moves every later literal one place left, and a wrapper option that
//! takes a value then eats the command. In
//! `["sudo", "-u", user, <rm>, <-rf>, "/srv/x"]` the skeleton is
//! `sudo -u <rm> <-rf> /srv/x`: `-u` takes `<rm>` as its user, `<-rf>` is read
//! as a sudo flag, and `/srv/x` becomes the command. The same words as shell
//! text deny.
//!
//! The reader now also gives a POSITIONAL reading, one word per list element
//! -- the literal, or an inert stand-in for an element that is not one -- and
//! the more severe verdict of the two readings decides, the shape
//! `detect_spawn_argv` already uses for a node argv. Neither reading is right
//! alone: in `["env", spec, <rm>, ...]` the stand-in is what `env` would run,
//! so only the skeleton finds `<rm>`. Those rows are pinned here as well,
//! beside their shell-text controls.
//!
//! Accepted gaps, both misses and never a false deny: a comment holding a
//! comma inside a multi-line list is counted as elements; and a subscript
//! element (`os.environ['X']`) ends the list at its `]` before either reading
//! starts (`.agent-config-xyi3s`).
//!
//! Measured in hook mode, sandboxed by `tests/common/spawn.rs`. The first
//! column is the build of the commit this fix sits on.
//!
//! ```text
//!   row                                                        | before | here
//!   -----------------------------------------------------------|--------|------
//!   python  [sudo, -u, user, <rm>, <-rf>, /srv/x]   (bead row)  | ALLOW  | DENY
//!   control: shell  sudo -u "$U" <rm> <-rf> /srv/x              | DENY   | DENY
//!   python  [sudo, -g, grp, <rm>, <-rf>, /srv/x]                | ALLOW  | DENY
//!   python  [/usr/bin/sudo, -u, user, /bin/<rm>, <-rf>, /srv/x] | ALLOW  | DENY
//!   python  [sudo, -u, users.get(n, default), <rm>, ...]       | ALLOW  | DENY
//!   python  [sudo, -u, os.environ.get('SUDO_USER', 'root'), ...] | ALLOW | DENY
//!   python  [echo, 'a\'b)', ls]   (a closer the list never opened) | ALLOW | ALLOW
//!   python  [sudo, -u, user, git, reset, --hard]             | ALLOW  | DENY
//!   control: shell  sudo -u "$U" git reset --hard            | DENY   | DENY
//!   python  [sudo, -u, user, git, status]                    | ALLOW  | ALLOW
//!   python  [env, spec, <rm>, <-rf>, /srv/x]                    | DENY   | DENY
//!   control: shell  env "$SPEC" <rm> <-rf> /srv/x               | DENY   | DENY
//!   python  [sudo, flag, <rm>, <-rf>, /srv/x]                   | DENY   | DENY
//!   python  [<rm>, <-rf>, os.path.join('/srv', 'data')]         | DENY   | DENY
//!   python  [sudo, -u, user, ls, -la, /srv/x]                   | ALLOW  | ALLOW
//!   python  [sudo, -u, user, <rm>, <-rf>, /tmp/build]           | ALLOW  | ALLOW
//!   python  [<rm>, flag, /srv/x]                                | ALLOW  | ALLOW
//!   control: shell  <rm> "$F" /srv/x                            | ALLOW  | ALLOW
//! ```
//!
//! `<rm>` and `<-rf>` stand for the argv strings that name a recursive force
//! delete. Spelled out, this file would be a payload, and the live guard would
//! refuse to let anyone edit it.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// Assembled at runtime so this source file is not itself a payload.
fn rm() -> &'static str {
    "r\u{6d}"
}

fn recursive_force() -> &'static str {
    "-r\u{66}"
}

/// A python string literal.
fn lit(s: &str) -> String {
    format!("'{s}'")
}

/// `python3 -c` running `subprocess.run` over a list whose items are python
/// EXPRESSIONS, so a test can put a name or a call where a literal would be.
fn python_run(items: &[String]) -> String {
    format!(
        "python3 -c \"import subprocess; subprocess.run([{}])\"",
        items.join(", ")
    )
}

/// `[<prefix>..., <rm>, <-rf>, <target>]`
fn delete_after(prefix: &[&str], target: &str) -> String {
    let mut items: Vec<String> = prefix.iter().map(|s| (*s).to_string()).collect();
    items.extend([lit(rm()), lit(recursive_force()), lit(target)]);
    python_run(&items)
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

fn assert_denied_by(command: &str, rule: &str, why: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got.as_deref(),
        Some(rule),
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn assert_allowed(command: &str, why: &str) {
    let (got, stdout, stderr) = hook(command);
    assert_eq!(
        got, None,
        "{why}\ncommand: {command:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

const RM_RF_CATASTROPHIC: &str = "heredoc.python:subprocess_run.rm_rf_catastrophic";
const SHELL_RM_RF: &str = "core.filesystem:rm-rf-root-home";

// ---------------------------------------------------------------------------
// An unread option VALUE keeps its place, so the command after it is read.
// ---------------------------------------------------------------------------

#[test]
fn an_unread_sudo_user_does_not_swallow_the_command() {
    let cmd = delete_after(&["'sudo'", "'-u'", "user"], "/srv/x");
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "-u takes the unread element, not the command after it",
    );
}

#[test]
fn control_the_same_words_as_shell_text_deny() {
    let cmd = format!("sudo -u \"$U\" {} {} /srv/x", rm(), recursive_force());
    assert_denied_by(&cmd, SHELL_RM_RF, "the parity the row above is held to");
}

#[test]
fn an_unread_sudo_group_does_not_swallow_the_command() {
    let cmd = delete_after(&["'sudo'", "'-g'", "grp"], "/srv/x");
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "-g takes a value exactly as -u does",
    );
}

#[test]
fn absolute_paths_and_an_unread_value_compose() {
    let cmd = python_run(&[
        lit("/usr/bin/sudo"),
        lit("-u"),
        "user".to_string(),
        lit(&format!("/bin/{}", rm())),
        lit(recursive_force()),
        lit("/srv/x"),
    ]);
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "the basename reading and the positional reading are independent",
    );
}

#[test]
fn a_comma_inside_the_unread_value_is_not_a_list_comma() {
    // One element, `users.get(n, default)`, whose call holds a comma: it must
    // take ONE place, or the command lands one place too far right.
    let cmd = delete_after(&["'sudo'", "'-u'", "users.get(n, default)"], "/srv/x");
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "a call's comma does not separate list elements",
    );
}

#[test]
fn a_call_holding_literals_is_one_element() {
    // Two literals inside ONE element: the skeleton reads both as words and
    // `-u` takes the first; the positional reading counts the call once.
    let cmd = delete_after(
        &["'sudo'", "'-u'", "os.environ.get('SUDO_USER', 'root')"],
        "/srv/x",
    );
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "a literal nested in a call is the call's, not a list element",
    );
}

#[test]
fn an_unread_value_before_a_git_subcommand_denies() {
    // The positional reading reaches the git rule too, not only the delete.
    let cmd = python_run(&[
        lit("sudo"),
        lit("-u"),
        "user".to_string(),
        lit("git"),
        lit("reset"),
        lit("--hard"),
    ]);
    assert_denied_by(
        &cmd,
        "heredoc.python:subprocess_run.git_reset_hard",
        "-u takes the unread element, so git is read as the command",
    );
}

#[test]
fn control_the_same_git_words_as_shell_text_deny() {
    assert_denied_by(
        "sudo -u \"$U\" git reset --hard",
        "core.git:reset-hard",
        "the parity the row above is held to",
    );
}

#[test]
fn a_harmless_git_subcommand_after_an_unread_value_still_allows() {
    let cmd = python_run(&[
        lit("sudo"),
        lit("-u"),
        "user".to_string(),
        lit("git"),
        lit("status"),
    ]);
    assert_allowed(
        &cmd,
        "reading git in place must not make status destructive",
    );
}

#[test]
fn a_closer_the_list_never_opened_does_not_crash_the_reader() {
    // Valid python whose escaped quote ends the literal early, so `)` lands
    // in the text between literals with nothing open: bracket depth must not
    // underflow on text the hook was handed.
    let cmd = "python3 -c \"import subprocess; subprocess.run(['echo', 'a\\'b)', 'ls'])\"";
    assert_allowed(cmd, "a stray closer is text to read, not a crash");
}

// ---------------------------------------------------------------------------
// What the skeleton already denied must still deny: the stand-in is not
// always right, which is why both readings are judged.
// ---------------------------------------------------------------------------

#[test]
fn an_unread_env_assignment_still_denies() {
    // Positionally `env <unread> <rm> ...` runs the unread element, so only the
    // skeleton reading finds the delete.
    let cmd = delete_after(&["'env'", "spec"], "/srv/x");
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "the skeleton reading must survive the positional one",
    );
}

#[test]
fn control_env_as_shell_text_denies() {
    let cmd = format!("env \"$SPEC\" {} {} /srv/x", rm(), recursive_force());
    assert_denied_by(&cmd, SHELL_RM_RF, "the parity the row above is held to");
}

#[test]
fn an_unread_sudo_flag_still_denies() {
    let cmd = delete_after(&["'sudo'", "flag"], "/srv/x");
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "an unread flag must not become the command",
    );
}

#[test]
fn a_composed_target_still_names_itself() {
    let cmd = python_run(&[
        lit(rm()),
        lit(recursive_force()),
        "os.path.join('/srv', 'data')".to_string(),
    ]);
    assert_denied_by(
        &cmd,
        RM_RF_CATASTROPHIC,
        "ei4it's composed-target read is kept: the join opens the element its literals are in",
    );
}

// ---------------------------------------------------------------------------
// What must still be allowed.
// ---------------------------------------------------------------------------

#[test]
fn a_harmless_command_after_an_unread_value_still_allows() {
    let cmd = python_run(&[
        lit("sudo"),
        lit("-u"),
        "user".to_string(),
        lit("ls"),
        lit("-la"),
        lit("/srv/x"),
    ]);
    assert_allowed(
        &cmd,
        "reading the command in place must not make ls destructive",
    );
}

#[test]
fn a_build_dir_delete_after_an_unread_value_still_allows() {
    let cmd = delete_after(&["'sudo'", "'-u'", "user"], "/tmp/build");
    assert_allowed(&cmd, "a non-catastrophic target does not deny");
}

#[test]
fn the_stand_in_is_never_read_as_a_flag() {
    // `[<rm>, flag, /srv/x]`: the flags are unread, so nothing says this is
    // recursive or forced.
    let cmd = python_run(&[lit(rm()), "flag".to_string(), lit("/srv/x")]);
    assert_allowed(&cmd, "an unread element must not stand in for <-rf>");
}

#[test]
fn control_an_unread_flag_as_shell_text_allows() {
    let cmd = format!("{} \"$F\" /srv/x", rm());
    assert_allowed(&cmd, "the parity the row above is held to");
}
