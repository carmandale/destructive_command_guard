//! The find-delete family is judged, and judged on the same line as `rm -rf`
//! (`.agent-config-xzx79`).
//!
//! Measured 2026-09-23 on the live guard, dcg 0.4.2 at `~/.local/bin/dcg`
//! (sha256:039035c0…), 4 packs enabled and `doctor` clean:
//!
//!     find /Users/dalecarman/dev/agent-observer -type f -delete  -> ALLOW
//!     find . -type f -exec rm -f {} ;                            -> ALLOW
//!     find … -print0 | xargs -0 rm -f                            -> ALLOW
//!     rm -rf /Users/dalecarman/dev/agent-observer                -> DENY
//!
//! The first deletes every file in a git repo. Each ALLOW traced
//! `quick-rejected (no keywords)`: no pack claimed the word `find`, so the
//! command never reached full evaluation at all. The catching rule for the
//! control is named `rm-rf-root-home` — for the SPELLING, not for the act.
//!
//! The prefilter is not the defect. It is a keyword gate and it answered
//! correctly for the keyword set it was given; what was missing was a pack
//! claiming `find`. `core.find` is that pack.
//!
//! # What this file pins, and why each assertion is here
//!
//! Three shapes deny, each by its own named rule — a named rule is what
//! `dcg allow-once` and the allowlist key on, so an unnamed catch would leave
//! the legitimate case with no hatch.
//!
//! The temp line is the same line `core.filesystem` draws. That is the claim
//! most likely to rot, because the two are separate mechanisms — a structural
//! parse in `parse_rm_command`, a regex here — and nothing but
//! `temp_roots_agree_with_the_rm_pack` holds them together.
//!
//! And the false-positive floor, which is the reason the pack is narrow: a
//! guard that cries wolf gets switched off, and then it protects nothing.
//!
//! # MUTANTS — measured, not imagined
//!
//! Each row is `cargo test --test repro_find_delete_family` against a tree with
//! exactly one semantic edit in `src/packs/core/find.rs`, reverted afterwards.
//! A mutant that never applies reads as green, so the occurrence count was
//! asserted before each edit and the token grepped after.
//!
//! | # | mutant | kills |
//! |---|--------|-------|
//! | 1 | delete the `find-delete-outside-temp` rule | `shape_one_delete_action_denies`, and the `-delete` rows of the walk/allow tests keep passing — proving the kill is that rule's, not the pack's |
//! | 2 | delete the `find-exec-delete-outside-temp` rule | `shape_two_exec_delete_denies` only |
//! | 3 | delete the `find-xargs-delete-outside-temp` rule | `shape_three_xargs_delete_denies` only |
//! | 4 | drop `find` from `KEYWORDS` (leave all three rules) | every deny test — the gate, not the rules |
//! | 5 | widen the safe pattern's tail from `(?:\s+-\|\s*$)` to `(?:\s\|$)` | `a_second_root_behind_a_temp_one_is_not_exempt` |
//! | 6 | drop the double-quoted arm of the safe pattern | `temp_roots_agree_with_the_rm_pack` |
//!
//! # MUTANTS for the resolved per-user temp root (`.agent-config-o4e8j`)
//!
//! Same discipline, 2026-09-24, against `--lib` plus this harness. Each row's
//! anchor count was asserted as exactly 1 before the edit and the new token
//! grepped after, and the PANIC TEXT was read rather than the test name --
//! rows 1, 2, 3 and 6 all land inside the one big
//! `the_resolved_temp_root_agrees_with_the_rm_pack`, so a name alone would not
//! say which assertion fired.
//!
//! | # | mutant | kills, by the assertion that fired |
//! |---|--------|------------------------------------|
//! | 1 | `path_is_resolved_temp` asked about a sentinel instead of the path | the `mktemp -d` row: `rm -rf <resolved>/codex-workflow/run-1` denied as `rm-rf-root-home` |
//! | 2 | build `find_temp_root_pattern` with `&[]` resolved roots | the same path in the find spelling: denied as `find-delete-outside-temp` |
//! | 3 | separator after the root no longer required (`trim_start_matches` for `strip_prefix`) | the sibling row: `<resolved>OTHER/run-1` ALLOWED when it must deny |
//! | 4 | drop the two-segment floor in `temp_roots_from_tmpdir_value` | `a_degenerate_tmpdir_value_admits_nothing` -- `/var` becomes a scratch prefix |
//! | 5 | `tmpdir_value_ends_with_slash` reduced to `is_some()` | `a_tmpdir_without_a_trailing_slash_shuts_the_no_separator_gate` |
//! | 6 | drop the `..` guard in `path_is_resolved_temp` | the traversal row: `<resolved>/../C/run-1` ALLOWED when it must deny |
//! | 7 | never derive the `/private` twin | `a_macos_tmpdir_value_yields_both_members_of_the_private_pair` |
//!
//! Row 3 is the one worth noting: its first spelling shared an anchor with a
//! unit test and so applied to neither site, and a mutant that never applies
//! reads exactly like a mutant nothing catches.
//!
//! The raw runner output for each row is on the bead's close reason, not here.

// The `${TMPDIR}` in these command literals is shell text under test, not a
// format argument.
#![allow(
    clippy::doc_markdown,
    clippy::literal_string_with_formatting_args,
    clippy::uninlined_format_args
)]

use std::io::Write;
use std::process::Stdio;

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// The deny's rule id, or `None` for an allow (empty hook output).
///
/// This goes through the wire, not through the library: the bead's own caveat
/// was that both readings came from `dcg explain` and nobody had proved the
/// PreToolUse hook agrees. It does, and this is where that stays proved.
fn hook(command: &str) -> Option<(String, String)> {
    hook_with_tmpdir(command, None)
}

/// The per-user temp directory the resolved-root rows are written against.
///
/// A literal, not this machine's real `$TMPDIR`: `spawn::dcg` clears the
/// environment, so the child sees no `TMPDIR` unless a test hands it one, and a
/// test that read the developer's own value would assert a different thing on
/// every box. It ends in `/` because the macOS value does, which is what opens
/// the no-separator gate in
/// `core::filesystem::tmpdir_value_ends_with_slash`. It does not need to exist
/// on disk; dcg judges the text of the command, never the filesystem.
const FIXED_TMPDIR: &str = "/var/folders/2j/o4e8jtest0000gn/T/";

/// [`FIXED_TMPDIR`] without its trailing slash — how a path under it is spelled.
const FIXED_TMPDIR_ROOT: &str = "/var/folders/2j/o4e8jtest0000gn/T";

/// The deny's rule id, or `None` for an allow, with `TMPDIR` optionally set.
fn hook_with_tmpdir(command: &str, tmpdir: Option<&str>) -> Option<(String, String)> {
    let (mut cmd, sandbox) = spawn::dcg();
    if let Some(tmpdir) = tmpdir {
        cmd.env("TMPDIR", tmpdir);
    }
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

fn assert_denied_by(command: &str, rule_id: &str, why: &str) {
    match hook(command) {
        Some((rule, stdout)) => assert_eq!(
            rule, rule_id,
            "denied, but by the wrong rule ({why}): {command:?}\n{stdout}"
        ),
        None => panic!("ALLOWED, want a deny by {rule_id} ({why}): {command:?}"),
    }
}

fn assert_allowed(command: &str, why: &str) {
    if let Some((rule, stdout)) = hook(command) {
        panic!("DENIED as {rule:?}, want allow ({why}): {command:?}\n{stdout}");
    }
}

/// [`assert_allowed`] with `TMPDIR` set to [`FIXED_TMPDIR`].
fn assert_allowed_under_tmpdir(command: &str, why: &str) {
    assert_allowed_with_tmpdir(command, FIXED_TMPDIR, why);
}

/// [`assert_denied_by`] with `TMPDIR` set to [`FIXED_TMPDIR`].
fn assert_denied_by_under_tmpdir(command: &str, rule_id: &str, why: &str) {
    assert_denied_by_with_tmpdir(command, FIXED_TMPDIR, rule_id, why);
}

/// [`assert_allowed`] with `TMPDIR` set to a value the caller chooses.
fn assert_allowed_with_tmpdir(command: &str, tmpdir: &str, why: &str) {
    if let Some((rule, stdout)) = hook_with_tmpdir(command, Some(tmpdir)) {
        panic!(
            "DENIED as {rule:?}, want allow ({why}) under TMPDIR={tmpdir:?}: {command:?}\n{stdout}"
        );
    }
}

/// [`assert_denied_by`] with `TMPDIR` set to a value the caller chooses.
fn assert_denied_by_with_tmpdir(command: &str, tmpdir: &str, rule_id: &str, why: &str) {
    match hook_with_tmpdir(command, Some(tmpdir)) {
        Some((rule, stdout)) => assert_eq!(
            rule, rule_id,
            "denied, but by the wrong rule ({why}) under TMPDIR={tmpdir:?}: {command:?}\n{stdout}"
        ),
        None => {
            panic!("ALLOWED, want a deny by {rule_id} ({why}) under TMPDIR={tmpdir:?}: {command:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// The three shapes the bead named
// ---------------------------------------------------------------------------

#[test]
fn shape_one_delete_action_denies() {
    assert_denied_by(
        "find /Users/dalecarman/dev/agent-observer -type f -delete",
        "core.find:find-delete-outside-temp",
        "the bead's reproducer: this deletes every file in a git repo",
    );
    assert_denied_by(
        "find . -type f -delete",
        "core.find:find-delete-outside-temp",
        "the working directory is not scratch",
    );
    assert_denied_by(
        "find ~/dev/agent-observer -type f -delete",
        "core.find:find-delete-outside-temp",
        "a tilde root is the same root",
    );
}

#[test]
fn shape_two_exec_delete_denies() {
    assert_denied_by(
        "find . -type f -exec rm -f {} ;",
        "core.find:find-exec-delete-outside-temp",
        "there is no -rf anywhere in this, so no rm rule sees it",
    );
    assert_denied_by(
        "find . -type f -execdir rm -f {} ;",
        "core.find:find-exec-delete-outside-temp",
        "-execdir reaches the same outcome as -exec",
    );
}

#[test]
fn shape_three_xargs_delete_denies() {
    assert_denied_by(
        "find /Users/dalecarman/dev/agent-observer -name '*.swift' -print0 | xargs -0 rm -f",
        "core.find:find-xargs-delete-outside-temp",
        "the pipe makes it read like two harmless halves",
    );
    assert_denied_by(
        "find . -type f | grep foo | xargs rm -f",
        "core.find:find-xargs-delete-outside-temp",
        "an intermediate stage does not break the chain",
    );
}

// ---------------------------------------------------------------------------
// The line is the same line `rm -rf` draws
// ---------------------------------------------------------------------------

/// Every root `core.filesystem` treats as scratch, asked in both spellings.
///
/// This is the structural coupling between `parse_rm_command`'s
/// `path_is_safe_unquoted` / `path_is_safe_double_quoted` and this pack's
/// `find-temp-root` safe pattern. They cannot share code — one is a token walk,
/// the other a regex — so agreement is only ever as true as this test
/// (`.claude/rules/structural-coupling.md`).
///
/// The non-temp control at the end is what proves the probe can produce a
/// positive: without it, a `find-temp-root` that matched everything would make
/// every row here pass.
#[test]
fn temp_roots_agree_with_the_rm_pack() {
    const UNQUOTED_TEMP_ROOTS: &[&str] = &[
        "/tmp/scratch",
        "/var/tmp/scratch",
        "$TMPDIR/scratch",
        "${TMPDIR}/scratch",
        "${TMPDIR:-/tmp}/scratch",
        "${TMPDIR:-/var/tmp}/scratch",
    ];
    for root in UNQUOTED_TEMP_ROOTS {
        assert_allowed(
            &format!("rm -rf {root}"),
            "core.filesystem's temp set — the reference reading",
        );
        assert_allowed(
            &format!("find {root} -type f -delete"),
            "a path rm -rf allows is a path find -delete allows",
        );
    }

    // Inside double quotes `core.filesystem` accepts only the $TMPDIR
    // spellings: `rm -rf "/tmp/x"` is denied there, so it is denied here too.
    // This pack does not get to be more permissive than the rule it mirrors.
    const QUOTED_TEMP_ROOTS: &[&str] = &["\"$TMPDIR/build\"", "\"${TMPDIR}/build\""];
    for root in QUOTED_TEMP_ROOTS {
        assert_allowed(
            &format!("rm -rf {root}"),
            "core.filesystem's double-quoted temp set — the reference reading",
        );
        assert_allowed(
            &format!("find {root} -type f -delete"),
            "the double-quoted arm of find-temp-root",
        );
    }

    // The control. A safe pattern that matched anything would pass every row
    // above and this one would still be the only honest reading.
    assert_denied_by(
        "rm -rf /Users/dalecarman/dev/agent-observer",
        "core.filesystem:rm-rf-root-home",
        "the reference reading for a NON-temp path",
    );
    assert_denied_by(
        "find /Users/dalecarman/dev/agent-observer -type f -delete",
        "core.find:find-delete-outside-temp",
        "and the same path, the same answer, in the find spelling",
    );
}

/// The resolved per-user temp root, asked in both spellings, both arms.
///
/// `.agent-config-o4e8j`: `/var/folders/<2>/<hash>/T/` is what `mktemp -d`
/// prints, so an agent that makes scratch the standard way holds a path that
/// used to DENY while the `$TMPDIR` spelling of the SAME directory ALLOWED. This
/// is the coupling row for that fix — one `TMPDIR`, both packs, and the refusals
/// that bound it.
///
/// Every row runs with `TMPDIR` set to [`FIXED_TMPDIR`], because
/// `spawn::dcg` clears the environment; the assertions therefore read the same
/// on any machine.
#[test]
fn the_resolved_temp_root_agrees_with_the_rm_pack() {
    // ---- ALLOW: the resolved root, both members of the macOS /private pair.
    for root in [
        format!("{FIXED_TMPDIR_ROOT}/codex-workflow/run-1"),
        format!("/private{FIXED_TMPDIR_ROOT}/codex-workflow/run-1"),
    ] {
        assert_allowed_under_tmpdir(
            &format!("rm -rf {root}"),
            "the directory mktemp -d hands out is scratch by its own name",
        );
        assert_allowed_under_tmpdir(
            &format!("find {root} -type f -delete"),
            "a path rm -rf allows is a path find -delete allows",
        );
    }

    // ---- ALLOW: the ${TMPDIR:?} spellings, with and without a separator.
    // `${TMPDIR:?}` is what .claude/rules/bash-safety.md prescribes for a
    // delete target, and macOS's value already ends in `/`, so the no-separator
    // form is the one that actually gets written.
    for root in [
        "${TMPDIR:?}/run-1",
        "${TMPDIR:?}run-1",
        "${TMPDIR}run-1",
        "\"${TMPDIR:?}/run-1\"",
        "\"${TMPDIR:?}run-1\"",
        "\"${TMPDIR}run-1\"",
    ] {
        assert_allowed_under_tmpdir(
            &format!("rm -rf {root}"),
            "the guard spelling bash-safety.md asks for",
        );
        assert_allowed_under_tmpdir(
            &format!("find {root} -type f -delete"),
            "and the same spelling in the find arm",
        );
    }

    // ---- DENY: everything the carve-out must NOT reach. Each row is a way the
    // prefix test could have been written too loosely.
    let refusals: &[(String, &str)] = &[
        (
            "/var/folders".to_string(),
            "the shared parent of every user's temp dir is nobody's scratch",
        ),
        (
            "/var/folders/2j/o4e8jtest0000gn".to_string(),
            "the per-user folder ABOVE T holds the caches too",
        ),
        (
            "/var/folders/ab/someoneelse0000gn/T/run-1".to_string(),
            "another user's hash does not match this user's prefix",
        ),
        (
            format!("{FIXED_TMPDIR_ROOT}OTHER/run-1"),
            "a sibling that merely shares the prefix is not inside it",
        ),
        (
            format!("{FIXED_TMPDIR_ROOT}/../C/run-1"),
            "a traversal out of the root is not in the root",
        ),
    ];
    for (path, why) in refusals {
        assert_denied_by_under_tmpdir(
            &format!("rm -rf {path}"),
            "core.filesystem:rm-rf-root-home",
            why,
        );
        assert_denied_by_under_tmpdir(
            &format!("find {path} -type f -delete"),
            "core.find:find-delete-outside-temp",
            why,
        );
    }

    // ---- DENY: the opaque variable, which is the whole reason the literal had
    // to be named. dcg does not expand variables, so `$RUN_DIR` is never
    // scratch however the directory it holds is spelled — and the bead requires
    // this stay true, because the block it earns once stopped a delete that
    // would have taken peers' live clones.
    assert_denied_by_under_tmpdir(
        "rm -rf \"$RUN_DIR\"",
        "core.filesystem:rm-rf-general",
        "an opaque variable is not a temp root",
    );
    assert_denied_by_under_tmpdir(
        "find \"$RUN_DIR\" -type f -delete",
        "core.find:find-delete-outside-temp",
        "and it is not one in the find spelling either",
    );

    // ---- DENY: the controls. Without these a carve-out that matched anything
    // would pass every ALLOW row above and nothing here would say so.
    assert_denied_by_under_tmpdir(
        "rm -rf /",
        "core.filesystem:rm-rf-root-home",
        "the root filesystem, with TMPDIR set",
    );
    assert_denied_by_under_tmpdir(
        "rm -rf ~",
        "core.filesystem:rm-rf-root-home",
        "the home directory, with TMPDIR set",
    );
    assert_denied_by_under_tmpdir(
        "rm -rf /Users/dalecarman/dev/agent-observer",
        "core.filesystem:rm-rf-root-home",
        "an ordinary repo path, with TMPDIR set",
    );
    assert_denied_by_under_tmpdir(
        "find /Users/dalecarman/dev/agent-observer -type f -delete",
        "core.find:find-delete-outside-temp",
        "the same repo path in the find spelling, with TMPDIR set",
    );
}

/// A `TMPDIR` that does not end in `/` shuts the no-separator gate.
///
/// `${TMPDIR}run-1` and `${TMPDIR:?}run-1` are only a path under the temp root
/// because the macOS value ends in `/`. Given `/var/folders/<..>/T` instead, the
/// same spelling expands to `/var/folders/<..>/Trun-1`, which is inside nothing
/// -- and with `TMPDIR` unset, `${TMPDIR}src` expands to a RELATIVE `src`, so a
/// recursive force delete written that way inside a repo would take the repo's
/// own `src`. That is the failure this gate exists to prevent, so it is read
/// here through the wire rather than asserted in the pattern builder, which is
/// handed the flag directly and so cannot notice a gate wired to always-true.
#[test]
fn a_tmpdir_without_a_trailing_slash_shuts_the_no_separator_gate() {
    const NO_SLASH: &str = "/var/folders/2j/o4e8jtest0000gn/T";

    for command in ["rm -rf ${TMPDIR}run-1", "rm -rf ${TMPDIR:?}run-1"] {
        assert_denied_by_with_tmpdir(
            command,
            NO_SLASH,
            "core.filesystem:rm-rf-general",
            "no trailing slash, so this spelling does not name a path under the root",
        );
    }
    for command in [
        "find ${TMPDIR}run-1 -delete",
        "find ${TMPDIR:?}run-1 -delete",
    ] {
        assert_denied_by_with_tmpdir(
            command,
            NO_SLASH,
            "core.find:find-delete-outside-temp",
            "and the find arm shuts with it -- the two packs share the one answer",
        );
    }

    // The controls, same TMPDIR. The separator-carrying spellings never depended
    // on the value, so these prove the denials above are the gate closing and
    // not the carve-out having died.
    assert_allowed_with_tmpdir(
        "rm -rf ${TMPDIR:?}/run-1",
        NO_SLASH,
        "the spelling that carries its own separator is unconditional",
    );
    assert_allowed_with_tmpdir(
        "find ${TMPDIR:?}/run-1 -delete",
        NO_SLASH,
        "and so is its find spelling",
    );
    // And with a trailing slash the very same commands pass, which is the gate
    // opening rather than the rows above being refused for some other reason.
    assert_allowed_with_tmpdir(
        "rm -rf ${TMPDIR}run-1",
        FIXED_TMPDIR,
        "the identical command, one trailing slash different",
    );
    assert_allowed_with_tmpdir(
        "find ${TMPDIR}run-1 -delete",
        FIXED_TMPDIR,
        "the identical find command, one trailing slash different",
    );
}

/// With no `TMPDIR` at all, nothing under `/var/folders` is scratch.
///
/// The resolved-root carve-out is derived from the environment, so a missing or
/// degenerate value must admit NOTHING rather than admit a prefix near the root.
/// This is the fail-closed reading, and it is also why every row in
/// [`the_resolved_temp_root_agrees_with_the_rm_pack`] has to set `TMPDIR` for
/// itself.
#[test]
fn with_no_tmpdir_the_resolved_carve_out_admits_nothing() {
    for command in [
        format!("rm -rf {FIXED_TMPDIR_ROOT}/run-1"),
        format!("rm -rf /private{FIXED_TMPDIR_ROOT}/run-1"),
    ] {
        assert_denied_by(
            &command,
            "core.filesystem:rm-rf-root-home",
            "TMPDIR unset: the literal is just another absolute path",
        );
    }
    assert_denied_by(
        &format!("find {FIXED_TMPDIR_ROOT}/run-1 -type f -delete"),
        "core.find:find-delete-outside-temp",
        "TMPDIR unset: and the find spelling agrees",
    );

    // The control: the spellings that never needed the environment still pass,
    // so the rows above are the carve-out being absent and not the pack being
    // dead.
    assert_allowed(
        "rm -rf /tmp/run-1",
        "the literal temp root is unconditional",
    );
    assert_allowed(
        "find /tmp/run-1 -type f -delete",
        "and so is its find spelling",
    );
}

#[test]
fn a_traversal_out_of_a_temp_root_is_not_a_temp_root() {
    assert_denied_by(
        "find /tmp/../etc -type f -delete",
        "core.find:find-delete-outside-temp",
        "core.filesystem refuses the same path for rm -rf",
    );
}

#[test]
fn a_second_root_behind_a_temp_one_is_not_exempt() {
    assert_denied_by(
        "find /tmp/a /etc -type f -delete",
        "core.find:find-delete-outside-temp",
        "the temp carve-out ends at the first non-option operand",
    );
}

#[test]
fn a_wrapper_or_an_absolute_path_does_not_hide_the_walk() {
    assert_denied_by(
        "sudo find /etc -type f -delete",
        "core.find:find-delete-outside-temp",
        "sudo is stripped before matching",
    );
    assert_denied_by(
        "/usr/bin/find /etc -type f -delete",
        "core.find:find-delete-outside-temp",
        "the /find keyword covers an absolute path",
    );
    assert_denied_by(
        "echo start && find /etc -type f -delete",
        "core.find:find-delete-outside-temp",
        "a find after a separator is judged, not skipped",
    );
}

// ---------------------------------------------------------------------------
// The false-positive floor — the reason this pack is tolerated
// ---------------------------------------------------------------------------

#[test]
fn a_find_that_does_not_delete_is_allowed() {
    for (command, why) in [
        ("find . -name '*.log' -print", "a plain walk"),
        ("find . -type f -name '*.txt'", "a walk with no action"),
        (
            "find . -name '*.deleted'",
            "-delete is a word, not a substring",
        ),
        ("find . -maxdepth 2 -type d", "a directory listing"),
        (
            "find . -name node_modules -prune -o -print",
            "the shape every repo-wide search uses",
        ),
        (
            "find . -type f -exec chmod 644 {} ;",
            "-exec with a verb that is not a delete",
        ),
        (
            "find . -exec grep -l rm {} ;",
            "rm here is an argument, not a command",
        ),
        (
            "find . -name '*.log' | xargs grep rm",
            "xargs into a verb that is not a delete",
        ),
        ("echo find . -delete", "find named as data"),
        (
            "grep -rn \"find . -delete\" docs/",
            "searching the docs for the command",
        ),
    ] {
        assert_allowed(command, why);
    }
}

#[test]
fn deleting_under_a_temp_root_is_allowed() {
    for (command, why) in [
        ("find /tmp/scratch -type f -delete", "-delete under /tmp"),
        ("find /tmp -name '*.log' -delete", "rooted at /tmp itself"),
        (
            "find /tmp/scratch -delete",
            "no expression between the root and the action",
        ),
        (
            "find /tmp -type d -empty -delete",
            "the most common legitimate -delete there is",
        ),
        ("find /var/tmp/x -delete", "-delete under /var/tmp"),
        (
            "find /tmp/x -print0 | xargs -0 rm -f",
            "the xargs pipeline under a temp root",
        ),
    ] {
        assert_allowed(command, why);
    }
}

/// Deleting ONE named file stays ordinary work.
///
/// Called out in the bead as explicitly out of scope: this bead is about bulk
/// recursive deletion, and a guard that also blocks `rm -f ./one-file.mjs`
/// gets switched off within the day.
#[test]
fn deleting_one_named_file_is_still_allowed() {
    assert_allowed("rm -f ./observer.mjs", "one named file is ordinary work");
    assert_allowed(
        "rm -f ./observer.mjs ./other.mjs",
        "two named files are also ordinary work",
    );
}

/// The seven shapes that already denied before `core.find` existed.
///
/// A regression here is worse than the bug this pack fixes, so they are
/// re-measured in the same run rather than trusted. Under the sandbox's default
/// config — not this machine's, which sets two of them to `warn`.
#[test]
fn the_shapes_that_already_denied_still_deny() {
    for (command, rule) in [
        ("rm -rf /", "core.filesystem:rm-rf-root-home"),
        ("sudo rm -rf /usr/local", "core.filesystem:rm-rf-root-home"),
        ("git clean -fdx", "core.git:clean-force"),
        ("git reset --hard HEAD~5", "core.git:reset-hard"),
        (
            "rm -rf $HOME/.agent-config",
            "core.filesystem:rm-rf-general",
        ),
        (
            "rm -rf ~/dev/agent-observer",
            "core.filesystem:rm-rf-root-home",
        ),
        (
            "rm -rf /Users/dalecarman/dev",
            "core.filesystem:rm-rf-root-home",
        ),
    ] {
        assert_denied_by(command, rule, "denied before core.find, must deny after");
    }
}
