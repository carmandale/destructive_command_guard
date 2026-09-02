//! A data-sink heredoc reaching a shell through a SUBSTITUTION (`.agent-config-baqrr`).
//!
//! `.agent-config-j6ha9` closed the pipeline half of this class: `cat <<'EOF' | bash`.
//! Its gate reads the pipeline the heredoc's stdout flows into, so it cannot see a
//! route that never uses stdout at all. Four such routes were measured ALLOW on the
//! live v0.4.2 build on 2026-09-02, with the pipeline gate already installed:
//!
//! ```text
//! eval "$(cat <<'EOF' ... EOF)"          the substitution's text is executed
//! bash <(cat <<'EOF' ... EOF)            the substitution names a file bash runs
//! V=$(cat <<'EOF' ... EOF); eval "$V"    captured first, executed after
//! $(cat <<'EOF' ... EOF)                 the result IS the command word
//! ```
//!
//! In every one the heredoc's receiver is `cat`, so the receiver-only decision masked
//! the body out of the matcher and every rule in every pack was unreachable.
//!
//! Written from both sides on purpose, the same way the pipeline repro is. The first
//! group pins that the body is now seen; the second pins that the masking spec 333
//! exists to provide did not go with it. Deleting the new predicate's call sites turns
//! the first group red; widening it to "any `$(`" turns the second group red — and the
//! second group is not decoration, it is the shape the census found 56 times in real
//! traffic.

use destructive_command_guard::heredoc::{
    heredoc_substitution_result_is_executed, mask_non_executing_heredocs,
};
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases so a verdict difference
/// can only come from the substitution, never from the payload.
///
/// Assembled rather than written literally: the live guard denies this source file
/// being written by an agent otherwise, which is the guard working.
fn trigger() -> String {
    format!("rm -{}f /", "r")
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

fn assert_body_visible(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        masked.contains(&trigger()),
        "body was masked away, so no rule can read it ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

fn assert_body_masked(cmd: &str, why: &str) {
    let masked = mask_non_executing_heredocs(cmd);
    assert!(
        !masked.contains(&trigger()),
        "body should stay masked ({why}): {cmd:?}\nmasked: {masked:?}"
    );
}

/// `cmd <<'EOF'` with the trigger as its body, wrapped by the caller.
fn sink(receiver: &str) -> String {
    format!("{receiver} <<'EOF'\n{}\nEOF\n", trigger())
}

// ---------------------------------------------------------------------------
// The bypass: the body reaches an interpreter and must be readable by the packs.
// ---------------------------------------------------------------------------

#[test]
fn eval_of_a_command_substitution_is_code() {
    let cmd = format!("eval \"$({})\"", sink("cat"));
    assert_body_visible(&cmd, "eval executes the substitution's text");
    assert_denied(&cmd, "eval executes the substitution's text");
}

#[test]
fn eval_of_a_backtick_substitution_is_code() {
    let cmd = format!("eval \"`{}`\"", sink("cat"));
    assert_body_visible(&cmd, "backticks are a command substitution too");
    assert_denied(&cmd, "backticks are a command substitution too");
}

#[test]
fn a_process_substitution_run_by_a_shell_is_code() {
    for shell in ["bash", "sh", "zsh", "dash", "ksh", "/bin/bash", "/bin/sh"] {
        let cmd = format!("{shell} <({})", sink("cat"));
        assert_body_visible(&cmd, "the shell opens and runs the substitution's file");
        assert_denied(&cmd, "the shell opens and runs the substitution's file");
    }
}

#[test]
fn sourcing_a_process_substitution_is_code() {
    for verb in ["source", "."] {
        let cmd = format!("{verb} <({})", sink("cat"));
        assert_body_visible(&cmd, "source runs the substitution's file in this shell");
        assert_denied(&cmd, "source runs the substitution's file in this shell");
    }
}

#[test]
fn a_shell_with_dash_c_executes_the_substitution() {
    for shell in ["bash", "sh", "zsh"] {
        let cmd = format!("{shell} -c \"$({})\"", sink("cat"));
        assert_body_visible(&cmd, "-c makes the argument a program");
        assert_denied(&cmd, "-c makes the argument a program");
    }
}

#[test]
fn a_substitution_in_command_position_is_code() {
    // Nothing consumes the result: the shell runs it as the command word.
    let cmd = format!("$({})", sink("cat"));
    assert_body_visible(&cmd, "the substitution IS the command");
    assert_denied(&cmd, "the substitution IS the command");
}

#[test]
fn a_variable_captured_then_evaluated_is_code() {
    for tail in ["eval \"$V\"", "eval \"${V}\"", "bash -c \"$V\""] {
        let cmd = format!("V=$({}); {tail}", sink("cat"));
        assert_body_visible(&cmd, "the capture is executed later in the same command");
        assert_denied(&cmd, "the capture is executed later in the same command");
    }
}

#[test]
// `${V:-}` and friends are SHELL expansions in a plain string literal, not Rust
// formatting arguments. clippy cannot tell the two apart from the outside.
#[allow(clippy::literal_string_with_formatting_args)]
fn an_expansion_with_a_modifier_still_names_the_capture() {
    // Substring matching on `$V` missed every modified expansion. `${V:-}` was
    // the one row that survived the cold review's re-measurement of the round-2
    // fix, dispositioned there as an accepted cost; it is not a cost any more.
    for tail in [
        "eval \"${V:-}\"",
        "eval \"${V^^}\"",
        "eval \"${V// /}\"",
        "eval \"${V#x}\"",
    ] {
        let cmd = format!("V=$({}); {tail}", sink("cat"));
        assert_body_visible(&cmd, "a modifier does not make it a different variable");
        assert_denied(&cmd, "a modifier does not make it a different variable");
    }
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn a_longer_variable_name_is_a_different_variable() {
    // The other direction of the same defect: `$VERBOSE` contains `$V` as a
    // substring and is not this capture.
    for tail in ["eval \"$VERBOSE\"", "eval \"${V2}\"", "eval \"$V_X\""] {
        let cmd = format!("V=$({}); {tail}", sink("cat"));
        assert_body_masked(&cmd, "a longer name is not this capture");
    }
}

#[test]
fn an_env_assignment_does_not_hide_the_executing_word() {
    let cmd = format!("LC_ALL=C eval \"$({})\"", sink("cat"));
    assert_body_visible(&cmd, "NAME=value is not the command word");
    assert_denied(&cmd, "NAME=value is not the command word");
}

#[test]
fn nesting_does_not_hide_the_outer_executor() {
    // The innermost substitution's enclosing command is `printf`, a data sink.
    // The body still reaches `eval`, so every open level has to be consulted.
    let cmd = format!("eval \"$(printf '%s' \"$({})\")\"", sink("cat"));
    assert_body_visible(&cmd, "the outer level is the one that executes");
    assert_denied(&cmd, "the outer level is the one that executes");
}

#[test]
fn a_herestring_into_an_executed_substitution_is_code() {
    let cmd = format!("eval \"$(cat <<<'{}')\"", trigger());
    let masked = mask_non_executing_heredocs(&cmd);
    assert!(
        masked.contains(&trigger()),
        "here-string body was masked away: {cmd:?}\nmasked: {masked:?}"
    );
    assert_denied(&cmd, "a here-string is the same class");
}

// ---------------------------------------------------------------------------
// Round 2 — the blind cold review's confirmed bypasses (`baqrr-coldrev-*`).
//
// The first version of this gate read the enclosing command word as "the first
// whitespace token", balanced `)` against pushes it never made, honoured an
// apostrophe inside double quotes, and matched only a BARE `NAME=$( )`. Each of
// those is a prefix or a spelling that switches the whole gate off, and the
// suite was green because every case it pinned happened to use the one spelling
// that worked.
// ---------------------------------------------------------------------------

#[test]
fn a_redirection_prefix_does_not_hide_the_command_word() {
    for prefix in [">/dev/null", "2>/dev/null", "&>/dev/null", "<in.txt"] {
        let cmd = format!("{prefix} eval \"$({})\"", sink("cat"));
        assert_body_visible(&cmd, "a redirection is not a command word");
        assert_denied(&cmd, "a redirection is not a command word");
    }
}

#[test]
fn a_keyword_prefix_does_not_hide_the_command_word() {
    for cmd in [
        format!("if true; then eval \"$({})\"; fi", sink("cat")),
        format!("! eval \"$({})\"", sink("cat")),
        format!("time eval \"$({})\"", sink("cat")),
        format!("for f in x; do eval \"$({})\"; done", sink("cat")),
        format!("while true; do eval \"$({})\"; done", sink("cat")),
        format!("{{ eval \"$({})\"; }}", sink("cat")),
        format!("( eval \"$({})\" )", sink("cat")),
    ] {
        assert_body_visible(&cmd, "a reserved word is not the command word");
        assert_denied(&cmd, "a reserved word is not the command word");
    }
}

#[test]
fn a_group_inside_a_substitution_does_not_close_it() {
    // `(` and `{` open a level that the matching `)`/`}` must close. Without
    // that, the group's `)` pops the `$(` and the heredoc looks top-level.
    for cmd in [
        format!("eval \"$( (true) ; {})\"", sink("cat")),
        format!("eval \"$(sleep $((0)); {})\"", sink("cat")),
        format!("eval \"$({{ true; }}; {})\"", sink("cat")),
        format!("eval \"$(f() {{ true; }}; {})\"", sink("cat")),
    ] {
        assert_body_visible(&cmd, "a group's close is not the substitution's close");
        assert_denied(&cmd, "a group's close is not the substitution's close");
    }
}

#[test]
fn an_apostrophe_inside_double_quotes_is_not_a_quote() {
    // Inside `" "`, a `'` is an ordinary character. Treating it as opening a
    // literal span swallows the rest of the command, including the heredoc.
    let cmd = format!("eval \"it's fine ; $({})\"", sink("cat"));
    assert_body_visible(&cmd, "an apostrophe in double quotes opens nothing");
    assert_denied(&cmd, "an apostrophe in double quotes opens nothing");
}

#[test]
fn every_spelling_of_the_capture_is_code() {
    // The bare `V=$( )` was the one spelling the first suite pinned, and the
    // only one that worked. `V="$( )"` is what shellcheck pushes people toward.
    for head in [
        "V=$",
        "V=\"$",
        "export V=$",
        "local V=$",
        "declare V=$",
        "readonly V=$",
    ] {
        let close = if head.contains('"') { "\"" } else { "" };
        let cmd = format!("{head}({}){close}; eval \"$V\"", sink("cat"));
        assert_body_visible(&cmd, "the capture is executed regardless of spelling");
        assert_denied(&cmd, "the capture is executed regardless of spelling");
    }
}

// ---------------------------------------------------------------------------
// The cost: what spec 333 exists to protect must still be masked.
//
// These are not hypotheticals. `baqrr-census.py` counted, across spec 333's two
// populations, 41 `git commit -m "$(cat <<'EOF' ...)"` rows and 15
// `br create -d "$(cat <<'EOF' ...)"` rows. Turning those into denials is a
// worse defect than the bypass this file closes.
// ---------------------------------------------------------------------------

#[test]
fn a_plain_capture_is_still_data() {
    let cmd = format!("V=$({})", sink("cat"));
    assert_body_masked(&cmd, "captured and never executed");
}

#[test]
fn a_capture_that_is_only_printed_is_still_data() {
    let cmd = format!("V=$({}); echo \"$V\"", sink("cat"));
    assert_body_masked(&cmd, "echo is not an executor");
}

#[test]
fn an_eval_of_a_different_variable_is_still_data() {
    // The variable check is name-specific: an `eval` in the remainder that names
    // some OTHER variable says nothing about this heredoc.
    let cmd = format!("V=$({}); eval \"$OTHER\"", sink("cat"));
    assert_body_masked(&cmd, "the eval does not name this capture");
}

#[test]
fn the_commit_message_idiom_is_still_data() {
    for enclosing in [
        "git commit -m",
        "git commit -q -m",
        "br create \"a title\" -d",
        "gh pr create --body",
        "curl -d",
        "jq --arg body",
        "echo",
        "printf '%s'",
    ] {
        let cmd = format!("{enclosing} \"$({})\"", sink("cat"));
        assert_body_masked(&cmd, "an argument is not a program");
    }
}

#[test]
fn a_dash_c_flag_on_a_non_shell_is_still_data() {
    // `git -c` and `docker -c` are configuration flags, not program text.
    for enclosing in ["git -c user.name=x commit -m", "docker -c ctx exec -e"] {
        let cmd = format!("{enclosing} \"$({})\"", sink("cat"));
        assert_body_masked(&cmd, "-c only means 'a program follows' for a shell");
    }
}

#[test]
fn a_process_substitution_into_a_data_sink_is_still_data() {
    for enclosing in ["diff", "cmp", "comm -12", "wc -l", "grep -f"] {
        let cmd = format!("{enclosing} <({}) other.txt", sink("cat"));
        assert_body_masked(
            &cmd,
            "the enclosing command reads the file, it does not run it",
        );
    }
}

#[test]
fn a_bare_heredoc_is_untouched_by_this_gate() {
    assert_body_masked(&sink("cat"), "no substitution anywhere");
    assert_body_masked(&sink("tee /tmp/x"), "no substitution anywhere");
}

#[test]
fn arithmetic_expansion_does_not_leave_a_level_open() {
    // Named for what it actually pins. `baqrr-mutants.py` M9 deletes the `$((`
    // guard and this stays green, because the mutated scanner pushes a level at
    // `$(` and pops it at the first `)` of `))` -- so the heredoc sees no open
    // substitution either way. The guard encodes a true fact about bash and is
    // kept, but no case in this file can observe it, and claiming otherwise in
    // the test's name would be a false label.
    let cmd = format!("echo $((1 + 2)) && cat <<'EOF'\n{}\nEOF\n", trigger());
    assert_body_masked(&cmd, "arithmetic leaves nothing open at the heredoc");
}

#[test]
fn a_single_quoted_dollar_paren_opens_nothing() {
    // Asserted on the PREDICATE, not on the masking, and the difference matters.
    //
    // The property needs an executor as the enclosing command word with no
    // separator before the heredoc -- `echo` there passes whether or not single
    // quotes are honoured, which is how `baqrr-mutants.py` M8 survived the first
    // version of this test. But that same shape makes `eval` the heredoc's
    // OWNING command, and dcg's receiver resolution is being fixed separately
    // (`d45752f` on the union branch, `.agent-config-n8u79`). Under the better
    // resolution `eval` owns the body, it is correctly not masked, and a
    // masking assertion here would fail for a reason that has nothing to do with
    // quoting.
    //
    // So this asserts what it is actually about. The predicate must not see an
    // open substitution, whoever ends up owning the heredoc.
    let cmd = format!(
        "eval 'this $( is literal text' cat <<'EOF'\n{}\nEOF\n",
        trigger()
    );
    let at = cmd.find("<<").expect("the heredoc operator");
    assert!(
        !heredoc_substitution_result_is_executed(&cmd, at),
        "a substitution cannot open inside single quotes: {cmd:?}"
    );
}

// ---------------------------------------------------------------------------
// The pipeline gate must be unaffected in both directions.
// ---------------------------------------------------------------------------

#[test]
fn the_pipeline_gate_still_denies_and_still_masks() {
    // The pipe belongs on the OPERATOR's line: the body starts on the next one.
    let piped = format!("cat <<'EOF' | bash\n{}\nEOF\n", trigger());
    assert_body_visible(&piped, "j6ha9's case, unchanged");
    assert_denied(&piped, "j6ha9's case, unchanged");

    let to_sink = format!("cat <<'EOF' | jq .\n{}\nEOF\n", trigger());
    assert_body_masked(&to_sink, "j6ha9's data case, unchanged");
}
