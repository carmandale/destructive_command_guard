//! A SPACE before a quoted heredoc delimiter defeats the quoted-delimiter gate
//! (`.agent-config-1vfil`).
//!
//! `cat <<'EOF'` masks its body, as spec 333 intends. `cat << 'EOF'` — the same
//! command with one space — does not, and the body reaches the matcher. Measured
//! 2026-09-02 on the installed build: ALLOW without the space, DENY with it, on a
//! body that is documentation in both cases.
//!
//! The cause is not in the gate. `evaluator.rs` masks the NORMALIZED command, and
//! `normalize_command` -> `dequote_segment_command_words` ->
//! `normalize_subcommand_token` strips matching quotes from anything that looks
//! like a subcommand word. With no space, `<<'EOF'` is one token and survives.
//! With a space, `'EOF'` is its own token, gets dequoted to `EOF`, and the gate's
//! `parse_heredoc_delimiter(..).filter(|p| p.3)` then reads an unquoted delimiter
//! that the user never wrote.
//!
//! A heredoc delimiter's quoting is not decoration — it is what decides whether
//! the shell expands the body. Dequoting it changes the meaning of the command,
//! so this is wrong independently of the gate that noticed it.
//!
//! Written from both sides. The first group pins that the spaced spellings are
//! masked; the second pins that suppressing the dequote did not also switch off
//! masking's limits — an unquoted delimiter must still expose its body, or the
//! "fix" would be a blanket mask and a far worse bug than the one it replaces.

use destructive_command_guard::heredoc::mask_non_executing_heredocs;
use destructive_command_guard::normalize::normalize_command;
use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases so a verdict difference
/// can only come from the delimiter spelling, never from the payload.
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

fn assert_allowed(cmd: &str, why: &str) {
    let r = evaluate(cmd);
    assert!(
        !r.is_denied(),
        "expected ALLOW ({why}) but it was BLOCKED\n---\n{cmd}\n---"
    );
}

fn assert_blocked(cmd: &str, why: &str) {
    let r = evaluate(cmd);
    assert!(
        r.is_denied(),
        "expected DENY ({why}) but it was ALLOWED\n---\n{cmd}\n---"
    );
}

// ---------------------------------------------------------------------------
// 1. The defect: whitespace between the operator and a quoted delimiter.
// ---------------------------------------------------------------------------

#[test]
fn a_space_before_a_quoted_delimiter_still_masks() {
    let t = trigger();
    assert_allowed(
        &format!("cat << 'EOF'\n{t}\nEOF"),
        "one space; the delimiter is quoted, so the body is data",
    );
}

#[test]
fn several_spaces_and_a_tab_before_a_quoted_delimiter_still_mask() {
    let t = trigger();
    assert_allowed(&format!("cat <<  'EOF'\n{t}\nEOF"), "two spaces");
    assert_allowed(&format!("cat <<\t'EOF'\n{t}\nEOF"), "a tab");
}

#[test]
fn a_space_before_a_double_quoted_delimiter_still_masks() {
    let t = trigger();
    assert_allowed(
        &format!("cat << \"EOF\"\n{t}\nEOF"),
        "double quotes suppress expansion of the body just as single quotes do",
    );
}

#[test]
fn the_spaced_form_masks_for_other_data_sinks_too() {
    let t = trigger();
    assert_allowed(&format!("tee f << 'EOF'\n{t}\nEOF"), "tee");
    assert_allowed(
        &format!("cat > f << 'EOF'\n{t}\nEOF"),
        "cat with a redirect",
    );
}

#[test]
fn the_dash_form_masks_with_and_without_a_space() {
    let t = trigger();
    assert_allowed(&format!("cat <<-'EOF'\n{t}\nEOF"), "<<- with no space");
    assert_allowed(&format!("cat <<- 'EOF'\n{t}\nEOF"), "<<- with a space");
}

/// The property, stated on the normalizer rather than on the verdict: a heredoc
/// delimiter's quotes must survive normalization, because they decide whether the
/// shell expands the body.
///
/// This is the assertion that names the cause. If someone later fixes the symptom
/// by special-casing the gate instead, this stays red.
#[test]
fn normalization_does_not_strip_a_heredoc_delimiters_quotes() {
    let t = trigger();
    for cmd in [
        format!("cat << 'EOF'\n{t}\nEOF"),
        format!("cat <<  'EOF'\n{t}\nEOF"),
        format!("cat << \"EOF\"\n{t}\nEOF"),
        format!("cat <<- 'EOF'\n{t}\nEOF"),
    ] {
        let normalized = normalize_command(&cmd);
        assert!(
            normalized.contains("'EOF'") || normalized.contains("\"EOF\""),
            "normalization stripped the delimiter's quotes\n  raw: {cmd:?}\n  norm: {normalized:?}"
        );
    }
}

/// And the same property read through the thing that consumes it: masking the
/// normalized form must agree with masking the raw form.
#[test]
fn masking_agrees_on_the_raw_and_the_normalized_command() {
    let t = trigger();
    for cmd in [
        format!("cat << 'EOF'\n{t}\nEOF"),
        format!("cat <<'EOF'\n{t}\nEOF"),
        format!("cat << \"EOF\"\n{t}\nEOF"),
    ] {
        let raw_masked = mask_non_executing_heredocs(&cmd).contains("rm");
        let normalized = normalize_command(&cmd);
        let norm_masked = mask_non_executing_heredocs(&normalized).contains("rm");
        assert_eq!(
            raw_masked, norm_masked,
            "masking disagrees between raw and normalized\n  raw: {cmd:?}\n  norm: {normalized:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The other side. Suppressing the dequote must not widen masking.
//    If any of these goes green-to-red-to-green by "mask everything", the fix
//    is worse than the bug.
// ---------------------------------------------------------------------------

#[test]
fn an_unquoted_delimiter_still_exposes_its_body() {
    let t = trigger();
    assert_blocked(
        &format!("cat << EOF\n$({t})\nEOF"),
        "unquoted: the shell expands the body before cat ever sees it",
    );
    assert_blocked(&format!("cat <<EOF\n$({t})\nEOF"), "unquoted, no space");
}

#[test]
fn an_executing_receiver_still_exposes_its_body() {
    let t = trigger();
    assert_blocked(
        &format!("bash << 'EOF'\n{t}\nEOF"),
        "bash executes its stdin however the delimiter is quoted",
    );
}

#[test]
fn a_quoted_delimiter_piped_into_a_shell_is_still_code() {
    let t = trigger();
    assert_blocked(
        &format!("cat << 'EOF' | bash\n{t}\nEOF"),
        "the pipeline gate must still see the shell downstream",
    );
}

#[test]
fn a_quoted_delimiter_reaching_a_shell_by_substitution_is_still_code() {
    let t = trigger();
    assert_blocked(
        &format!("eval \"$(cat << 'EOF'\n{t}\nEOF\n)\""),
        "the substitution gate must still fire on the spaced spelling",
    );
}

#[test]
fn ordinary_quoted_subcommand_words_are_still_dequoted() {
    // The dequote this fix narrows is load-bearing elsewhere: `git "reset" --hard`
    // must still normalize to `git reset --hard` so the pack rule matches.
    let normalized = normalize_command("git \"reset\" --hard HEAD~1");
    assert!(
        normalized.contains("git reset"),
        "narrowing the heredoc case must not stop dequoting real subcommand words: {normalized:?}"
    );
}

#[test]
fn a_bare_destructive_command_is_still_blocked() {
    assert_blocked(
        &trigger(),
        "the control: the matcher can still produce DENY",
    );
}
