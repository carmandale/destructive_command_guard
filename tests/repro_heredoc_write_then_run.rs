//! A data-sink heredoc whose body is written into a shell script (`.agent-config-5xz9p`).
//!
//! dcg cannot see inside a file it is told to run. That is true of every build,
//! measured: `bash /private/tmp/x.sh` is ALLOW whatever `x.sh` contains. So for a
//! write-then-run hazard the WRITE is the only place any build could ever catch
//! it -- and once the heredoc masking gate cleared `cat > x.sh <<'EOF'` as data,
//! the route was open at every step. The cold reviewer executed it end to end in
//! a SINGLE Bash call and watched a marker fire.
//!
//! The predicate here is the sink's extension and nothing cleverer. A `.sh`
//! file's contents ARE shell and dcg's packs ARE shell patterns, so a pack
//! matching a line of one is a true positive by construction. That is not true of
//! a `.md` body, where the same match is documentation -- which is why this
//! recovers the write step without reopening the 88 documentation false positives
//! spec 333 closed.
//!
//! Written from both sides on purpose. The bypass cases pin that the body is seen
//! again; the data cases pin that the masking spec 333 exists to protect did not
//! go with it. Deleting `heredoc_body_sinks_into_shell_script`'s call sites turns
//! the first group red; widening it to "any redirect to a file" or to `.py` turns
//! the second group red.
//!
//! Every assertion is on `evaluate_command`, never on `mask_non_executing_heredocs`
//! directly. The evaluator masks the NORMALIZED command, so a masking assertion
//! measures a different string than the binary does -- which is how such a test
//! passed while the binary denied all four of its shapes (commit 141ed9a).
//!
//! The data cases write `>path` with no space, which was once load-bearing and is
//! not any more. REVISED 2026-09-06 (`.agent-config-n8u79`): the paragraph here
//! used to say `cat > path` with a space was permanently unmasked, because
//! `extract_heredoc_target_command` returned the bare `>` as the receiver, and
//! that a spaced control would therefore pass whatever this predicate did. That
//! is false against every build that ships today. Measured across the archived
//! binaries with one PreToolUse envelope per row
//! (`specs/333-dcg-heredoc-body-false-positives/artifacts/n8u79-receiver-redirect.py`):
//! `cat > f.rs <<'EOF'` carrying a destructive body was DENY on
//! `dcg-v0.4.2-34cbef71` and ALLOW on `d79302ce`, `fc25273d`, `be9a7553` and the
//! live `cd5132eb`. The walk resolves the receiver to `cat` through a redirect
//! now, so both spellings are masked and both are honest controls here.
//!
//! The spelling stays `>path` regardless -- rewriting these rows would change
//! what this file measures without adding a row. The property that paragraph
//! feared losing is pinned where it belongs, in
//! `repro_heredoc_receiver_reserved_word.rs`, under
//! `a_redirect_before_the_operator_does_not_hide_the_receiver`.

use destructive_command_guard::{Config, LayeredAllowlist, evaluate_command, packs::REGISTRY};

/// The trigger every case carries. Identical across cases so a verdict
/// difference can only come from the sink, never from the payload.
const TRIGGER: &str = "rm -rf /";

fn evaluate(
    cmd: &str,
    heredoc_analysis: bool,
) -> destructive_command_guard::evaluator::EvaluationResult {
    let mut config = Config::default();
    config.heredoc.enabled = Some(heredoc_analysis);
    config.packs.enabled = vec!["core".to_string()];

    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    evaluate_command(cmd, &config, &keywords, &overrides, &allowlists)
}

/// Both postures, every case. `HeredocSettings::default().enabled` is FALSE and
/// this fleet's `configs/dcg/config.toml` has no `[heredoc]` section, so the
/// live machine-wide guard runs tier-2 content analysis OFF -- masking is the
/// only thing between a heredoc body and a pack there. Asserting only with it ON
/// hides that: several shapes below deny under tier-2 for reasons of their own
/// and would pass whatever this predicate did. (The reason once given here --
/// that the receiver of `cat > path` tokenizes as the bare `>` -- is no longer
/// true of any shipping build; see the REVISED note in the module header.)
fn both(cmd: &str) -> [(bool, destructive_command_guard::evaluator::EvaluationResult); 2] {
    [(true, evaluate(cmd, true)), (false, evaluate(cmd, false))]
}

fn assert_denied(cmd: &str, why: &str) {
    for (analysis, result) in both(cmd) {
        assert!(
            result.is_denied(),
            "should be DENIED ({why}) with heredoc analysis {analysis}: {cmd:?}\nreason: {:?}",
            result.reason()
        );
    }
}

fn assert_allowed(cmd: &str, why: &str) {
    for (analysis, result) in both(cmd) {
        assert!(
            !result.is_denied(),
            "should be ALLOWED ({why}) with heredoc analysis {analysis}: {cmd:?}\nreason: {:?}",
            result.reason()
        );
    }
}

// ---------------------------------------------------------------------------
// The route: a heredoc body landing in a file that is shell.
// ---------------------------------------------------------------------------

#[test]
fn redirect_before_the_operator_is_a_shell_script_sink() {
    // The exact shape agent-config's tests/test-dcg-trash-verbs.sh pins, and the
    // one assertion that went red when the masking gate landed.
    let cmd = format!("cat > /private/tmp/probe.sh <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the body becomes a shell script");
}

#[test]
fn redirect_after_the_operator_is_the_same_sink() {
    // The cold reviewer's spelling. Word order is not a security boundary.
    let cmd = format!("cat <<'EOF' > /private/tmp/probe.sh\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the redirect follows the delimiter");
}

#[test]
fn redirect_with_no_space_is_the_same_sink() {
    // `>/private/tmp/probe.sh` tokenizes as one word. Measured 2026-09-02: this
    // spelling was ALREADY ALLOW on the pre-gate binary, so the old defence
    // covered exactly one way of writing the same thing.
    let cmd = format!("cat >/private/tmp/probe.sh <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "no space between the redirect and its target");
}

#[test]
fn append_redirect_is_the_same_sink() {
    let cmd = format!("cat >> /private/tmp/probe.sh <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "appending to a script is still writing one");
}

#[test]
fn tee_to_a_script_needs_no_redirect_at_all() {
    // `tee` takes its sink as an argument, so a gate that only understands `>`
    // reads this as stdout-only data.
    let cmd = format!("tee /private/tmp/probe.sh <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "tee writes the file as an argument");
}

#[test]
fn write_and_run_in_one_command_is_seen_at_the_write() {
    // Both halves inside a single Bash call. The run half is invisible to dcg on
    // every build, so this can only be caught at the write.
    let cmd = format!("cat <<'EOF' > /private/tmp/x.sh\n{TRIGGER}\nEOF\nbash /private/tmp/x.sh");
    assert_denied(&cmd, "one command string writes the hazard and runs it");
}

#[test]
fn an_uppercase_extension_is_still_a_shell_script() {
    let cmd = format!("cat > /private/tmp/PROBE.SH <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "the filesystem here is case-insensitive");
}

#[test]
fn a_quoted_sink_path_is_still_a_shell_script() {
    let cmd = format!("cat > '/private/tmp/probe.sh' <<'EOF'\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "quoting the path does not change what it is");
}

#[test]
fn a_here_string_into_a_script_is_the_same_route() {
    // Asserted with tier-2 analysis ON only, and the reason is worth stating: a
    // here-string body sits MID-LINE, and dcg's rules are line-anchored `(?im)^`,
    // so with analysis off nothing can read it whether it is masked or not. That
    // is a limit of the rule anchors, not of this gate. `>path` with no space so
    // the receiver resolves to `cat` and the body really is masked without the
    // predicate -- the spaced form denies for an unrelated reason.
    let cmd = format!("cat >/private/tmp/probe.sh <<<'{TRIGGER}'");
    let result = evaluate(&cmd, true);
    assert!(
        result.is_denied(),
        "should be DENIED (a here-string writes the file just as well): {cmd:?}\nreason: {:?}",
        result.reason()
    );
}

#[test]
fn an_unquoted_delimiter_writing_a_script_is_still_seen() {
    // Quoting the delimiter suppresses expansion. It has never had anything to
    // say about whether the result is a program.
    let cmd = format!("cat > /private/tmp/probe.sh <<EOF\n{TRIGGER}\nEOF");
    assert_denied(&cmd, "delimiter quoting is not a security boundary");
}

// ---------------------------------------------------------------------------
// The masking spec 333 exists to protect: prose sinks, and no sink at all.
// ---------------------------------------------------------------------------

#[test]
fn a_markdown_sink_is_still_documentation() {
    // This is the shape of the 88 false positives spec 333 closed. Widening the
    // gate to "any redirect to a file" reopens every one of them.
    let cmd = format!("cat >/private/tmp/notes.md <<'EOF'\n{TRIGGER}\nEOF");
    assert_allowed(&cmd, "a markdown file is prose, not a program");
}

#[test]
fn no_sink_at_all_is_still_data() {
    let cmd = format!("cat <<'EOF'\n{TRIGGER}\nEOF");
    assert_allowed(&cmd, "nothing is written anywhere");
}

#[test]
fn a_python_sink_is_deliberately_not_covered() {
    // `.py` is absent from the list on purpose: this fleet writes probe scripts
    // constantly, a Python body is not shell, and a shell pattern matching a
    // line inside one is a coincidence. Adding it here would be a new class of
    // false positive, not a new catch.
    let cmd = format!("cat >/private/tmp/census.py <<'EOF'\n{TRIGGER}\nEOF");
    assert_allowed(&cmd, "a python body is not shell");
}

#[test]
fn an_earlier_bodys_prose_cannot_unmask_a_later_heredoc() {
    // The bound that makes this safe to ship. Heredoc bodies routinely NAME a
    // `.sh` path in prose ("run bash probe.sh to reproduce"). Reading backwards
    // past the newline would let one document's text unmask the next document.
    let cmd = format!(
        "cat >/private/tmp/a.md <<'EOF'\nrun bash probe.sh to reproduce\nEOF\ncat >/private/tmp/b.md <<'EOF'\n{TRIGGER}\nEOF"
    );
    assert_allowed(&cmd, "the .sh is prose inside an earlier body");
}

#[test]
fn a_separator_puts_the_script_in_a_different_command() {
    // Found by the neighbouring suite, not by me: `cat <<'EOF' ; bash /tmp/other.sh`
    // writes the body NOWHERE -- it goes to stdout, and the `.sh` belongs to a
    // second command that runs a file this heredoc never touched. Scanning to the
    // newline read that `.sh` as this heredoc's sink and unmasked the body.
    for separator in [";", "&&", "||", "&"] {
        let cmd = format!("cat <<'EOF' {separator} bash /tmp/other.sh\n{TRIGGER}\nEOF");
        assert_allowed(&cmd, "the .sh belongs to the command after the separator");
    }
}

#[test]
fn a_separator_before_the_heredoc_is_the_same_boundary() {
    let cmd = format!("bash /tmp/other.sh ; cat <<'EOF'\n{TRIGGER}\nEOF");
    assert_allowed(&cmd, "the .sh belongs to the command before the separator");
}

#[test]
fn a_shell_script_sink_on_a_previous_line_does_not_unmask_this_one() {
    // Two separate commands, newline-separated. The first genuinely writes a
    // script; the second writes prose. Only the first should lose its mask.
    let cmd = format!(
        "cat >/private/tmp/setup.sh <<'A'\necho hi\nA\ncat >/private/tmp/notes.md <<'B'\n{TRIGGER}\nB"
    );
    assert_allowed(&cmd, "the script sink belongs to the previous command");
}
