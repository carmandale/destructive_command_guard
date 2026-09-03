//! Every hook-mode payload under `tests/` comes from `tests/common/payload.rs`.
//!
//! Why this exists, measured rather than imagined (2026-09-02, `.agent-config-d5c7l`
//! and `.agent-config-a5aau`): 65 of the 66 hook-input literals in this tree were
//! the minimal `{"tool_name": ..., "tool_input": {...}}` object, which no real
//! `PreToolUse` invocation sends. That payload reaches `ClaudeCompatible` through
//! the final `else` in `detect_protocol`; a real one reaches it through the
//! `hook_event_name == "PreToolUse"` branch. So when dcg answered Claude Code in
//! Gemini's protocol — a correct verdict Claude Code cannot parse, which on the
//! wire is an allow — the whole suite stayed green and an 18,723-row replay
//! reported "identical". A comment saying "send the real envelope" would not
//! have caught that. This test does.
//!
//! `tests/spawn_isolation.rs` closes the environment half of the same blind
//! spot. This is the payload half, and it is deliberately the same shape: a line
//! scan, a positive control, and an honest list of what it cannot see.
//!
//! What it cannot see: a payload assembled from pieces or from a variable, a
//! spelling that is not `"tool_name"`, the unit tests under `src/` (which test
//! the parsers directly and are meant to feed them odd shapes), and the shell
//! scripts under `tests/e2e/` and `tests/scripts/`, which build their own JSON
//! and run outside cargo. It is a syntactic proxy and is meant to stay one.

use std::path::Path;

#[path = "common/payload.rs"]
mod payload;

/// The one file allowed to spell a hook payload.
const BUILDER: &str = "common/payload.rs";

/// The literal that names a hook payload in JSON, however it is written —
/// `serde_json::json!({"tool_name": ...})`, a raw string, or a `format!`.
const NEEDLE: &str = "\"tool_name\"";

/// Files whose `"tool_name"` literals are not hook-mode stdin, and why.
///
/// Each entry is a measured exemption, not a convenience. Adding one means
/// naming the reader that consumes those bytes and showing it never reaches
/// `detect_protocol`'s output shape.
const EXEMPT: &[(&str, &str)] = &[(
    "stdin_batch_mode.rs",
    "`dcg hook --batch` reads dcg's own JSONL CLI format, not an agent's hook \
     stdin. `evaluate_batch_line` in src/cli.rs binds the protocol as `_protocol` \
     and answers in `BatchHookOutput`, so no envelope field can reach an output \
     shape there — and these literals are the fixtures for that line parser, so \
     routing them through the builder would make the test a mirror of it",
)];

#[test]
fn every_hook_payload_comes_from_the_builder() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let this_file = Path::new(file!())
        .file_name()
        .expect("this file has a name");

    // Positive control: the builder must contain the spelling this scan looks
    // for, or the scan could pass over a tree where nothing builds a payload
    // the way it actually does.
    let builder = std::fs::read_to_string(tests_dir.join(BUILDER))
        .unwrap_or_else(|e| panic!("read {BUILDER}: {e}"));
    assert!(
        builder.contains(NEEDLE),
        "{BUILDER} no longer contains {NEEDLE}; the scan can no longer tell a \
         hook payload from anything else"
    );

    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(&tests_dir) {
        let entry = entry.expect("walk tests/");
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let rel = path.strip_prefix(&tests_dir).expect("path is under tests/");
        if rel == Path::new(BUILDER) || rel == Path::new(this_file) {
            continue;
        }
        if EXEMPT
            .iter()
            .any(|(name, _)| rel == Path::new(name) || rel.ends_with(name))
        {
            continue;
        }
        let source =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", rel.display()));
        for (index, line) in source.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains(NEEDLE) {
                offenders.push(format!(
                    "tests/{}:{}\n        {}",
                    rel.display(),
                    index + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} hook payload(s) are spelled outside tests/{BUILDER}. A payload \
         written by hand is the minimal {{tool_name, tool_input}} shape no real \
         PreToolUse sends, and it exercises a branch of detect_protocol that no \
         agent reaches. Build it with payload::pre_tool_use(cwd, command) or \
         payload::pre_tool_use_for_tool(cwd, tool, input) instead:\n\n{}\n",
        offenders.len(),
        offenders.join("\n")
    );
}

/// Every exemption has to say why, or the list becomes a place to hide.
#[test]
fn every_exemption_names_its_reader() {
    for (name, reason) in EXEMPT {
        assert!(
            reason.len() > 40,
            "exemption for {name} does not explain which reader consumes those \
             bytes and why the envelope cannot reach its output shape"
        );
    }
}

/// The builder emits the envelope Claude Code actually sends.
///
/// The scan above only proves the payload came from one place; it cannot say
/// that place is right. This pins the four fields a real `PreToolUse` carries
/// beyond `tool_name` and `tool_input`, so a builder that quietly loses one
/// fails here by name rather than by turning the whole suite back into a test
/// of `detect_protocol`'s fallback branch.
#[test]
fn the_builder_sends_a_real_pre_tool_use_envelope() {
    let cwd = Path::new("/tmp/dcg-payload-shape");
    let built = payload::pre_tool_use(cwd, "git reset --hard");

    assert_eq!(
        built["hook_event_name"], "PreToolUse",
        "hook_event_name is the field that wins detect_protocol for Claude; \
         without it session_id/transcript_path/cwd send dcg down the Gemini branch"
    );
    assert_eq!(built["cwd"], cwd.to_string_lossy().as_ref());
    assert!(
        built["session_id"].as_str().is_some_and(|s| !s.is_empty()),
        "a real PreToolUse carries a session id"
    );
    assert!(
        built["transcript_path"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "a real PreToolUse carries a transcript path"
    );
    assert_eq!(built["tool_name"], "Bash");
    assert_eq!(built["tool_input"]["command"], "git reset --hard");
}
