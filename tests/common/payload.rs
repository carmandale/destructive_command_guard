//! One place that builds the JSON a hook-mode dcg invocation reads on stdin.
//!
//! Why this exists, measured rather than imagined (2026-09-02, `.agent-config-d5c7l`):
//! dcg answered Claude Code in Gemini's protocol. The verdict was correct and
//! unreadable, which on the wire is an allow. The whole suite stayed green
//! through it, and an 18,723-row replay reported "identical", because every
//! hook-mode harness sent `{"tool_name": "Bash", "tool_input": {...}}` and
//! nothing else. That payload reaches `ClaudeCompatible` by falling off the end
//! of `detect_protocol` — the final `else` — not by the `hook_event_name ==
//! "PreToolUse"` branch a real invocation takes. So the suite exercised a branch
//! no agent ever reaches and left the one every agent reaches untested.
//!
//! A real Claude Code `PreToolUse` payload carries four more fields:
//! `session_id`, `transcript_path`, `cwd` and `hook_event_name`. The first
//! three are what `detect_protocol` reads as "Gemini context"; the fourth is
//! what saves it. Send all four or the test is measuring a shape that only
//! exists in the test.
//!
//! Of those, only `hook_event_name` changes a verdict path today — dcg reads
//! `session_id`, `transcript_path` and `cwd` in `detect_protocol` and nowhere
//! else (they do not reach git detection, path anchoring or the allowlist), and
//! nothing opens the transcript. They are here because a real hook sends them
//! and because their presence is precisely what made the Gemini branch win.
//!
//! Get the payload from here, or the guard test in `tests/payload_shape.rs`
//! fails.

#![allow(dead_code)]

use std::path::Path;

/// A stand-in for the UUID Claude Code mints per session.
///
/// Fixed, so two runs of the same test send the same bytes. dcg only tests
/// this field for presence.
const SESSION_ID: &str = "9a02fa0e-5133-42b7-8f0e-1d2c3b4a5e6f";

/// The stdin payload a real `PreToolUse` hook sends for a Bash command.
///
/// `cwd` is the directory the agent is running in, which for a test is the
/// sandbox root — `spawn::Sandbox::root()`, the same directory `spawn::dcg_in`
/// gives the child as its working directory.
///
/// Returns a `Value`, not a `String`, on purpose: most callers hand it to
/// `serde_json::to_writer`, and a `String` there serialises to a quoted JSON
/// scalar that dcg reads as malformed — a silent green. Callers that need the
/// bytes say `.to_string()`, and forgetting that is a type error rather than a
/// passing test.
pub fn pre_tool_use(cwd: &Path, command: &str) -> serde_json::Value {
    pre_tool_use_for_tool(cwd, "Bash", serde_json::json!({ "command": command }))
}

/// The same envelope around a `tool_input` the caller chooses.
///
/// For the harnesses that assert dcg skips a non-Bash tool, or that a `Bash`
/// call with no `command` is handled rather than crashed. The envelope is
/// identical; only the payload dcg is meant to ignore differs.
pub fn pre_tool_use_for_tool(
    cwd: &Path,
    tool_name: &str,
    tool_input: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "session_id": SESSION_ID,
        "transcript_path": cwd.join("transcript.jsonl").to_string_lossy(),
        "cwd": cwd.to_string_lossy(),
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    })
}
