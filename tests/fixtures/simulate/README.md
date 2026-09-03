# `dcg simulate` log fixtures

Input for `dcg simulate --file`, which reads a log of past tool calls. It is a
different reader from hook mode: `src/simulate.rs` has its own line parser that
looks up `tool_name` and `tool_input.command` in a `serde_json::Value` and never
touches `session_id`, `transcript_path`, `cwd` or `hook_event_name`. The shape
`{"tool_name": ..., "tool_input": {...}}` is the one that module's own docs
define, so these fixtures are deliberately not `PreToolUse` envelopes.

They live in files rather than inline in `tests/cli_e2e.rs` so that the hook-mode
payload guard (`tests/payload_shape.rs`) can scan that harness without an
exemption that would also cover its six real hook-mode call sites.

- `hook_json.jsonl` — three well-formed lines, one of them a non-Bash tool the
  simulator must ignore.
- `mixed_with_malformed.log` — a raw shell line, a hook line whose `tool_input`
  carries no `command`, and another raw line. Drives both the `--strict` failure
  and the non-strict `malformed_count`.
