# Coordinator log — .agent-config-a6jka

Session `fda3b398-0c97-4b03-b9b6-cc6b7c15fa01`, pane `w5:pD8`, account `george`.
Repo under change: `/Users/dalecarman/dev/destructive_command_guard` (branch `main`).
Bead tracker: `~/.agent-config` (`.agent-config-a6jka`, and its sibling `.agent-config-0kt9v`).

## Goal

`dcg allow-once` is the documented escape hatch for a false positive
(AGENTS.md §8). Three tests said the hatch and the user allowlist do not work.
Name the mechanism behind each, fix it at the cause or split it out with its
own cause, and prove end to end that `dcg allow-once` actually opens the hatch
against a real deny.

## Sibling check before claiming

`.agent-config-a6jka` was already assigned to session
`51be4fb6-4eaa-4b63-9220-937320ba70a7` in pane `w5:pDG`. That pane reads as an
empty prompt and no transcript for that session exists under any account
profile, so the payload never armed — the bead's own third comment predicted
exactly this. Reassigned to this session rather than working alongside it.

## Reproduction (before any edit)

`~/.cargo/bin/cargo`, not `/opt/homebrew/bin/cargo`: the repo pins nightly in
`rust-toolchain.toml`, and the Homebrew cargo ignores the pin and fails with
`#![feature] may not be used on the stable release channel`, which reads as a
dependency problem and is not one.

All three REPRODUCED at `18b722d`:

```
tests/cli_e2e.rs        117 passed; 2 failed
  hook_mode_tests::hook_mode_allow_once_allows_pack_denied_command
  hook_mode_tests::hook_mode_allow_once_can_override_config_block_with_force_flag
tests/allowlist_command_tests.rs    0 passed; 1 failed
  test_exact_command_allowlist_works
```

## The bead's hypothesis is REFUTED

The bead proposed one shared cause: "hook mode does not consult the sandbox's
config dir / env-named override path", flagged as hypothesis, not established.
Both halves are wrong, and the three tests have two different causes.

### Probe 1 — hook mode DOES consult `DCG_ALLOW_ONCE_PATH`

`a6jka-scope-probe.py` (this directory). One command, one env, one directory; only the
spelling of `scope_path` in the written entry varies.

```
no entry at all (control)                      DENY
scope cwd,  scope_path = tempdir as given      DENY
scope cwd,  scope_path = os.path.realpath      ALLOW
scope project, scope_path = "/"                ALLOW
```

The env-named path is read and honoured. What fails is the scope comparison.

**Cause A — `AllowOnceEntry::matches_scope` compares path strings, not
directories.** `std::env::current_dir` is `getcwd(3)`, which has already
resolved every symlink; a stored `scope_path` carries whatever spelling its
writer used. On macOS every `TMPDIR` path is such a pair
(`/var/folders/..` vs `/private/var/folders/..`), so the two tests write an
entry naming the very directory the hook then runs in, and the string
comparison refuses it — silently, with no log line.

Stated with its limit: **every production writer goes through `getcwd()` on
both sides**, so the two spellings agree in real use and the hatch does work
today. That is why this red survived. It is still a correctness bug —
`scope_path` is a `pub` field with a `pub` constructor, the store is an
env-overridable documented file, and the failure mode is total silence — and
the repo had already decided this question elsewhere:
`allowlist::resolve_path_for_matching` canonicalizes before comparing.

### Probe 2 — the allowlist failure is not about hook mode at all

`allowlist.rs::load_default_allowlists` resolved the User layer from
`dirs::home_dir()` with a `dirs::config_dir()` fallback. It is the only
config-dir resolver in the crate that never consults `XDG_CONFIG_HOME`.
`config.rs::load_user_config_layer`, `cli.rs::config_dir`, `cli.rs::config_path`
and `pending_exceptions.rs::config_dir_override` all do.

**Cause B — the writer and the reader of the user allowlist disagreed.**
`dcg allowlist add --user` writes through `cli.rs::config_dir()`, which honours
`XDG_CONFIG_HOME`; `load_default_allowlists` read from `~/.config/dcg/` and
ignored it. With `XDG_CONFIG_HOME` set, an entry a user just added is written to
one file and read from another, and never takes effect. A third spelling,
`dirs::config_dir()` alone, sat at `cli.rs:11339` in the suggest-undo path.
This one is a live production defect, not a test artifact.

Cause B belongs to `.agent-config-0kt9v`, which already exists as its own bead
and already carries that test. Fixed here because it is three lines and the same
"the documented escape hatch does not open" story; recorded on both beads.

### Finding 3 — found while verifying, and the one that actually bites

`a6jka-hatch-e2e.py` (this directory) runs the real consumer flow: hook denies →
`dcg allow-once <code> --yes` → hook re-runs. Before the change:

```
STEP 1 hook denies            allowOnceCode: '35836'   (sibling JSON field)
       reason text mentions an allow-once code : False
STEP 2 dcg allow-once 35836 --yes    exit=0
STEP 3 hook re-runs                  ALLOW
HATCH OPENS: yes    CODE REACHES THE AGENT: no
```

**Cause C — the code never reaches the caller who needs it.**
`format_denial_message` builds `permissionDecisionReason`, which is the whole of
what Claude Code shows its agent: sibling JSON fields are not rendered and
PreToolUse stderr is not surfaced. The code lived in `allowOnceCode`, in
`remediation.allowOnceCommand`, and in the stderr box — every surface except
that one. The text ended by pointing the agent *away* from the hatch ("ask the
user … and have them run the command manually").

Measured in this session, unprompted: a `python3 -c` heredoc containing
`os.rmdir(d)` was denied by the installed binary, and the deny this session
could read carried no code. That is the bead's "live data point", reproduced
first-hand.

This is a delivery bug, not a posture change: `output::denial` already prints
`To allow once: dcg allow-once {code}`, and `remediation.allowOnceCommand`
already ships the runnable command. The product had decided to offer the hatch;
one channel did not deliver it.

## Changes

| File | Change |
|---|---|
| `src/pending_exceptions.rs` | `matches_scope` canonicalizes both sides via new `canonical_or_self`; falls back to the raw path, so the fallback arm is byte-identical to the old behaviour. Three unit tests. |
| `src/config.rs` | New `user_config_dir()` — one spelling of the user-config-dir policy. |
| `src/cli.rs` | `config_dir()` delegates to it; the fifth resolver at the suggest-undo site routed onto it too. |
| `src/allowlist.rs` | User allowlist layer reads through the same resolver the writer uses. |
| `src/hook.rs` | `format_denial_message` takes the allow-once code and names the hatch, keeping the manual-permission line last. Two unit tests. |
| `tests/cli_e2e.rs` | `hook_mode_denial_reason_quotes_the_minted_allow_once_code` — asserts the reason quotes *the code that was minted*, so it cannot pass on a stale or hard-coded code. |
| `tests/golden_json_tests.rs` | Masks the code inside the reason, as it already did for `remediation`. |
| `tests/golden/hook/*.json` | One line each. |

Goldens were patched in place (`a6jka-patch-goldens.py`, asserting
exactly one substitution per file) rather than regenerated: `UPDATE_GOLDEN=1`
also rewrites every key into a different order, which buried a one-line change
in a 16-line diff. Only the reason string differs.

## Proof

- The three originally-red tests: green. `cli_e2e` 119 passed / 0 failed
  (was 117/2); `allowlist_command_tests` 1 passed / 0 failed (was 0/1).
- End to end after the change: `HATCH OPENS: yes`, `CODE REACHES THE AGENT: yes`.
- The new `matches_scope` tests build their own symlink rather than leaning on
  `TMPDIR`, because on Linux no temp path is a symlink pair and a
  platform-dependent guard would pass there with the bug still present.
- Full `cargo test --release --no-fail-fast`: see below.

## Lane declaration

- **Lane** `cold-review-a6jka` — runtime Claude Code via `herdr` pane `w25:p1`,
  session `ce4ea56c-0bd3-4641-a445-204520085c53`, account `george`, model
  `claude-opus-5[1m]`. Launched with
  `node ~/dev/agent-observer/coordinator-start.mjs launch`.
- **Purpose**: one cold independent review of the uncommitted diff, blind to the
  coordinator's reasoning.
- **Visibility**: user-visible pane.
- **Grant**: a full Claude session — it holds writers (`Bash`, `Write`, `Edit`).
  Write-holding lane, so its write is verified by reading its log file, not by
  its report. Prompt-level ban on editing `src/`, `tests/`, goldens, `.beads/`,
  and on commit/push/stash/reset/checkout; a prompt-level ban is not a grant, so
  the coordinator diffs the tree against the pre-launch state before landing.
- **Log**: `lanes/cold-review.md` (this directory). Brief: `lanes/cold-review-brief.md`.
- **Stop condition**: a `## VERDICT` section in that log.
- **Arming**: `coordinator-start.mjs` reported UNCONFIRMED — "not started after
  Enter (status=idle, watched 45s)", no transcript. Read the pane instead of
  relaunching: live, ready, empty prompt. Re-sent via `herdr agent prompt`.
  Same failure the bead recorded for the pane that held this bead before.

Observe: cold-review.md parent-harvest

## Dispositions

Cold-review lane `cold-review-a6jka`, log `lanes/cold-review.md`, verdict
**APPROVE WITH FINDINGS** pinned to its state S6. Every finding below is bound
to that log's own evidence, and the raw log is committed unedited.

| # | finding | disposition |
|---|---|---|
| 1 | golden mask not idempotent — three deny goldens red | **Applied.** Fixed mid-review, `strip_prefix(MASK)`, pinned by `masking_an_allow_once_code_is_idempotent`. |
| 2 | `KNOWN_RED.tsv` still listed the three fixed tests | **Applied.** Three rows removed; `check_known_red.sh` now exits 0. |
| 3 | allowlist reads narrowed — an allowlist in an older location silently orphaned | **Applied, and my prior reasoning was wrong.** See below. |
| 4 | `matches_scope` doc claimed an unreproduced production symptom | **Applied.** Comment rewritten to what the evidence supports; canonicalisation made all-or-nothing, which also closes the Windows `\\?\` narrowing. |
| 5 | `test_matches_scope_falls_back_when_the_path_is_gone` was vacuous | **Applied.** Negative half and Project arm added; re-ran the lane's own M6 mutant and the named test now reddens. |
| 6 | empty allow-once code indistinguishable from a real one | **Applied.** `filter(|c| !c.is_empty())`, a non-empty precondition in the e2e test, and a unit test. |
| 7 | hatch line advertised on config-block denials it cannot open | **Applied.** `allow_once_suffices`; mutant-verified. |
| 8 | `--force --yes` skips the FORCE prompt | **Deferred with cause** → `.agent-config-eth3v`. Pre-existing; this change no longer feeds that chain from the reason text. Posture call, not a bug fix. |
| 9 | six other hand-rolled user-config-dir spellings; `config_dir_override` skips tilde expansion | **Deferred with cause** → `.agent-config-piua5`. Pre-existing; the tilde half is a real bug (a directory literally named `~`). |
| 10 | `Config::user_config_path` is a line-for-line duplicate | **Applied.** Routed through `user_config_dir`. |
| 11 | `ConfigOverride` spelled two ways, nothing couples them | **Applied.** `tests/regression_config_override_spelling.rs`, mutant-verified. |
| 12 | `AGENTS.md` and `hook-output.json` examples stale | **Already applied when raised.** Both were updated at S5; the finding was measured against an earlier state. |
| 13 | "Same wording as `output::denial`" was false | **Applied.** The comment now states the difference and why. |
| 14 | one new `cargo fmt` violation | **Applied.** Back to the pre-existing 26, file-for-file identical. |

### Finding 3 is the one where I was wrong, not just imprecise

I had already spotted that the first allowlist fix drops the undocumented
platform-native fallback, and I argued in this log that restoring it would
"reintroduce the writer/reader divergence" the change exists to remove. That
reasoning was wrong, and the lane's counter is the correct one:
`Config::load_user_config_layer` has always solved the same problem by falling
through all three candidates while the writer picks one of them. Because the
writer's choice is always a member of the reader's list, the two ends cannot
diverge — and no file already on disk is orphaned. That is exactly why
`config.toml` never had `.agent-config-0kt9v`'s bug.

So I had reasoned myself into a silent data-loss path and then written three
paragraphs justifying it. The fail-closed direction and the documentation
argument were both true and neither made it right. `config::user_config_file`
now reads through every candidate; `test_user_allowlist_in_an_older_location_is_still_read`
pins it, and `test_xdg_allowlist_outranks_the_older_location` pins that falling
through did not turn into "first file found wins".

### On the lane's closing caveat

It is fair. The tree moved six times during the review, three without notice,
and at 05:13 it did not compile — a transient state between adding a twelfth
parameter and updating its wrapper, which `cargo build` caught immediately
after. The approval covers S6. Everything changed after S6 (findings 3, 5, 10,
11) I mutant-checked myself, each read by the named test's own line.

## A defect I shipped into my own change, and how it was caught

The first `mask_allow_once_code_in_text` masked unconditionally. Both sides of
the golden comparison go through it — the actual output carrying a fresh code,
and the golden file on disk already carrying `<DYNAMIC>` — so the golden became
`dcg allow-once <DYNAMIC><DYNAMIC>` and all three deny goldens failed against
output that was correct.

How it got in: after hand-patching the goldens I read the diffstat, saw one line
per file, wrote "One line per file" and moved on. I had verified the *shape of
the diff* and called it verification of *behaviour*. The golden suite had last
run under `UPDATE_GOLDEN=1`, which cannot fail.

Caught by the first full `cargo test --release --no-fail-fast`:

```
golden_hook_deny_filesystem        FAILED
golden_hook_deny_git_force_push    FAILED
golden_hook_deny_git_reset_hard    FAILED
```

Fixed by making the masker idempotent, and pinned by
`masking_an_allow_once_code_is_idempotent`, which asserts masking twice equals
masking once — the property the first version violated. The cold-review lane was
told its target had moved rather than being left to review a stale tree.

## The allowlist fix's read side — a wrong turn, corrected

**SUPERSEDED. The position argued in this section is the one the cold review
overturned; see Dispositions, finding 3. It is kept, not rewritten, because the
reasoning that led me here is the point.**

The first fix made the User-layer resolution `user_config_dir()/allowlist.toml`
with no second candidate, where it had been `~/.config/dcg/allowlist.toml` *if
that file exists*, else `dirs::config_dir()/dcg/allowlist.toml`. I noticed that
drops a real file for a user whose allowlist lives only at the macOS
platform-native path, and I argued it was the right trade:

1. **It is what the docs already promise.** `README.md:2083`,
   `docs/configuration.md:117` and `docs/custom-packs.md:310` all name
   `~/.config/dcg/allowlist.toml` as the User layer. No document mentions the
   platform-native path; that fallback was undocumented behaviour.
2. **The writer never used it either.** `dcg allowlist add --user` goes through
   `config_dir()`, which already preferred `~/.config/dcg` whenever that
   directory existed — and it exists for anyone who has a `config.toml`.
3. **The failure direction is fail-closed.** Losing an allowlist entry makes dcg
   deny more, not less, which for a guard is the safe direction.

All three statements are true. None of them made the change right, and the third
carried a bad inference: that restoring a fallback would "put the reader back on
a path the writer never writes". It would not. The writer picks one directory
from a fixed list; a reader that tries the whole list in the same order always
finds the writer's choice, so the two ends cannot drift — and nothing already on
disk is orphaned. `Config::load_user_config_layer` had been doing exactly that
for `config.toml` all along, which is why `config.toml` never had this bug. The
precedent was in the same file and I did not read it as one.

What the argument above was really defending was silent data loss, dressed as
documentation fidelity. The corrected shape is `config::user_config_file`.

Measured on this machine at the time: no `allowlist.toml` at either location, so
nothing here changed for this host either way.
`~/Library/Application Support/dcg/` holds only a `pending_exceptions.jsonl`
last written 25 Jul.

