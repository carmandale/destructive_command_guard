# Cold review: dcg allow-once / allowlist override changes

You are reviewing a change in `/Users/dalecarman/dev/destructive_command_guard`
(Rust). You have not seen the author's reasoning and you should not go looking
for it in any transcript. Judge the code.

**Use `~/.cargo/bin/cargo`, never `/opt/homebrew/bin/cargo`** — the repo pins a
nightly toolchain in `rust-toolchain.toml` and the Homebrew cargo ignores it and
fails with a fake dependency error (`#![feature] may not be used on the stable
release channel`).

Export `DCG_NO_SELF_HEAL=1` for anything that runs the built binary.

## What the change claims to do

Three tests were failing on `main` before this change. They are named in
`tests/KNOWN_RED.tsv`:

- `tests/allowlist_command_tests.rs` `test_exact_command_allowlist_works`
- `tests/cli_e2e.rs` `hook_mode_tests::hook_mode_allow_once_allows_pack_denied_command`
- `tests/cli_e2e.rs` `hook_mode_tests::hook_mode_allow_once_can_override_config_block_with_force_flag`

The change also edits the text of every denial dcg emits.

## Read the diff

```bash
cd /Users/dalecarman/dev/destructive_command_guard
git diff
git status --short
```

Nothing is committed yet. `git stash` is NOT available to you here — do not run
it, and do not revert, reset, or checkout anything. If you want to see
pre-change behaviour, use `git show HEAD:<path>` into a scratch file under
`/tmp`, or build a probe that does not mutate the working tree.

## Your job

Answer these, each with evidence you produced yourself:

1. **Is the diagnosis right?** For each of the three tests, is the cause the
   diff fixes actually the cause of that test's failure? Prove it — a mutant, a
   probe, `git stash`-free A/B, whatever you can run. A fix that makes a test
   pass for a different reason than it failed is a finding.

2. **Do the new tests actually guard?** For each test added in this diff, break
   the thing it names and check *that test* goes red with a message that points
   at the right place. Beware: `set -e`-style aborts and neighbouring failures
   can make a test look like it fired when it never ran. Grep for the test's own
   name in the output.

3. **Is the denial-text change safe?** `format_denial_message` now puts an
   `allow-once` code into `permissionDecisionReason`. dcg is a security guard.
   Consider whether this makes it easier for an agent to talk itself past a
   *true* positive, whether the code can be forged or replayed, whether anything
   else parses this string, and whether the golden-file masking that was added
   alongside it hides a regression it should catch.

4. **Is any of it over-built or in the wrong place?** Specifically:
   `crate::config::user_config_dir` was extracted and three call sites moved onto
   it — is that the right seam, does it change behaviour for anyone, and did it
   miss a call site? Ask of each part: if it did not exist, what would break?

5. **What did the author miss?** Look for adjacent instances of the same bug
   class that the diff did not fix, and for anything the diff breaks that no
   test covers.

## Verify green yourself

```bash
cd /Users/dalecarman/dev/destructive_command_guard
DCG_NO_SELF_HEAL=1 ~/.cargo/bin/cargo test --release --no-fail-fast 2>&1 | tail -40
bash scripts/check_known_red.sh   # if it exists; read it first
```

`tests/KNOWN_RED.tsv` is a ledger of tests that are *expected* to fail. A listed
test that now passes makes that file wrong — say so if you find it.

## Where to write

Append everything — commands, raw output, findings — to exactly this file:

`/Users/dalecarman/dev/destructive_command_guard/thoughts/shared/handoffs/20260903-a6jka-allow-once-hatch/lanes/cold-review.md`

Append only. Do not create other files outside `/tmp`. Do not edit `src/`,
`tests/`, or any golden file — you are reviewing, not fixing. Do not commit, do
not push, do not touch `.beads/`.

End your log with a section `## VERDICT` containing one of `APPROVE`,
`APPROVE WITH FINDINGS`, or `REJECT`, then a numbered list of findings, each
marked `BLOCKING` or `NON-BLOCKING`, each with the evidence line that supports
it. A finding with no evidence you produced is not a finding — say "unverified
suspicion" and mark it as such.

Being unable to reproduce something is a result. Write it down rather than
softening it.
