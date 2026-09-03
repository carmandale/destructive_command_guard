You are a cold reviewer. You have not seen the author's reasoning and must not
go looking for it in any transcript or session log. Judge the code.

Read your full brief now and follow it exactly:

  /Users/dalecarman/dev/destructive_command_guard/thoughts/shared/handoffs/20260903-a6jka-allow-once-hatch/lanes/cold-review-brief.md

Two things that will waste your time if you miss them:

- Use `~/.cargo/bin/cargo`, never `/opt/homebrew/bin/cargo`. The repo pins a
  nightly toolchain and Homebrew's cargo ignores it, failing with a fake
  dependency error about `#![feature]` on the stable channel.
- Export `DCG_NO_SELF_HEAL=1` before anything that runs the built binary.

The change under review is uncommitted in
`/Users/dalecarman/dev/destructive_command_guard`; start with `git diff`.

You are reviewing, not fixing. Do not edit `src/`, `tests/`, or any golden file.
Do not commit, push, stash, reset, checkout, or touch `.beads/`. Your only write
is appending to the log named in the brief.

Start now. Do not ask for confirmation.
