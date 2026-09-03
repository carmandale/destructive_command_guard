# Cold review — dcg allow-once / allowlist override changes

Reviewer: cold lane, no access to the author's reasoning. Every claim below is
backed by a command run in this session and its raw output.

Toolchain: `~/.cargo/bin/cargo` (repo pins nightly), `DCG_NO_SELF_HEAL=1` on
everything that runs the built binary. Host: darwin 27.0.0, arm64.

**Mid-review note.** The working tree moved once while I was reviewing. The
author changed `tests/golden_json_tests.rs::mask_allow_once_code_in_text` to be
idempotent, and added `masking_an_allow_once_code_is_idempotent`. I had already
found and reproduced the defect that change fixes (§B1 below); I have kept the
finding, re-read the new code, and re-run the goldens against it. The finding is
marked **fixed mid-review**. Nothing else in the tree moved — verified with
`git status --short` and `git diff` at both points.

---

## 0. Method: how "before" was obtained without touching the tree

`git stash` is unavailable and the tree must not be mutated, so I built a
pre-change binary from `HEAD` in a scratch copy:

```
rsync -a --exclude 'target/' --exclude '.worktrees/' --exclude '.git/' \
      --exclude 'thoughts/' --exclude '.beads/' --exclude '.agent-state/' \
      ./ /tmp/coldrev/pre/
for f in <the 10 modified paths>; do git show "HEAD:$f" > "/tmp/coldrev/pre/$f"; done
cd /tmp/coldrev/pre && DCG_NO_SELF_HEAL=1 ~/.cargo/bin/cargo build --release --bin dcg
```

Instrument label check — I did not assume which binary was which, I measured it:

```
$ for b in ./target/release/dcg /tmp/coldrev/pre/target/release/dcg; do
    printf '%s: ' "$b"
    strings -a "$b" | grep -q "If this is a false positive: dcg allow-once" \
      && echo "HAS new hatch string" || echo "no hatch string"
  done
./target/release/dcg: HAS new hatch string          <- POST
/tmp/coldrev/pre/target/release/dcg: no hatch string <- PRE
```

Copies kept as `/tmp/coldrev/dcg-pre` and `/tmp/coldrev/dcg-post`.

---

## A. Is the diagnosis right?

### A1. `test_exact_command_allowlist_works` — diagnosis CORRECT, and the
### underlying bug is real in production, not just in the harness

The test writes its allowlist to `$XDG_CONFIG_HOME/dcg/allowlist.toml`
(`tests/common/spawn.rs::Sandbox::dcg_config_dir`). I replicated the harness
against both binaries (`/tmp/coldrev/probe_allowlist.sh`):

```
PRE : DENIED (non-empty stdout) -> test_exact_command_allowlist_works FAILS
POST: ALLOWED (empty stdout)    -> test_exact_command_allowlist_works PASSES
```

Then I mapped *which* candidate locations each binary actually reads, one file
at a time (`/tmp/coldrev/probe_allowlist_where.sh`). "READ" == the command was
allowed, i.e. that file was consulted:

```
--- PRE (HEAD) ---
PRE   $XDG_CONFIG_HOME/dcg      (XDG set)     -> NOT read (denied)
PRE   $HOME/.config/dcg         (XDG set)     -> READ (allowed)
PRE   $HOME/Library/App Support/dcg (XDG set) -> READ (allowed)
PRE   $HOME/.config/dcg         (XDG unset)   -> READ (allowed)
PRE   $HOME/Library/App Support/dcg (XDG unset) -> READ (allowed)
--- POST (working tree) ---
POST  $XDG_CONFIG_HOME/dcg      (XDG set)     -> READ (allowed)
POST  $HOME/.config/dcg         (XDG set)     -> NOT read (denied)
POST  $HOME/Library/App Support/dcg (XDG set) -> NOT read (denied)
POST  $HOME/.config/dcg         (XDG unset)   -> READ (allowed)
POST  $HOME/Library/App Support/dcg (XDG unset) -> READ (allowed)
```

And the write side, with `XDG_CONFIG_HOME` set
(`/tmp/coldrev/probe_write_side.sh`, `dcg allowlist add core.git:reset-hard
--reason probe --user`):

```
PRE  wrote: <sandbox>/xdg/dcg/allowlist.toml
POST wrote: <sandbox>/xdg/dcg/allowlist.toml
```

So on `HEAD`, `dcg allowlist add --user` wrote to `$XDG_CONFIG_HOME/dcg/` and
`load_default_allowlists` never looked there. That is exactly the split the
diff's comment in `src/config.rs` claims, and it is a **real user-facing bug**,
not a test artefact: any user with `XDG_CONFIG_HOME` exported got a silently
inert `--user` allowlist entry. Diagnosis confirmed.

### A2 / A3. The two `hook_mode_allow_once_*` tests — diagnosis CORRECT

`/tmp/coldrev/probe_allow_once.sh` builds the same hand-written
`allow_once.jsonl` the harness builds, and varies exactly one thing: whether
`scope_path` carries the `/var/folders/...` spelling `TempDir` hands out or the
`/private/var/folders/...` spelling `getcwd(3)` returns.

```
===== test 2 shape: allow-once vs pack deny =====
PRE   scope=asgiven   force=false cfgblock=no  -> DENY  (git reset --hard destroys uncommitted changes...)
POST  scope=asgiven   force=false cfgblock=no  -> ALLOW (empty stdout)
PRE   scope=canonical force=false cfgblock=no  -> ALLOW (empty stdout)
===== test 3 shape: force flag vs config block =====
PRE   scope=asgiven   force=true  cfgblock=yes -> DENY  (explicit config block)
POST  scope=asgiven   force=true  cfgblock=yes -> ALLOW (empty stdout)
PRE   scope=canonical force=true  cfgblock=yes -> ALLOW (empty stdout)
===== control: no-force vs config block (must DENY on both) =====
PRE   scope=canonical force=false cfgblock=yes -> DENY  (explicit config block)
POST  scope=asgiven   force=false cfgblock=yes -> DENY  (explicit config block)
```

The spelling is the only variable, and it flips the verdict on PRE. The
diagnosis is right, and the control shows the fix does **not** widen the
config-block override: without `force_allow_config` the config block still wins
on the post binary.

### A4. But the *production* claim attached to that fix is not supported

`src/pending_exceptions.rs` documents `canonical_or_self` as a correctness fix
whose consequence is "the escape hatch of AGENTS.md §8 not opening". I tried to
reproduce that end to end, using only paths dcg itself writes — no hand-built
JSONL — inside a directory reached through a symlink
(`/tmp/coldrev/probe_end_to_end.sh`):

```
--- PRE ---
PRE   1) first hook run -> DENY, code=87902
PRE   2) dcg allow-once 87902 --yes -> exit 0
        |   CWD: /private/var/folders/.../e2eP02HWV/real
        |   Scope: Project (/private/var/folders/.../e2eP02HWV/real)
PRE   3) second hook run -> ALLOW (hatch OPENED)
        stored scope_path: allow_once.jsonl -> /private/var/folders/.../e2eP02HWV/real
        symlink spelling : /var/folders/.../e2eP02HWV/link
        canonical        : /private/var/folders/.../e2eP02HWV/real
--- POST ---
POST  3) second hook run -> ALLOW (hatch OPENED)
```

**The hatch already opened on the pre-change binary.** dcg writes `scope_path`
from `std::env::current_dir()` (`src/main.rs:450/494/512` →
`record_block(.., working_dir, ..)` → `handle_allow_once_command`
`src/cli.rs:9934,9957-9968`), and `current_dir` is `getcwd(3)`, which is already
symlink-resolved. Both sides of the comparison were therefore already canonical
for every entry dcg itself creates.

I could not construct a production path that produces a non-canonical
`scope_path`. The only writer of a mismatched spelling I found is the test
harness's own `write_allow_once_entry` (`tests/cli_e2e.rs:1484-1516`), which
passes `temp.path()` straight in.

This does not make the change wrong — comparing filesystem paths by canonical
form is the right call, it is what `allowlist::resolve_path_for_matching`
already does, and it defends the store against entries written by anything other
than the current code path. But the doc comment states a production consequence
that I could not reproduce and that the code as written appears to preclude.
See finding 4.

---

## C. Is the denial-text change safe?

### C1. Nothing parses the string structurally

I checked every consumer in the repo:

```
$ grep -rn "permissionDecisionReason\|permission_decision_reason" tests/ scripts/ docs/ src/ | grep -v '^tests/golden/'
```

`tests/agent_hook_output.rs:239`, `tests/test_explanations.rs:283`,
`tests/e2e/run_agent_e2e.sh:412`, `tests/e2e/framework.rs:104`,
`scripts/e2e_test.sh:346` and the seven `cli_e2e.rs` sites all do presence,
length, or `contains(..)` checks. `docs/json-schema/hook-output.json:24` types it
as a plain string with no pattern. Inserting a paragraph before the last one
breaks none of them, and the full suite agrees (§F).

### C2. The code is not, and never was, a secret — so "forgery" is the wrong axis

`compute_full_hash` (`src/pending_exceptions.rs:1366`) is SHA-256 over
`timestamp | cwd | command_raw`, HMAC only when `DCG_ALLOW_ONCE_SECRET` is set,
and `short_code_from_hash` (`:1410`) truncates to 5 decimal digits. The same
code is already published in `hookSpecificOutput.allowOnceCode` and
`remediation.allowOnceCommand` in the very same stdout object. Putting it in the
reason string reveals nothing that object did not already carry, and a forged
code fails because `lookup_by_code` (`:436`) matches against the pending store,
not against the code's arithmetic. Replay is bounded by the 24 h expiry and by
`--single-use`.

So the change does not weaken a cryptographic property. What it changes is the
**set of consumers that can see the code**: from "a consumer that reads the
sibling JSON fields or the stderr box" to "any consumer that reads only the
reason". That is the whole point of the change, and it is also the entire risk.

### C3. What a consumer that sees only the reason can now do, measured

`/tmp/coldrev/probe_selfclear2.sh` scrapes the code **out of the reason text
only** (`sed -n 's/.*dcg allow-once \([A-Za-z0-9]*\).*/\1/p'`), redeems it with
stdin at `/dev/null`, and re-runs the hook. Fresh sandbox per case:

```
pack-noyes     code=48175  redeem_rc=1   verdict_after=DENY
       | Proceed? [y/N]: Error: Aborted.
pack-yes       code=62193  redeem_rc=0   verdict_after=ALLOW (self-cleared)
cfg-yes        code=32771  redeem_rc=1   verdict_after=DENY
       | Error: This denial came from your config blocklist; re-run with --force to override.
cfg-force-yes  code=57855  redeem_rc=0   verdict_after=ALLOW (self-cleared)
       | ✓ Allow-once entry created
```

Three things follow.

1. Without `--yes` the prompt holds: a non-interactive caller gets `Aborted.`
   and the denial stands. That is a real brake and the change does not remove it.
2. With `--yes` a pack denial is cleared in one command, by the caller, for
   24 hours, for any command — not only a false positive. This is the intended
   design (AGENTS.md §8 tells agents to do exactly this), so it is a posture
   the project has already chosen; the diff completes it for the reason-only
   consumer.
3. **`--force --yes` clears a config-blocklist denial with no human anywhere.**
   `handle_allow_once_command` gates the `Type 'FORCE' to confirm override:`
   prompt behind `needs_prompt = !(cmd.yes || cmd.dry_run)` (`src/cli.rs:10014`),
   so `--yes` skips the FORCE confirmation entirely. `docs/allow-once-usage.md:121`
   says a standard allow-once "does **not** override explicit blocklist entries";
   the escalation to `--force` is one word away and now begins with a code the
   agent read in the denial itself.

### C4. The hatch line is advertised on denials it cannot open

The `cfg-yes` row above is the tell: a `ConfigOverride` denial still carries
`If this is a false positive: dcg allow-once 32771`, and running exactly that
command fails with `This denial came from your config blocklist; re-run with
--force to override.` The text hands the agent a command that errors and whose
error message names the escalation. `format_denial_message` has no way to know
the denial's source, because `output_denial_for_protocol` is not given it —
`info.source` is stringified into the *pending record* at `src/main.rs:731` but
never reaches the formatter.

### C5. The golden masking hides less than it looks like it hides

`mask_dynamic_fields` already blanked `allowOnceCode`, `allowOnceFullHash` and
`remediation.allowOnceCommand` before this diff, so the goldens never pinned a
code value. Masking the reason keeps the *shape* of the new line pinned — the
three golden files still assert the exact sentence, its position between
`Command:` and the manual-permission line, and the two blank lines around it —
and the value binding moved to
`hook_mode_denial_reason_quotes_the_minted_allow_once_code`. That is a
reasonable split and the comment in `golden_json_tests.rs` says so.

One hole, though: **the mask cannot tell a real code from an empty one.** With
an empty code the emitted text is `dcg allow-once \n\n`; `mask_allow_once_code_in_text`
finds the needle, sees `\n` as the first non-alphanumeric byte, consumes zero
characters and writes `dcg allow-once <DYNAMIC>` — byte-identical to a run with
a real code. And `reason.contains(&format!("dcg allow-once {code}"))` with
`code == ""` reduces to `reason.contains("dcg allow-once ")`, which is true.
Measured as mutant M7 in §B. `short_code_from_hash` always returns five digits
today, so this is not live; it is a vacuity in the two guards, not a bug in the
product.

---

## D. Is any of it over-built or in the wrong place?

### D1. `crate::config::user_config_dir` — right seam, real behaviour change,
### and six other spellings of the same policy left standing

The seam is right. `config.rs` already owns `resolve_config_path_value`,
`load_user_config_layer` and `Config::user_config_path`; `cli.rs` is 11k lines
and the wrong home for a policy `allowlist.rs` has to agree with. The extracted
body is logic-identical to the old `cli::config_dir`, so `cli` callers are
unaffected — I read both and they match arm for arm.

The **behaviour change is on the read side of the allowlist**, and it is real
(the §A1 table). With `XDG_CONFIG_HOME` set, `load_default_allowlists` used to
fall through to `~/.config/dcg/allowlist.toml` and then to the platform-native
path; it no longer does. A user on macOS who exports `XDG_CONFIG_HOME` to
anything other than `~/.config` and keeps an allowlist at
`~/Library/Application Support/dcg/allowlist.toml` silently loses every entry in
it. The failure is closed (more denials, not fewer), which is the right
direction for a guard, but it is silent, undocumented and untested — the exact
shape of the bug this diff exists to fix, pointing the other way.

`grep -rn "XDG_CONFIG_HOME" tests/` shows no test pins allowlist-layer
precedence at all, before or after.

**Missed call sites.** The comment says "One function is what keeps the two ends
together." For the allowlist it does — all four sites
(`allowlist.rs:994`, `cli.rs:9742`, `:9840`, `:11319`) now agree. Six other
resolutions of the same policy were left hand-rolled:

| site | what it resolves | differs from `user_config_dir` how |
|---|---|---|
| `config.rs:3180` `Config::user_config_path` | `config.toml` (write) | none — a line-for-line duplicate, 3000 lines below the new function |
| `config.rs:2553` `load_user_config_layer` | `config.toml` (read) | tries all three in order instead of picking one |
| `cli.rs:9337` `config_path` | `config.toml` (display) | tries all three in order |
| `pending_exceptions.rs:275` `PendingExceptionStore::default_path` | pending store | `config_dir_override` skips `resolve_config_path_value` |
| `pending_exceptions.rs:474` `AllowOnceStore::default_path` | allow-once store | same |
| `history/schema.rs:760` `HistoryDb::default_path` | history db | same |

The last three are not cosmetic. `config_dir_override` (`pending_exceptions.rs:63`)
is `PathBuf::from(value).join("dcg")` with no tilde expansion and no
relative-path resolution, so it disagrees with `user_config_dir` whenever
`XDG_CONFIG_HOME` is not a plain absolute path
(`/tmp/coldrev/probe_pending_path.sh`, post-change binary):

```
POST XDG_CONFIG_HOME='~/cfg'
        <sandbox>/home/cfg/dcg/allowlist.toml
        <sandbox>/work/~/cfg/dcg/pending_exceptions.jsonl
```

dcg creates a directory literally named `~` under the current working directory
for the allow-once store, while the allowlist goes to the expanded home. That is
the same class of defect as `.agent-config-0kt9v`, it lives in the file this
diff edits, and the diff did not touch it. (Not introduced here — `PRE` behaves
identically — so it is pre-existing debt this change walked past, not a
regression.)

### D2. `canonical_or_self` — defensible, but smaller alternatives existed and
### the comment claims more than it can show

If it did not exist, the two `hook_mode_allow_once_*` tests stay red and nothing
else changes — see §A4, where the hatch opened end to end on the pre-change
binary. The one-line alternative was to canonicalise in the harness's
`write_allow_once_entry`, which is where the non-canonical spelling is actually
manufactured. The author instead changed the product. I think that is the better
of the two — comparing filesystem paths by canonical form is correct, it mirrors
`allowlist::resolve_path_for_matching`, and it hardens the store against an
entry written by an older binary or by hand. But the doc comment's framing
("this is a correctness fix and not a convenience", "the escape hatch of
AGENTS.md §8 not opening") describes a production failure I could not reproduce
and that `std::env::current_dir()` appears to preclude.

The comment also makes an absolute claim I could not verify on every platform:

> "The fallback arm is therefore byte-identical to the old behaviour: this can
> only make more spellings of the same directory match, never fewer."

On Unix that holds, because `getcwd(3)` is already canonical so the cwd side of
the comparison is a no-op. On Windows — which `.github/workflows/dist.yml:51`
builds and ships — `Path::canonicalize` returns a `\\?\`-prefixed path while
`std::env::current_dir` does not, so a mixed outcome (one side resolves, the
other falls back) yields `\\?\C:\repo` vs `C:\repo` and stops matching where the
string comparison matched. I have no Windows host here, so this is an
**unverified suspicion**, flagged as such.

### D3. The hatch line itself

If it did not exist, an agent whose harness shows it only
`permissionDecisionReason` has no code to quote. I cannot verify Claude Code's
rendering from this repo — that is a claim about an external product. What I can
verify is the half that lives here: on the pre-change binary the reason string
contains no code at all (the `strings` check in §0 and the golden diff), and on
the post-change binary it does. I also hit a live dcg denial in this session
whose reason carried no code, which is consistent with the claim.

The line is three lines of code with two unit tests and one e2e test. Not
over-built.

### D4. The golden mask

Needed the moment the reason carries a per-run value. 20 lines and one unit
test. The first version of it shipped a defect (§B1); the current one is correct
and pinned.

---

## E. What did the author miss?

### E1. `tests/KNOWN_RED.tsv` was not updated — the repo's own gate fails

The three tests the change fixes are still listed as expected-red. The ledger's
own rule (`tests/KNOWN_RED.tsv` header, `scripts/check_known_red.sh:8`) is that
disagreement in *either* direction is an error.

Run against the full `--no-fail-fast` release suite from the pre-fix tree state:

```
$ bash scripts/check_known_red.sh /tmp/coldrev_suite_after.log
FAIL: failing tests that the ledger does not list — this is a regression:
  golden_hook_deny_filesystem
  golden_hook_deny_git_force_push
  golden_hook_deny_git_reset_hard
FAIL: tests/KNOWN_RED.tsv lists tests that now PASS — the ledger is lying about the repo:
  hook_mode_tests::hook_mode_allow_once_allows_pack_denied_command
  hook_mode_tests::hook_mode_allow_once_can_override_config_block_with_force_flag
  test_exact_command_allowlist_works
EXIT=1
```

The first block is finding 1 (fixed mid-review). The second block is still true
of the tree as it stands: three rows must come out and their beads
(`.agent-config-a6jka`, `.agent-config-0kt9v`) must close.

### E2. A test that passed for the wrong reason and now passes for the right one

`hook_mode_allow_once_does_not_override_config_block_without_force` was green on
`HEAD` — but the §A2 probe shows why: on the pre-change binary the allow-once
entry never matched scope at all, so the deny it asserts came from the entry
being invisible, not from the config block outranking it. Post-change the entry
matches and the config block wins on its merits. The test is now load-bearing
where it was previously vacuous. Nobody had to do anything about this — it is
worth recording because it means the *pre-change* green on that test was not
evidence of anything.

### E3. Documentation that now describes output dcg no longer produces

Two places carry a literal `permissionDecisionReason` example and neither was
updated:

- `AGENTS.md:370` — the "JSON Output Format (Denial)" block, which is the
  contract document for agent integrators.
- `docs/json-schema/hook-output.json:86` — the schema's `examples` entry.

Neither is asserted by a test, so nothing went red. `docs/allow-once-usage.md:24`
also documents a stderr line (`ALLOW-24H CODE: [12345] | run: dcg allow-once
12345`) that no longer matches `output::denial` — that drift predates this diff.

### E4. The comment in `hook.rs` claims wording parity that does not hold

> "Same wording as `output::denial`, so the two surfaces read alike."

`src/output/denial.rs:176` emits `To allow once: dcg allow-once {code}`. The new
line emits `If this is a false positive: dcg allow-once {code}`. The runnable
command is identical; the sentence introducing it is not.

### E5. One new rustfmt violation

CI runs `cargo fmt -- --check` (`.github/workflows/ci.yml:46`). Measured on both
trees:

```
PRE fmt diffs: 26
POST fmt diffs: 27
```

The new one is the line this diff added:

```
Diff in .../src/hook.rs:765:
-    let message = format_denial_message(command, reason, explanation, pack, pattern, allow_once_code);
+    let message =
+        format_denial_message(command, reason, explanation, pack, pattern, allow_once_code);
```

The gate is already red for 26 pre-existing reasons, so this does not newly break
CI — but it is a one-line fix in a file the change already touches.

### E6. Not checked

`cargo clippy --all-targets -- -D warnings` (`ci.yml:49`) — I did not run it.
Stated so it is not mistaken for a clean result.

---

## Tree-state timeline — what each result is pinned to

The working tree moved twice during this review. Every claim above and below is
pinned to one of these states; I recorded content hashes rather than trusting
"the diff I read earlier".

| state | when (local) | `src/hook.rs` md5 | `src/pending_exceptions.rs` md5 | `tests/golden_json_tests.rs` md5 |
|---|---|---|---|---|
| **S1** — what the brief pointed me at | up to ~05:03 | `e6ba4fe…` | `686e17f…` | (30-line hunk) |
| **S2** — after the announced mask fix | ~05:03–05:12 | `e6ba4fe…` | `686e17f…` | `5ae1d85…` (55-line hunk) |
| **S3** — a second, unannounced move | from ~05:12 | `e1258fd…` | `0b5f67f…` | `5ae1d85…` |

- §A, §C, §D, §E and the mutant work in §B are measured against **S1/S2**.
- **S3 does not compile.** Measured at 05:13:

  ```
  $ DCG_NO_SELF_HEAL=1 ~/.cargo/bin/cargo check --all-targets
  error[E0061]: this function takes 12 arguments but 11 arguments were supplied
  error: could not compile `destructive_command_guard` (lib) due to 1 previous error
  error: could not compile `destructive_command_guard` (lib test) due to 1 previous error
  ```

  `output_denial_for_protocol` gained a twelfth parameter (`allow_once_suffices:
  bool`) and its wrapper `output_denial` (`src/hook.rs:881`) was not updated. The
  full release suite I launched at 05:09 died on this and produced no
  `test result:` line at all, so `scripts/check_known_red.sh` on that log
  correctly refuses to report anything. This is plainly mid-edit rather than a
  finished state; §G records the re-verification I ran once it settled.

S3 changes two things I had already written up, in the direction of the findings:

- `matches_scope` now canonicalises **all-or-nothing** — if either side fails,
  both are compared as given — and the doc comment now says the production
  symptom was not reproduced. That answers §A4/§D2 and closes the Windows
  `\\?\` mixed-case suspicion I raised. Residual nit, production-unreachable: for
  `Project` scope the "never fewer" guarantee still has one hole in principle —
  `scope=/a/b`, `cwd=/a/b/link` where `link` points outside `/a/b` matches as
  strings and not after resolution — but `cwd` always arrives from `getcwd(3)`
  and is already resolved, so nothing in dcg can reach it.
- `format_denial_message` now treats an empty code as no code, and
  `output_denial_for_protocol` takes `allow_once_suffices` so the hatch line is
  suppressed for a config-blocklist denial. Those are §C5 and §C4.

---

## B. Do the new tests actually guard?

Method: the tree must not be edited, so mutants were applied to a scratch copy
of the tree (`/tmp/coldrev/pre`, synced byte-for-byte to state **S2** —
`diff -rq src tests` clean before each run) via exact-literal substitution
(`/tmp/coldrev/mutate.py`, which exits 3 unless the old literal occurs exactly
once). Dev profile, because `[profile.release]` sets `lto = true` +
`codegen-units = 1` and each relink cost minutes.

Baselines first — a mutant against a red baseline proves nothing:

```
--lib matches_scope            test result: ok. 3 passed
--lib format_denial_message    test result: ok. 3 passed
--test cli_e2e (4 selected)    test result: ok. 4 passed
--test golden_json_tests       test result: ok. 34 passed
```

Every run below is reported by the *named test's own line*, not by the binary's
exit status, so a compile abort or a neighbour's failure cannot be read as "the
test fired". The driver prints `!! NO 'test result:' LINE` if nothing ran; that
never triggered.

### B1. The golden mask — the defect I found, and the fix

At **S1** `mask_allow_once_code_in_text` masked unconditionally. Both sides of
the golden comparison run through it, and the golden on disk already carries
`<DYNAMIC>`, so the golden became `dcg allow-once <DYNAMIC><DYNAMIC>` while live
output became `dcg allow-once <DYNAMIC>`. I predicted this by transcribing the
function into Python, then confirmed it against the real suite:

```
$ sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' /tmp/coldrev_suite_after.log | sort -u
golden_hook_deny_filesystem
golden_hook_deny_git_force_push
golden_hook_deny_git_reset_hard
test_audit_backtracking_requirements                      <- known red (rzo28)
src/output/progress.rs - output::progress (line 27) - compile   <- known red (bbdqd)

  CHANGED: $.hookSpecificOutput.permissionDecisionReason
    expected: "... dcg allow-once <DYNAMIC><DYNAMIC>\n\n ..."
    actual:   "... dcg allow-once <DYNAMIC>\n\n ..."
```

Three new reds, none in the ledger — a straight regression, and one that
`UPDATE_GOLDEN=1` could not have converged because that path returns `Ok(())`
before comparing, so it would have written a file that fails on the next run.

**Fixed mid-review** (S2) by `strip_prefix(MASK)`. I re-read the new function and
checked it for the obvious holes — idempotent by construction, `rest` strictly
shrinks each iteration so it terminates, `find(char predicate)` and
`strip_prefix` both return char boundaries — then re-ran the goldens:

```
$ DCG_NO_SELF_HEAL=1 ~/.cargo/bin/cargo test --release --test golden_json_tests
test result: ok. 34 passed; 0 failed
```

And the new guard is load-bearing. Mutant **M8** removes the `strip_prefix`
branch, i.e. restores the S1 version:

```
[M8] test masking_an_allow_once_code_is_idempotent ... FAILED
[M8] test golden_hook_deny_filesystem ... FAILED
[M8] test golden_hook_deny_git_force_push ... FAILED
[M8] test golden_hook_deny_git_reset_hard ... FAILED
[M8] test result: FAILED. 30 passed; 4 failed
```

Double-pinned: the unit test and the three goldens each catch it independently.

### B2. Mutant results for every test the diff adds

| mutant | what it deletes | test that should fire | result |
|---|---|---|---|
| M4 | `canonical_or_self` → identity (the pre-change comparison) | `test_matches_scope_sees_through_a_symlinked_spelling` | **FAILED** ✔ (other two green) |
| M4e | same, e2e | `hook_mode_allow_once_allows_pack_denied_command`, `…can_override_config_block_with_force_flag` | **both FAILED** ✔ |
| M5 | `Cwd` arm → `true` | `test_matches_scope_still_refuses_a_different_directory` | **FAILED** ✔ |
| M5b | `Project` arm → string prefix instead of components | same test (the `mine-too` half) | **FAILED** ✔ |
| M6 | fallback → a constant instead of "the path as given" | `test_matches_scope_falls_back_when_the_path_is_gone` | **all green — did not fire** ✘ |
| M1lib | hatch line never emitted | `test_format_denial_message_carries_the_allow_once_code` | **FAILED** ✔ |
| M1e | same, e2e | `hook_mode_denial_reason_quotes_the_minted_allow_once_code` | **FAILED** ✔ |
| M2lib | hatch quotes a hard-coded `00000` | `…carries_the_allow_once_code` | **FAILED** ✔ |
| M2e | same, e2e | `hook_mode_denial_reason_quotes_…` | **FAILED** ✔ |
| M3lib | hatch emitted even with no code | `test_format_denial_message_omits_the_hatch_when_no_code_exists` | **FAILED** ✔ |
| M7e | dcg mints an **empty** code | `hook_mode_denial_reason_quotes_…` | **green — did not fire** ✘ (at S2) |
| M7g | same | the three deny goldens | **green — did not fire** ✘ (at S2) |
| M8 | mask loses idempotence | `masking_an_allow_once_code_is_idempotent` + 3 goldens | **all four FAILED** ✔ |

Eleven of thirteen mutants were caught by the test they were aimed at, each with
a message naming the right thing. Notably M2e confirms the e2e test's own
stated claim — "asserting the two agree … is what keeps this from passing on a
hard-coded or stale code" — is true and not just an assertion about itself.

### B3. The two that did not fire

**M6 — `test_matches_scope_falls_back_when_the_path_is_gone` is close to
vacuous.** It compares one unresolvable path against itself, and both sides go
through the same transformation, so *any* deterministic fallback keeps them
equal. I replaced the fallback with a constant `/__unresolved__` and all three
scope tests stayed green. The test does pin something — a mutant that returned
`false` outright would fire — but not the thing its name and doc claim ("falls
back to the path as given"). Unchanged at S4, where the fallback moved inline
but stayed symmetric.

**M7 — an empty code was indistinguishable from a real one, in both guards.**
At S2, `code: String::new()` in `main.rs` produced `dcg allow-once \n\n`; the
golden mask consumed zero characters and emitted `dcg allow-once <DYNAMIC>`,
byte-identical to a real run, and `reason.contains(&format!("dcg allow-once
{code}"))` with `code == ""` reduces to `contains("dcg allow-once ")`, which the
bare prefix satisfies. Both guards passed over a denial offering nothing
runnable — the "an empty command string exits 0" shape.

**Closed at S4**, in both places, without my having to say so:
`format_denial_message` now takes `allow_once_code.filter(|code|
!code.is_empty())`, and the e2e test asserts `!code.is_empty() &&
code.chars().all(|c| c.is_ascii_alphanumeric())` *before* using the code as a
needle. I did not re-run M7 against S4 — the S4 sources differ from the mutant
sandbox — so that is a code reading, not a measurement. The reading is
unambiguous: the precondition assert is unconditional and fires first.

---

## F. Two more things I went looking for

### F1. `MatchSource::ConfigOverride` is spelled two ways, and nothing couples them

S4 adds `allow_once_suffices: !matches!(info.source, MatchSource::ConfigOverride)`
(`src/main.rs:761`). The pre-existing gate that actually refuses a bare
`dcg allow-once` for a config block is a *string* comparison against the Debug
form of the same variant:

```
src/main.rs:731   Some(format!("{:?}", info.source))      // written into the pending record
src/cli.rs:9947   selected.source.as_deref() == Some("ConfigOverride")
```

Rename the variant and the string side stops matching while the `matches!` side
keeps working. I broke it without touching any code — by rewriting the `source`
field in the pending store, which is exactly what a rename would write — and
measured what happens (`/tmp/coldrev/probe_source_coupling*.sh`, pre-change
binary, since `cli.rs` is byte-identical across every state here):

```
=== control: source left as dcg wrote it ===
PRE  recorded source: ['ConfigOverride']
PRE   dcg allow-once 17611 --yes  -> rc=1
       | Error: This denial came from your config blocklist; re-run with --force to override.
PRE   hook after: DENY — the config blocklist held

=== data-only mutant: source renamed to "ConfigBlocklist" ===
PRE   dcg allow-once 02622 --yes  -> rc=0
       | ✓ Allow-once entry created
PRE   hook after: DENY — the config blocklist held

PRE  mutate=no   --force --yes rc=0  force_allow_config=[True]   hook after: ALLOW
PRE  mutate=yes  --force --yes rc=0  force_allow_config=[False]  hook after: DENY
```

**I tried to turn this into a bypass and it held.** A second, independent gate —
the evaluator requires `force_allow_config: true` on the stored entry — keeps
the config block enforced. The actual consequence of the coupling breaking is
the opposite of a bypass: `dcg allow-once <code> --force --yes` prints
`✓ Allow-once entry created`, exits 0, and does nothing. A silent no-op on the
override path, fail-closed. Worth coupling; not a security hole.

### F2. Formatting and lint gates

`cargo fmt -- --check` (`ci.yml:46`) is red on this repo for 26 pre-existing
reasons. At S1 this change added a 27th (`src/hook.rs:765`, the widened
`format_denial_message` call). At S5 the sets are identical file-for-file:

```
=== PRE ===                              === S5 ===
   2 src/cli.rs                             2 src/cli.rs
   2 src/heredoc.rs                         2 src/heredoc.rs
   1 src/lib.rs                             1 src/lib.rs
   1 src/main.rs                            1 src/main.rs
   2 src/pending_exceptions.rs              2 src/pending_exceptions.rs
   ... (identical through all 13 files, 26 total) ...
```

`cargo clippy --all-targets -- -D warnings` (`ci.yml:49`): clean on the
pre-change tree (`Finished dev profile in 2m 31s`, 0 errors). My run against the
working tree caught it mid-edit and is not usable; §G re-runs it.

---

## G. Verify green — measured at the settled state (S6)

The tree stopped moving at 05:22. Everything in this section is one run over one
state, with a content-hash receipt on both ends so a mid-run edit could not be
reported as a clean result (`/tmp/coldrev/final_verify.sh`):

```
TREE-HASH-BEFORE: 59cf246… 214e5f0… fdd453c… 0f3b772… 70b8402… 36d984b… 3ae87b1… 269a699… 5ae1d85… 3fe0705… 7c5e83f… 948d1c4… 400dea1…
Thu Sep  3 05:48:39 CDT 2026
suite exit=101
TREE-HASH-AFTER : 59cf246… 214e5f0… fdd453c… 0f3b772… 70b8402… 36d984b… 3ae87b1… 269a699… 5ae1d85… 3fe0705… 7c5e83f… 948d1c4… 400dea1…
Thu Sep  3 06:02:15 CDT 2026
TREE STABLE across the run
--- failures ---
src/output/progress.rs - output::progress (line 27) - compile
test_audit_backtracking_requirements
--- known-red ledger ---
OK: 2 failing test(s), exactly the 2 in tests/KNOWN_RED.tsv.
    Every one cites a bead. Nothing new is broken.
check_known_red exit=0
```

(The files hashed, in order: `allowlist.rs cli.rs config.rs hook.rs main.rs
pending_exceptions.rs allowlist_command_tests.rs cli_e2e.rs golden_json_tests.rs
KNOWN_RED.tsv` and the three deny goldens.)

`suite exit=101` is expected and is not a finding: the two ledgered known-reds
make cargo exit non-zero, which is exactly why `check_known_red.sh` reads the
failure *set* rather than the exit code.

The tests this change is about, from that run:

```
test test_exact_command_allowlist_works ... ok
test test_user_allowlist_precedence_follows_xdg_config_home ... ok
test hook_mode_tests::hook_mode_allow_once_allows_pack_denied_command ... ok
test hook_mode_tests::hook_mode_allow_once_can_override_config_block_with_force_flag ... ok
test hook_mode_tests::hook_mode_allow_once_does_not_override_config_block_without_force ... ok
test hook_mode_tests::hook_mode_denial_reason_quotes_the_minted_allow_once_code ... ok
test hook_mode_tests::hook_mode_config_block_denial_does_not_offer_the_plain_hatch ... ok
test golden_hook_deny_filesystem ... ok
test golden_hook_deny_git_force_push ... ok
test golden_hook_deny_git_reset_hard ... ok
test result: ok. 2050 passed; 0 failed        (--lib)
```

### G1. `cargo clippy --all-targets -- -D warnings` goes from clean to failing

This is the one gate I found red at S6 that is green on `HEAD`. My first two
clippy runs were unusable — one caught the tree mid-edit — so I re-ran both
sides from scratch and then bisected it.

```
$ cd /tmp/coldrev/fmtpre  (HEAD sources)
$ ~/.cargo/bin/cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [optimized + debuginfo] target(s) in 2m 31s      # 0 errors

$ cd <repo>  (S6)
$ ~/.cargo/bin/cargo clippy --all-targets -- -D warnings
error: allocating a local array larger than 16384 bytes
  = note: `-D clippy::large-stack-arrays` implied by `-D warnings`
error: could not compile `destructive_command_guard` (lib test) due to 1 previous error
```

The diagnostic carries no usable span — a zero-byte primary span at
`src/lib.rs:1`, target kind `["lib"]` — so I bisected by copying one changed
`src/` file at a time into the HEAD tree (`/tmp/coldrev/bisect_clippy.sh`):

```
baseline (HEAD sources): 0
after adding src/config.rs: 0
after adding src/allowlist.rs: 0
after adding src/cli.rs: 0
after adding src/hook.rs: 0
after adding src/main.rs: 0
after adding src/pending_exceptions.rs: 1
```

Then inside that file (`/tmp/coldrev/bisect_inner*.py`):

```
variant A (matches_scope change only, new tests removed): 0
variant B (full file):                                    1
keep = scoped_entry only            -> 0
keep = scoped_entry + test #0       -> 0
keep = scoped_entry + test #1       -> 0
keep = scoped_entry + test #2       -> 0
```

Reproducible in both directions, three times:

```
full S6 file, run 2: 1
HEAD file, run 2:    0
full S6 file, run 3: 1
```

So it is the **aggregate** of the three new `test_matches_scope_*` tests in
`src/pending_exceptions.rs`, not any one of them — consistent with a span-less
`large_stack_arrays` on a promoted item that crosses 16 KiB once enough test
items exist. `.github/workflows/ci.yml:49` runs exactly this command. The `check`
job would in practice stop earlier, at the already-red `cargo fmt -- --check`
(26 pre-existing violations, unchanged by this diff) — but that is
someone else's debt masking this, not this change being clean.

Cheapest fix consistent with the repo's lint config: an
`#[allow(clippy::large_stack_arrays)]` on the `tests` module in
`src/pending_exceptions.rs`, or wherever the real allocation turns out to live
once someone has a span.


## VERDICT

**APPROVE WITH FINDINGS**, pinned to state **S6** (the state whose hashes §G
records). Two findings were BLOCKING when I raised them; both were fixed while
this review was running, and I re-measured both rather than taking the fix on
trust. Everything still open is NON-BLOCKING.

A caveat that belongs in the verdict rather than a footnote: the working tree
moved six times during this review, three of those without notice, and at
05:13 it did not compile. My approval covers S6 and nothing after it. The
mutant harness is still in `/tmp/coldrev` and re-running it costs one command
(`/tmp/coldrev/all_mutants.sh`) after `rsync -a src/ tests/ /tmp/coldrev/pre/`.

### Findings

1. **BLOCKING — fixed at S2.** `mask_allow_once_code_in_text` was not
   idempotent, and both sides of the golden comparison run through it, so the
   golden's own `<DYNAMIC>` became `<DYNAMIC><DYNAMIC>` and all three deny
   goldens failed against correct output.
   *Evidence:* `golden_hook_deny_filesystem`, `golden_hook_deny_git_force_push`,
   `golden_hook_deny_git_reset_hard` all `... FAILED` in
   `/tmp/coldrev_suite_after.log`, with the diff showing
   `expected: "... <DYNAMIC><DYNAMIC> ..."` vs `actual: "... <DYNAMIC> ..."`.
   `UPDATE_GOLDEN=1` could not have converged it — that path returns `Ok(())`
   before comparing. Re-verified after the fix: `test result: ok. 34 passed`,
   and mutant M8 shows the new `masking_an_allow_once_code_is_idempotent`
   plus the three goldens all go red if the fix is removed.

2. **BLOCKING — fixed at S5.** `tests/KNOWN_RED.tsv` still listed the three
   tests this change fixes, which the repo defines as a hard error in both
   directions.
   *Evidence:* `scripts/check_known_red.sh /tmp/coldrev_suite_after.log` →
   `FAIL: tests/KNOWN_RED.tsv lists tests that now PASS`, exit 1. Fixed by
   `git diff tests/KNOWN_RED.tsv` removing all three rows.

3. **NON-BLOCKING — open.** `load_default_allowlists` silently narrowed which
   user allowlist locations are read. With `XDG_CONFIG_HOME` set,
   `~/.config/dcg/allowlist.toml` and the platform-native allowlist are no
   longer consulted at all; before, both were.
   *Evidence:* the PRE/POST location table in §A1 — `PRE $HOME/.config/dcg (XDG
   set) -> READ` vs `POST $HOME/.config/dcg (XDG set) -> NOT read`, same for
   `$HOME/Library/Application Support/dcg`. A macOS user who exports
   `XDG_CONFIG_HOME` somewhere other than `~/.config` and keeps an allowlist in
   either old location loses every entry, silently. It fails closed, and
   `test_user_allowlist_precedence_follows_xdg_config_home` now pins the new
   precedence as intended — but the *removed* fallback is untested and
   undocumented. `Config::load_user_config_layer` solves the same problem by
   falling through the three candidates instead of picking one, which is why
   `config.toml` never had this bug; the same shape here would fix the split
   without dropping anyone's file.

4. **NON-BLOCKING — fixed at S3.** The `matches_scope` doc claimed a production
   symptom ("the escape hatch of AGENTS.md §8 not opening") that I could not
   reproduce.
   *Evidence:* §A4 — on the pre-change binary, end to end through a symlinked
   cwd, `dcg allow-once <code> --yes` opened the hatch (`3) second hook run ->
   ALLOW`), because every writer derives `scope_path` from `getcwd(3)`. S3
   rewrote the comment to say exactly that, and made canonicalisation
   all-or-nothing, which also closes the Windows `\\?\` mixed-case narrowing I
   had flagged as an unverified suspicion.

5. **NON-BLOCKING — open.** `test_matches_scope_falls_back_when_the_path_is_gone`
   does not pin what its name claims. It compares one unresolvable path against
   itself, and both sides go through the same transformation, so any
   deterministic fallback keeps them equal.
   *Evidence:* mutant M6 replaced the fallback with a constant
   `/__unresolved__`; all three scope tests stayed green
   (`test result: ok. 3 passed`). Still symmetric at S6.

6. **NON-BLOCKING — fixed at S4/S6.** An empty allow-once code was
   indistinguishable from a real one in both new guards.
   *Evidence:* mutants M7e and M7g against S2 — `code: String::new()` in
   `main.rs`, and both `hook_mode_denial_reason_quotes_the_minted_allow_once_code`
   and the three deny goldens stayed green over a denial offering nothing
   runnable. Closed by `allow_once_code.filter(|code| !code.is_empty())`, the
   e2e test's new non-empty precondition, and
   `test_format_denial_message_treats_an_empty_code_as_no_code`.

7. **NON-BLOCKING — fixed at S4.** The hatch line was advertised on config
   blocklist denials, where the command it advertises errors and the error names
   the `--force` escalation.
   *Evidence:* §C3 `cfg-yes` — code `32771` scraped from the reason of a config
   block denial, and `dcg allow-once 32771 --yes` →
   `Error: This denial came from your config blocklist; re-run with --force to
   override.` Closed by `allow_once_suffices` plus
   `hook_mode_config_block_denial_does_not_offer_the_plain_hatch`.

8. **NON-BLOCKING — open, pre-existing, worth a decision.** `--yes` skips the
   `Type 'FORCE' to confirm override:` prompt, so `dcg allow-once <code> --force
   --yes` clears a config blocklist with no human anywhere
   (`src/cli.rs:10014`, `needs_prompt = !(cmd.yes || cmd.dry_run)`).
   *Evidence:* §C3 `cfg-force-yes  redeem_rc=0  verdict_after=ALLOW
   (self-cleared)`, stdin at `/dev/null` throughout. This change no longer feeds
   that chain from the reason text (finding 7), so the exposure is back to what
   it was — but the FORCE prompt is the only thing standing between an agent and
   the user's explicit "never" list, and `--yes` removes it.

9. **NON-BLOCKING — open, pre-existing, adjacent.** Six other hand-rolled
   spellings of the user-config-dir policy survive, and one demonstrably
   disagrees with the new function.
   *Evidence:* §D1 table, and `/tmp/coldrev/probe_pending_path.sh` with
   `XDG_CONFIG_HOME='~/cfg'` on the post-change binary:
   `<sandbox>/home/cfg/dcg/allowlist.toml` next to
   `<sandbox>/work/~/cfg/dcg/pending_exceptions.jsonl` — dcg creates a directory
   literally named `~` under the cwd for the allow-once store, because
   `pending_exceptions::config_dir_override` skips `resolve_config_path_value`.
   Same bug class as `.agent-config-0kt9v`, in the file this change edits.

10. **NON-BLOCKING — open.** `Config::user_config_path` (`src/config.rs:3180`)
    is a line-for-line duplicate of the new `user_config_dir` plus a `mkdir`,
    3000 lines below it in the same file. The most obvious missed call site.
    *Evidence:* both read in full; arm for arm identical
    (XDG → `~/.config/dcg` if it exists → platform-native).

11. **NON-BLOCKING — open.** `MatchSource::ConfigOverride` is now spelled two
    ways with nothing coupling them: `!matches!(info.source,
    MatchSource::ConfigOverride)` (`src/main.rs:761`, new) and
    `selected.source.as_deref() == Some("ConfigOverride")` (`src/cli.rs:9947`,
    against `format!("{:?}", info.source)`).
    *Evidence:* §F1 — I broke the string by rewriting the pending store's
    `source` field, with no code edit. **I could not turn it into a bypass**:
    the evaluator's independent `force_allow_config` gate held
    (`mutate=yes --force --yes rc=0 force_allow_config=[False] hook after:
    DENY`). The real consequence is a silent no-op — `dcg allow-once --force
    --yes` prints `✓ Allow-once entry created`, exits 0, and does nothing.

12. **NON-BLOCKING — open.** Two documents carry a literal
    `permissionDecisionReason` example and neither was updated: `AGENTS.md:370`
    (the integrator-facing contract) and `docs/json-schema/hook-output.json:86`.
    *Evidence:* both read; both still show the pre-change string. No test
    asserts them, so nothing went red.

13. **NON-BLOCKING — fixed at S3.** The comment "Same wording as
    `output::denial`" was wrong — `src/output/denial.rs:176` says
    `To allow once:`, the new line says `If this is a false positive:`. S3's
    comment now states the difference is deliberate and why.

14. **NON-BLOCKING — fixed at S4.** S1 added a 27th `cargo fmt --check`
    violation at `src/hook.rs:765`.
    *Evidence:* `PRE fmt diffs: 26 / POST fmt diffs: 27`, the extra one being
    the widened `format_denial_message` call. At S5/S6 the two sets are
    identical file-for-file, 26 each.

### Answers to the brief's five questions, in one line each

1. **Is the diagnosis right?** Yes, for all three tests, proven by A/B against a
   binary built from `HEAD` (§A1–A3) — with the caveat that the allow-once
   fix's *production* rationale did not survive an end-to-end test (§A4,
   finding 4), which the author has since corrected in the source.
2. **Do the new tests guard?** Eleven of thirteen mutants were caught by the
   test aimed at them, by name (§B2). The two that were not are findings 5
   and 6.
3. **Is the denial-text change safe?** Nothing parses the string; the code was
   never a secret and is already in two sibling JSON fields; the real change is
   *which consumers can see it*, and the one place that mattered — a config
   blocklist denial — is now excluded (§C, findings 7 and 8).
4. **Over-built or in the wrong place?** `user_config_dir` is the right seam and
   fixes a real bug, but it narrows reads (finding 3) and leaves six siblings
   standing (findings 9, 10). `canonical_or_self` is defensible hardening rather
   than the correctness fix it was first billed as (finding 4). The hatch line
   and the golden mask are both minimal.
5. **What was missed?** Findings 3, 5, 8, 9, 10, 11, 12 — plus the observation
   that `hook_mode_allow_once_does_not_override_config_block_without_force` was
   green before this change *for the wrong reason* (§E2), so its pre-change
   green was not evidence of anything.

### Unverified suspicions, stated as such

- Whether Claude Code renders only `permissionDecisionReason` to its agent — the
  premise the whole hatch line rests on — is a claim about an external product I
  cannot test from this repo. What I *can* confirm is the half that lives here
  (the code is absent from that string before, present after), and that a live
  dcg denial in this session carried no code.
- `cargo clippy --all-targets -- -D warnings` — see §G.

---

## VERDICT

*(This block is authoritative and supersedes the VERDICT block immediately above
it, which I drafted while the clippy bisect in §G1 was still running and which
therefore says "everything still open is NON-BLOCKING". That is no longer true.
The file is append-only, so the superseded text stays where it is. Findings
1–14 are unchanged; finding 15 is new and the headline changes with it.)*

**APPROVE WITH FINDINGS — one of them BLOCKING**, pinned to state **S6**, whose
content hashes §G records and whose full-suite run carries a
`TREE STABLE across the run` receipt.

The change is correct, the diagnosis is right for all three tests it set out to
fix, and the tests it adds genuinely guard — eleven of thirteen mutants died
against the test aimed at them. The blocking item is a lint gate, not the logic.

### Findings, most severe first

1. **BLOCKING — OPEN.** `cargo clippy --all-targets -- -D warnings`
   (`.github/workflows/ci.yml:49`) is clean on `HEAD` and fails with this change.
   *Evidence (§G1):* HEAD tree → `Finished dev profile in 2m 31s`, 0 errors.
   S6 → `error: allocating a local array larger than 16384 bytes` →
   `could not compile destructive_command_guard (lib test)`. Bisected by copying
   one changed `src/` file at a time into the HEAD tree: clean through
   `config.rs`, `allowlist.rs`, `cli.rs`, `hook.rs`, `main.rs`; fires on
   `pending_exceptions.rs`. Inside that file it is the aggregate of the three
   new `test_matches_scope_*` tests — the `matches_scope` change alone is clean
   and so is the helper plus any single one of them. Reproduced three times in
   both directions. Fix is one `#[allow(clippy::large_stack_arrays)]`.
   *Not a reason to reject the change* — but it must not land like this, and
   the fact that CI would stop earlier at the already-red `cargo fmt --check` is
   pre-existing debt masking it, not a reason to ship.

2. **BLOCKING — fixed at S2.** Non-idempotent golden mask failed all three deny
   goldens against correct output. *Evidence:* §B1, three `... FAILED` lines
   with `expected "<DYNAMIC><DYNAMIC>"` vs `actual "<DYNAMIC>"`. Re-verified
   green; mutant M8 shows the fix is double-pinned.

3. **BLOCKING — fixed at S5.** `tests/KNOWN_RED.tsv` listed three now-passing
   tests. *Evidence:* §E1, `check_known_red.sh` exit 1 → after the fix, exit 0
   with `OK: 2 failing test(s), exactly the 2 in tests/KNOWN_RED.tsv`.

4. **NON-BLOCKING — OPEN.** `load_default_allowlists` silently stops reading
   `~/.config/dcg/allowlist.toml` and the platform-native allowlist whenever
   `XDG_CONFIG_HOME` is set. *Evidence:* the PRE/POST table in §A1. Fails
   closed, and the new precedence is now pinned by a test, but the dropped
   fallback is undocumented and takes an existing user's entries with it.
   `Config::load_user_config_layer` falls through its three candidates instead
   of picking one — the same shape here fixes the write/read split without
   dropping anyone's file.

5. **NON-BLOCKING — OPEN.** `test_matches_scope_falls_back_when_the_path_is_gone`
   does not pin what its name claims: both sides go through the same
   transformation, so any deterministic fallback passes. *Evidence:* mutant M6,
   constant fallback, all three scope tests stayed green.

6. **NON-BLOCKING — OPEN, pre-existing.** `--yes` skips the `Type 'FORCE'`
   confirmation, so `dcg allow-once <code> --force --yes` clears a config
   blocklist with no human. *Evidence:* §C3 `cfg-force-yes redeem_rc=0
   verdict_after=ALLOW (self-cleared)`, stdin `/dev/null`.

7. **NON-BLOCKING — OPEN, pre-existing, adjacent.** Six other hand-rolled
   spellings of the user-config-dir policy survive, and
   `pending_exceptions::config_dir_override` demonstrably disagrees with the new
   function. *Evidence:* §D1 — with `XDG_CONFIG_HOME='~/cfg'`, the allowlist
   lands in `<sandbox>/home/cfg/dcg/` and the allow-once store in
   `<sandbox>/work/~/cfg/dcg/`, a directory literally named `~`.

8. **NON-BLOCKING — OPEN.** `Config::user_config_path` (`src/config.rs:3180`) is
   a line-for-line duplicate of the new `user_config_dir`, in the same file.
   The most obvious missed call site. *Evidence:* both read in full, arm for arm.

9. **NON-BLOCKING — OPEN.** `MatchSource::ConfigOverride` is now spelled two
   ways with nothing coupling them (`matches!` at `src/main.rs:761`, the string
   `"ConfigOverride"` at `src/cli.rs:9947`). *Evidence:* §F1 — I broke the
   string with a data-only edit to the pending store and **could not turn it
   into a bypass**; the evaluator's `force_allow_config` gate held
   (`hook after: DENY`). The consequence is a silent no-op:
   `dcg allow-once --force --yes` prints `✓ Allow-once entry created`, exits 0,
   and changes nothing.

10. **NON-BLOCKING — OPEN.** `AGENTS.md:370` and
    `docs/json-schema/hook-output.json:86` both carry a literal
    `permissionDecisionReason` example that no longer matches dcg's output.
    *Evidence:* both read; no test asserts them, so nothing went red.

11. **NON-BLOCKING — fixed at S3.** The `matches_scope` doc claimed a production
    symptom I could not reproduce. *Evidence:* §A4 — the hatch opened end to end
    on the pre-change binary through a symlinked cwd. S3 rewrote the claim
    honestly and made canonicalisation all-or-nothing, which also closed the
    Windows `\\?\` narrowing I had flagged as an unverified suspicion.

12. **NON-BLOCKING — fixed at S4/S6.** An empty allow-once code was
    indistinguishable from a real one in both new guards. *Evidence:* mutants
    M7e and M7g, both green over a denial offering nothing runnable. Closed by
    `filter(|code| !code.is_empty())`, the e2e precondition assert, and
    `test_format_denial_message_treats_an_empty_code_as_no_code`.

13. **NON-BLOCKING — fixed at S4.** The hatch line was advertised on config
    blocklist denials, where the command it names errors and the error names the
    `--force` escalation. *Evidence:* §C3 `cfg-yes`. Closed by
    `allow_once_suffices` plus a new e2e test.

14. **NON-BLOCKING — fixed at S3.** "Same wording as `output::denial`" was
    inaccurate (`To allow once:` vs `If this is a false positive:`).

15. **NON-BLOCKING — fixed at S4.** S1 added a 27th `cargo fmt --check`
    violation at `src/hook.rs:765`. *Evidence:* `PRE 26 / POST 27`; at S6 the
    two sets are identical file-for-file.

### Unverified suspicions, marked as such

- **Unverified suspicion:** that Claude Code renders only
  `permissionDecisionReason` to its agent — the premise the whole hatch line
  rests on. It is a claim about an external product and this repo cannot test
  it. The half that lives here I did verify: the code is absent from that string
  before the change and present after, and a live dcg denial in this session
  carried no code.

### Note on the review target

The tree moved six times while I was reviewing, three without notice, and at
05:13 it did not compile. Findings 2, 3, 11, 12, 13, 14 were fixed underneath
me; I re-measured each rather than taking the fix on trust, and I have said so
where I only read the code (finding 12's S4 half). My approval covers S6 and
nothing after it. Re-running the whole mutant harness costs two commands:
`rsync -a src/ tests/ /tmp/coldrev/pre/` then `/tmp/coldrev/all_mutants.sh`.
