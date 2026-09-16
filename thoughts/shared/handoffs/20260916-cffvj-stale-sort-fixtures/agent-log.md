# Coordinator log — .agent-config-dcg-golden-corpus-stale-sort-cffvj

Owner: Claude Code session 29a62cfc-fdd1-4ec7-81cc-a2c431b531f3 (account faith), coordinator.
Goal: `check` green on carmandale/destructive_command_guard main by updating the
fixtures that still encode `sort` as a heredoc data sink after 8234603c removed it
from NON_EXECUTING_HEREDOC_COMMANDS. Expectation updated, rule not reverted.

## Evidence

- CI run 35078538017 (head 6898e128), job 104736628740 `check`: 3201 run, 9 failed.
  The 9: golden_isomorphism {golden_false_positives_all_allowed,
  golden_category_invariants, golden_full_corpus_verification}; regression_corpus
  {corpus_false_positives_isomorphism, corpus_full_summary};
  repro_heredoc_pipe_to_shell {env_assignment_before_a_data_sink_is_still_data,
  every_listed_receiver_masks_its_body_including_the_new_entries,
  split_filter_executes_its_stdin_so_its_body_is_never_data_bvt4k};
  repro_search_receiver_redirection {non_search_receivers_were_never_affected_and_still_are_not}.
  Every panic message names `sort` as the assumed data sink.
- The bead body named only the 5 corpus tests; the other 4 were read from the CI log.
- REPRODUCED locally on a6a77566 for the corpus binaries (5 failed, FalsePositives 166/167).
- 8234603c touched only src/heredoc.rs; it moved its own unit control sort -> tr
  (src/heredoc.rs ~5479) but no file under tests/.

## Decisions

- Corpus row: moved, not deleted, following 85e62aa4 (awk): the quoted
  `sort <<'EOF'` row leaves false_positives/heredoc_data.toml and lands in
  edge_cases/heredoc_expansion_trade.toml as `deny`, with a pointer comment left behind.
- Receiver list: `sort` removed, comment rewritten to record slwtp's reversal, as
  awk/split were.
- Controls (env-assignment stage, split arm control, non-search receiver row):
  `sort` -> `tr a-z A-Z`, following the 8234603c unit-test control.

## Local proof (HEAD 6898e128 + diff sha256 0583f93972b5113f…)

- 4 binaries: 50 run, 50 passed.
- Mutant A (`"sort"` restored to the list): corpus_edge_cases_isomorphism,
  golden_full_corpus_verification, corpus_full_summary red, naming the moved row.
- Mutant B (`"tr"` removed): all 3 new controls red with their own messages.
- cargo fmt --check rc 0; clippy on the 4 test targets Finished.

## Lanes

- cold-review — Claude Code Workflow tool, one agent (default workflow subagent,
  inherits session model). Purpose: one cold pass on the exact diff above.
  Log: lanes/cold-review.md (the lane writes it; append-only). Write permission:
  that log only — no source, test, git, or tracker writes. Stop: verdict written.
  Visibility: user-visible in /workflows. No pin (Claude runtime).
Observe: cold-review.md parent-harvest

## Cold review — harvested

Workflow wf_0d0969f4-04a, one agent, 634 s. Log: lanes/cold-review.md (12,906 bytes,
written by the lane; `git status` after the run showed no other path touched).
Target: lanes/cold-review-target.diff (sha256 0583f93972b5113f…). VERDICT: APPROVE.
Blockers none, should-fix none, nits N1–N7.

- N1 `-S` "forces the spill" overstates the probe (12 KB did not spill) — **Applied**:
  "sets the spill threshold" in the trade file and the receiver-list comment.
- N2 module doc of repro_search_receiver_redirection.rs still names `sort` — **Rejected**:
  that sentence records what the y5eor defect measured, and sort was genuinely
  unaffected by it; swapping in `tr` would rewrite a measurement. The pin's own
  comment says why sort left the list.
- N3 trade-file header "every row is an unquoted twin" false for awk and sort — **Applied**.
- N4 src/heredoc.rs:2033 "the sort/uniq/tr family" — **Rejected**: a family label,
  not a membership claim; sort's removal is recorded at its old slot (src/heredoc.rs:1960).
- N5 no tests/ end-to-end DENY arm for `cat <<'EOF' | sort` — **Rejected**: new coverage
  beyond this bead; reviewer measured no prior opposite pin, mask and verdict share
  `heredoc_body_is_inert`, and mutant A shows the corpus row reddens on re-adding sort.
- N6 moved row has no `rule_id` — **Rejected**: its awk siblings carry none, and a
  rule_id couples the row to a rule name unrelated to what it guards.
- N7 "the src/heredoc.rs arm" ambiguous — **Applied**: "the bvt4k arm".

Post-review delta: lanes/post-review.diff. Every +/- line that differs from the reviewed
target is a `#` or `//` comment (filter for non-comment lines printed nothing), so the
correction is not material and does not reopen review. Re-run: 4 binaries 50/50,
cargo fmt --check rc 0.
