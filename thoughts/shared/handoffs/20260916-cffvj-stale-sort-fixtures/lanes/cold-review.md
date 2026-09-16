# Cold review: stale sort heredoc fixtures (cffvj)

Scope: I reviewed the working-tree diff in `/Users/dalecarman/dev/destructive_command_guard`. It is byte-identical to `lanes/cold-review-target.diff`: `git diff | diff - cold-review-target.diff` printed `SAME`. It touches 4 files, all under tests/. src/ is unchanged from HEAD 6898e128.
Lane writes: only this file. There were no git writes. `cargo build`/`nextest` wrote only to target/. One scratch file, `$TMPDIR/x.out`, held `dcg explain` output and was deleted in the same command.

## Summary

The diff does what it says. It updates the 9 tests that CI run 35078538017 failed. All 9 failed because of sort, and none of the fixes brings sort back into NON_EXECUTING_HEREDOC_COMMANDS. No assertion was weakened. The moved corpus row is checked as a deny by 3 tests. It fails in both directions: with sort on the list it gives allow, and without sort it gives deny. I found no blockers and no should-fix items. There are 7 optional nits.

## Commands and what they showed

1. `gh run view 35078538017 -R carmandale/destructive_command_guard --log-failed` (summary block): 9 FAIL.
   - golden_isomorphism: `golden_category_invariants`, `golden_false_positives_all_allowed`, `golden_full_corpus_verification`
   - regression_corpus: `corpus_false_positives_isomorphism`, `corpus_full_summary`
   - repro_heredoc_pipe_to_shell: `env_assignment_before_a_data_sink_is_still_data`, `every_listed_receiver_masks_its_body_including_the_new_entries`, `split_filter_executes_its_stdin_so_its_body_is_never_data_bvt4k`
   - repro_search_receiver_redirection: `non_search_receivers_were_never_affected_and_still_are_not`
   - Every panic message is about sort. The corpus failures say `Description: sort heredoc is DATA / Expected: allow / Actual: deny / Rule ID: Some("core.filesystem:rm-rf-root-home")` (8 times). The mask failures say `body should stay masked (...)` for `sort <<'EOF'`, `cat <<'EOF' | sort`, and `cat <<'EOF' | LC_ALL=C sort`.
2. `gh run view` job conclusions:
   - Run 35071585150 on f1cea3c9 (the parent of 8234603c): `check success`.
   - Run 35072885167 on 8234603c: `check failure`.
   - So the same sort row gives allow with sort on the list and deny without it. It works as a tripwire in both directions.
3. `cargo nextest run --test golden_isomorphism --test regression_corpus --test repro_heredoc_pipe_to_shell --test repro_search_receiver_redirection`: `50 tests run: 50 passed, 0 skipped`, rc=0.
4. `cargo nextest run --lib -E 'test(/slwtp|bvt4k|vyjkz/)'`: `sort_compress_program_executes_its_stdin_so_its_heredoc_body_is_not_masked_slwtp` PASS, `split_filter_..._bvt4k` PASS.
5. `cargo nextest run ... --no-capture` on the 4 corpus decision tests:
   - `All 115 edge case tests passed with full isomorphism check`, `EdgeCases: 115/115 [OK]`, `FalsePositives: 166/166 [OK]`, `Total: 377 tests (377 passed, 0 failed)`.
   - `rg -c '^\[\[case\]\]'`: the trade file went from 6 rows at HEAD to 7, and heredoc_data.toml went from 25 to 24. The edge_cases files sum to 115, so the moved row is loaded and no row was dropped.
6. `DCG_HISTORY_DISABLED=1 DCG_HISTORY_ENABLED=false DCG_NO_UPDATE_CHECK=1 DCG_NO_COLOR=true ./target/debug/dcg explain <cmd>` (binary rebuilt from HEAD src):
   - `cat <<'EOF' | sort\nrm -rf /\nEOF` gives `Decision: DENY`.
   - `sort <<'EOF'\nrm -rf /\ngit clean -fd\nEOF` (the moved row) gives `Decision: DENY`.
   - `cat <<'EOF' | tr a-z A-Z\nrm -rf /\nEOF` (the new control) gives `Decision: ALLOW`.
7. Repo-wide search for sort treated as data, excluding target/, .git/ and thoughts/:
   - `rg -e '\| *sort\b' -e '\bsort +<<' -e '"sort"' ...`
   - `rg -e '\bsort\b[^\n]{0,40}<<' -e '<<[^\n]{0,60}\|[^\n]{0,30}\bsort\b'`
   - `rg -w sort` over non-.rs files, src/, benches/ and fuzz/
   - Nothing else asserts sort as a data sink. The only other hits:
     - scripts/scan_precommit_e2e.sh uses real `| sort` pipelines.
     - src/normalize.rs:2496 has `diff <(sort a) <(sort b)`, a redirection-split test that has nothing to do with the list.
     - tests/corpus/edge_cases/multi_segment.toml:29 has `cat file | grep pattern | sort | uniq`, which has no heredoc.
     - Two comment-only leftovers, below as nits N2 and N4.

## Answers

### Q1: Do the changed assertions match current src, and could any of them hide a regression?

Yes, they match, and none hides a regression.

- **Corpus row, allow in false_positives moved to deny in edge_cases.** The command bytes are unchanged; only the verdict flipped. Current src gives deny (item 6), and so did CI at 8234603c (item 1). Re-adding sort makes it red again (item 2).
- **`env_assignment_before_a_data_sink_is_still_data`, sort replaced by `tr a-z A-Z`** (tests/repro_heredoc_pipe_to_shell.rs:167). `next_pipeline_stage` (src/heredoc.rs:2330-2355) skips `LC_ALL=C` through `is_env_assignment` and returns `tr`. `tr` is a list member (src/heredoc.rs:1964). After that the scan resumes at `end` and reaches the newline. If the env skip were deleted, the stage word would become `LC_ALL=C`, which is not a member, and `heredoc_output_reaches_executor` would return true. The body would stay visible and the test would go red. The added `a-z A-Z` args contain no operator bytes, so the tested path is the same.
- **bvt4k control, sort replaced by `tr a-z A-Z`** (:490-494). This mirrors the src bvt4k arm control at src/heredoc.rs:5486. It can still fail: CI shows the same `assert_body_masked` failing for a non-member.
- **`every_listed_receiver` loses "sort".** That is correct, because the test only checks list members. The inverse direction is covered by the src slwtp arm (src/heredoc.rs:5514, cases c1–c4) and by the corpus row.
- **`non_search_receivers...`, sort replaced by `tr a-z A-Z`** (tests/repro_search_receiver_redirection.rs:133). `rg '"tr"|"uniq"|"sort"' src/context.rs src/normalize.rs src/evaluator.rs` found no hits, so sanitize has no special case for tr. The arg-less shape, where the heredoc operator is the first positional word, is still covered by `cat` and `head`.

### Q2: Did the diff miss any test, fixture, doc, or corpus row?

Nothing it missed is still red. Two stale comments remain (N2, N4), and neither is an assertion.

### Q3: Was coverage lost, and is the moved row actually checked?

No coverage was lost.

The moved row's `expected = "deny"` is checked by 3 tests:
- `corpus_edge_cases_isomorphism` (tests/regression_corpus.rs:539, via `run_category_tests` and `verify_corpus_case`)
- `corpus_full_summary` (:556)
- `golden_full_corpus_verification` (tests/golden_isomorphism.rs:184, via `verify_corpus_batch` and `verify_corpus_case`)

`verify_corpus_case` (src/packs/test_helpers.rs:1170-1188) compares `case.expected` with the actual decision for every category.

Two tests do not check it:
- `golden_edge_cases_stable` accepts any decision.
- `golden_category_invariants` has no edge_cases invariant.

That matches the awk precedent from 85e62aa4. The placement is right: a plain `sort <<'EOF'` is a false positive we accept, not a bypass.

The src slwtp arm pins re-adding sort in both roles:
- as the receiver: c3, `sort --compress-program=sh <<'EOF'`
- as a downstream stage: c1, c2, and the plain `| sort` in c4

The plain receiver form is pinned end to end by the corpus row.

### Q4: Are the new comments accurate?

Mostly. N1 and N7 are small wording problems.

### Q5: Is there anything simpler?

The diff is already about as small as it can be.
- `uniq` would be a drop-in with the same arity as `sort` in all three tests. That is a marginal gain and would break symmetry with the src bvt4k arm's `tr`.
- The test comments repeat the full rationale from the src doc comment. The awk and split precedents in the same files do the same, but the repeats have already drifted from each other (N1). A one-line pointer to the doc on `NON_EXECUTING_HEREDOC_COMMANDS` would drift less.

## Findings

### N1 (nit): `-S` "forces the spill" overstates the measurement

- **Where:** tests/repro_heredoc_pipe_to_shell.rs:380 says "`-S` in the same argv forces the spill". tests/corpus/edge_cases/heredoc_expansion_trade.toml:85 says it "lets the writer force the spill".
- **Problem:** The measurement is weaker. src/heredoc.rs (8234603c) says "A 12 KB body did not spill and did not fire, so the size floor is real". The probe output (`agent-config specs/333-dcg-heredoc-body-false-positives/probes/slwtp-sort-compress-program-output.txt`) shows `body~300L script=18463 bytes ... marker absent — no spill at this size` under `-S 1024`. End to end, only the 1.8 MB body spilled.
- **Scenario:** A reader takes "forces" literally and cites it to argue that any heredoc under `-S` executes.
- **Fix:** heredoc_data.toml:88-89 already has the exact wording, "sets the spill threshold". Use it in all three places.

### N2 (nit): the module doc still lists `sort` beside the pinned rows

- **Where:** tests/repro_search_receiver_redirection.rs:20. The module doc still says "`cat`, `head`, `sort`, `sed -n p` and `jq .` were unaffected".
- **Problem:** The pinned rows at :130-137 now have `tr a-z A-Z` and no `sort`. As a statement about the y5eor bug it is still true, since sort is not a search command, but it no longer matches the list below it. sort's body now reaches the packs by design.
- **Scenario:** A reader compares the doc with the pins and thinks a sort row was dropped by accident.
- **Evidence:** `rg -n -w sort tests/` shows line 20 is the only hit that isn't one of the new comments.

### N3 (nit): the trade file's header "exact twin" claim is false for two rows

- **Where:** tests/corpus/edge_cases/heredoc_expansion_trade.toml:3-5 says "Every row here is the exact twin of a row in ... heredoc_data.toml, differing only in that its delimiter is NOT quoted".
- **Problem:** The quoted awk row, added in 85e62aa4, already broke this. The diff adds a second exception: the sort row is quoted and has no twin. The section banners explain both exceptions, but the header does not.

### N4 (nit): src still calls the list group "the sort/uniq/tr family"

- **Where:** src/heredoc.rs:2033, `// Further text transforms (the sort/uniq/tr family)`. `git blame` dates it to da4df7d42, and 8234603c left it alone.
- **Problem:** The group is still named after a command that is no longer on the list. This is outside the tests-only diff, so it is noted here, not asked for.

### N5 (nit): no tests/ arm checks the end-to-end DENY for `cat <<'EOF' | sort`

- **Where:** tests/repro_heredoc_pipe_to_shell.rs has no end-to-end DENY assertion for `cat <<'EOF' | sort`. The awk arm (vyjkz, fn at :433, `assert_denied` at :455) and the split arm (bvt4k, fn at :460, `assert_denied` at :485) both call `assert_denied`. The sort case is held only by the src slwtp arm, which checks the mask, and by the corpus row, which covers only the receiver form.
- **Why this is not a regression:** Nothing held the opposite before. Measured today, `dcg explain` gives DENY (item 6). The mask and the evaluator both go through one function, `heredoc_body_is_inert` (src/heredoc.rs:3038-3053, called at src/evaluator.rs:2589 and :2656). A mask-only mutant like 41wu8 can't split them without changing that shared function.
- **Fix (optional):** a `sort_..._slwtp` sibling arm in tests/.

### N6 (nit): the moved corpus row has no `rule_id`

- **Where:** tests/corpus/edge_cases/heredoc_expansion_trade.toml:90-93.
- **Scenario:** A future change denies `sort <<'EOF'` for an unrelated reason while the body is masked again. The row stays green.
- **Fix:** CI already shows the rule this deny comes from, `core.filesystem:rm-rf-root-home`. Adding `rule_id = "core.filesystem:rm-rf-root-home"` would bind the deny to the body. The awk rows set the precedent of having no `rule_id`, so this is optional.

### N7 (nit): "as in the src/heredoc.rs arm" does not say which arm

- **Where:** tests/repro_heredoc_pipe_to_shell.rs:491.
- **Problem:** src/heredoc.rs has several arms. It is accurate if it means the bvt4k arm, whose control uses `tr` (:5486). The slwtp arm's control uses `cut -c1-5` (:5565).
- **Fix:** Say "the bvt4k arm".

## Blockers vs non-blockers

- Blockers: none.
- Should-fix: none.
- Nits: N1–N7, all optional. N1 and N2 are one-line comment edits if the author wants them before committing.

## Residual risk

- I ran no mutants, because editing src/ was out of bounds for this lane. That both directions fail rests on CI history: check was green on f1cea3c9 with sort on the list and red on 8234603c without it, for these exact rows. The control's ability to fail rests on the same CI failures of `assert_body_masked`.
- I ran only the 4 affected test binaries plus 2 lib arms, not the full suite. After the check job, CI's downstream jobs (e2e, scan-regression, memory-tests, coverage) have not run on this diff. The repo-wide search found no sort-as-data fixtures in their inputs.

VERDICT: APPROVE
