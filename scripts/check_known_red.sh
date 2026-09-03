#!/usr/bin/env bash
#
# Compare the suite's real failures against tests/KNOWN_RED.tsv.
#
# Exit 0 only when the two agree exactly. Disagreement in EITHER direction is an
# error: an unlisted failure is a regression, and a listed test that now passes
# means the ledger is lying about the repo.
#
# Usage:
#   scripts/check_known_red.sh                 # run the suite, then check
#   scripts/check_known_red.sh path/to/log     # check an existing run's output
#
# The log must come from a --no-fail-fast run. Without that flag cargo stops at
# the first failing binary and the later reds are simply absent, which is the
# defect this script exists to prevent (.agent-config-izbto).

set -euo pipefail

cd "$(dirname "$0")/.."

LEDGER="tests/KNOWN_RED.tsv"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"   # the repo pins nightly in rust-toolchain.toml;
                                           # Homebrew's cargo ignores that pin

if [[ ! -f "$LEDGER" ]]; then
    echo "FAIL: no ledger at $LEDGER" >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

log="${1:-}"
if [[ -z "$log" ]]; then
    log="$work/suite.log"
    echo "Running the full suite (--no-fail-fast); this takes several minutes..."
    # The suite is expected to fail, so its exit code is not the signal here --
    # the failure SET is. A build error is, though, and shows up as an empty set
    # plus a compile error, which the sanity check below catches.
    "$CARGO" test --release --no-fail-fast >"$log" 2>&1 || true
elif [[ ! -f "$log" ]]; then
    echo "FAIL: no such log: $log" >&2
    exit 2
fi

if ! grep -q '^test result:' "$log"; then
    echo "FAIL: $log contains no 'test result:' line — the suite never ran." >&2
    echo "      A suite that did not run is not a green suite." >&2
    tail -20 "$log" >&2
    exit 2
fi

# Actual failures, as reported by the run.
sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$log" | LC_ALL=C sort -u >"$work/actual"

# Expected failures, from the ledger. Every row needs a bead.
: >"$work/expected"
lineno=0
bad_rows=0
while IFS= read -r line; do
    lineno=$((lineno + 1))
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    name=$(printf '%s' "$line" | cut -f1)
    bead=$(printf '%s' "$line" | cut -f2)
    reason=$(printf '%s' "$line" | cut -f3)

    if [[ -z "$name" || -z "$bead" || -z "$reason" ]]; then
        echo "FAIL: $LEDGER line $lineno is not <test>TAB<bead>TAB<reason>: $line" >&2
        bad_rows=$((bad_rows + 1))
        continue
    fi
    if [[ "$bead" != .agent-config-* ]]; then
        echo "FAIL: $LEDGER line $lineno cites '$bead', which is not a bead id." >&2
        echo "      Every known red is owed to somebody. Skipping is allowed; hiding is not." >&2
        bad_rows=$((bad_rows + 1))
        continue
    fi
    printf '%s\n' "$name" >>"$work/expected"
done <"$LEDGER"

if [[ "$bad_rows" -ne 0 ]]; then
    exit 2
fi

LC_ALL=C sort -u -o "$work/expected" "$work/expected"

new_reds=$(comm -23 "$work/actual" "$work/expected")
now_green=$(comm -13 "$work/actual" "$work/expected")

actual_count=$(wc -l <"$work/actual" | tr -d ' ')
expected_count=$(wc -l <"$work/expected" | tr -d ' ')

status=0

# One name per line, read line-wise. A doctest's name contains spaces, so word
# splitting would shred it into a dozen fake entries.
if [[ -n "$new_reds" ]]; then
    echo "FAIL: failing tests that the ledger does not list — this is a regression:" >&2
    printf '%s\n' "$new_reds" | while IFS= read -r n; do echo "  $n" >&2; done
    echo "      Fix them, or add a row to $LEDGER citing the bead that owns each." >&2
    status=1
fi

if [[ -n "$now_green" ]]; then
    echo "FAIL: $LEDGER lists tests that now PASS — the ledger is lying about the repo:" >&2
    printf '%s\n' "$now_green" | while IFS= read -r n; do echo "  $n" >&2; done
    echo "      Remove those rows and close their beads." >&2
    status=1
fi

if [[ "$status" -eq 0 ]]; then
    echo "OK: $actual_count failing test(s), exactly the $expected_count in $LEDGER."
    echo "    Every one cites a bead. Nothing new is broken."
fi

exit "$status"
