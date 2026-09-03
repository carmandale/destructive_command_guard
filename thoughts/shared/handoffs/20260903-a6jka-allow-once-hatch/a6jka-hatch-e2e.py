#!/usr/bin/env python3
"""End-to-end: does `dcg allow-once <code>` actually open the hatch?

The real consumer flow, no test helpers:
  1. hook denies a command      -> capture the deny
  2. `dcg allow-once <code> -y` -> writes the entry itself
  3. hook runs the same command -> must allow

Also reports what a Claude Code agent can actually SEE of step 1, which is
`hookSpecificOutput.permissionDecisionReason` and nothing else: sibling JSON
fields are not shown to the model and PreToolUse stderr is not either.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

BIN = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "target", "debug", "dcg")
)
COMMAND = "git reset --hard"

work = tempfile.mkdtemp()
home = tempfile.mkdtemp()
xdg = tempfile.mkdtemp()
os.makedirs(os.path.join(work, ".git"), exist_ok=True)

ENV = {
    "HOME": home,
    "XDG_CONFIG_HOME": xdg,
    "DCG_ALLOWLIST_SYSTEM_PATH": "",
    "DCG_PACKS": "core.git,core.filesystem",
    "DCG_NO_SELF_HEAL": "1",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}


def hook():
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": COMMAND}})
    return subprocess.run(
        [BIN], input=payload, env=ENV, cwd=work, capture_output=True, text=True
    )


def cli(*args):
    return subprocess.run(
        [BIN, *args], env=ENV, cwd=work, capture_output=True, text=True
    )


print(f"binary : {BIN}")
print(f"cwd    : {work}  (realpath {os.path.realpath(work)})")
print()

print("STEP 1 — hook denies")
r1 = hook()
if not r1.stdout.strip():
    sys.exit("FAIL: expected a deny, got an allow (empty stdout)")
deny = json.loads(r1.stdout)["hookSpecificOutput"]
print(f"  decision      : {deny['permissionDecision']}")
code = deny.get("allowOnceCode")
print(f"  allowOnceCode : {code!r}  (sibling JSON field)")

reason = deny["permissionDecisionReason"]
print()
print("  What the agent actually sees (permissionDecisionReason):")
for line in reason.splitlines():
    print(f"    | {line}")
print()
found = re.search(r"allow-once\s+(\S+)", reason)
print(f"  reason text mentions an allow-once code : {bool(found)}")
if not code:
    sys.exit("FAIL: no allowOnceCode minted at all")

print()
print(f"STEP 2 — dcg allow-once {code} --yes")
r2 = cli("allow-once", code, "--yes")
print(f"  exit={r2.returncode}")
for line in (r2.stdout + r2.stderr).strip().splitlines():
    print(f"    | {line}")
if r2.returncode != 0:
    sys.exit("FAIL: allow-once did not write an entry")

print()
print("STEP 3 — hook re-runs the same command")
r3 = hook()
if r3.stdout.strip():
    verdict = json.loads(r3.stdout)["hookSpecificOutput"]["permissionDecision"]
    print(f"  decision : {verdict.upper()}")
    sys.exit("FAIL: the hatch did not open -- still denied after allow-once")
print("  decision : ALLOW (empty stdout)")
print()
print("HATCH OPENS: yes")
print(f"CODE REACHES THE AGENT: {'yes' if found else 'no'}")
