#!/usr/bin/env python3
"""Probe: does the hook honour a DCG_ALLOW_ONCE_PATH entry, and does the
scope_path spelling decide it?

Reproduces tests/cli_e2e.rs hook_mode_allow_once_allows_pack_denied_command
outside cargo, and varies exactly one thing: whether scope_path is written as
the tempdir's /var path or its realpath'd /private/var path.

Prints the raw verdict for each arm. No conclusion is printed; read the table.
"""

import json
import os
import subprocess
import sys
import tempfile

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "target", "debug", "dcg")
BIN = os.path.normpath(BIN)
COMMAND = "git reset --hard"


def entry(scope_path, scope_kind="cwd", force=False):
    return {
        "schema_version": 1,
        "source_short_code": "12345",
        "source_full_hash": "0" * 64,
        "created_at": "2099-01-01T00:00:00Z",
        "expires_at": "2099-01-02T00:00:00Z",
        "scope_kind": scope_kind,
        "scope_path": scope_path,
        "command_raw": COMMAND,
        "command_redacted": COMMAND,
        "reason": "test pending",
        "single_use": False,
        "consumed_at": None,
        "force_allow_config": force,
    }


def run(label, scope_path_fn, scope_kind="cwd", write_entry=True):
    work = tempfile.mkdtemp()
    home = tempfile.mkdtemp()
    xdg = tempfile.mkdtemp()
    os.makedirs(os.path.join(work, ".git"), exist_ok=True)

    allow_once = os.path.join(work, "allow_once.jsonl")
    if write_entry:
        with open(allow_once, "w") as fh:
            fh.write(json.dumps(entry(scope_path_fn(work), scope_kind)) + "\n")

    env = {
        "HOME": home,
        "XDG_CONFIG_HOME": xdg,
        "DCG_ALLOWLIST_SYSTEM_PATH": "",
        "DCG_PACKS": "core.git,core.filesystem",
        "DCG_ALLOW_ONCE_PATH": allow_once,
        "DCG_NO_SELF_HEAL": "1",
        "PATH": "/usr/bin:/bin",
    }
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": COMMAND}})
    proc = subprocess.run(
        [BIN], input=payload, env=env, cwd=work,
        capture_output=True, text=True,
    )
    out = proc.stdout.strip()
    if not out:
        verdict = "ALLOW (empty stdout)"
    else:
        try:
            verdict = json.loads(out)["hookSpecificOutput"]["permissionDecision"].upper()
        except Exception:
            verdict = "UNPARSEABLE: " + out[:120]
    print(f"  {label:<46} exit={proc.returncode}  {verdict}")
    if proc.stderr.strip():
        print(f"     stderr: {proc.stderr.strip()[:200]}")


print(f"binary: {BIN}")
print(f"TMPDIR: {os.environ.get('TMPDIR')}")
d = tempfile.mkdtemp()
print(f"mkdtemp {d} -> realpath {os.path.realpath(d)}")
print()
print("Hook mode, DCG_ALLOW_ONCE_PATH set, command = 'git reset --hard':")
run("no entry at all (control)", lambda w: w, write_entry=False)
run("scope cwd,  scope_path = tempdir as given", lambda w: w)
run("scope cwd,  scope_path = os.path.realpath", os.path.realpath)
run("scope project, scope_path = '/'", lambda w: "/", scope_kind="project")
