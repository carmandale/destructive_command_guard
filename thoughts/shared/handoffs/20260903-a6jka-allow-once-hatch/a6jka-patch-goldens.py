#!/usr/bin/env python3
"""Insert the allow-once hatch line into the golden deny reasons, in place.

Regenerating with UPDATE_GOLDEN also rewrites every key into a different order
(the goldens were written by a build without serde_json/preserve_order), which
buries a one-line change in a 16-line diff. This edits only the string that
actually changed and leaves byte order alone.

Asserts exactly one substitution per file, and refuses a file that already
carries the line.
"""

import sys

ANCHOR = "\\n\\nIf this operation is truly needed,"
INSERT = "\\n\\nIf this is a false positive: dcg allow-once <DYNAMIC>" + ANCHOR

FILES = [
    "tests/golden/hook/deny_git_reset.json",
    "tests/golden/hook/deny_filesystem.json",
    "tests/golden/hook/deny_git.json",
]

failed = False
for path in FILES:
    with open(path) as fh:
        text = fh.read()

    if "allow-once <DYNAMIC>\\n\\nIf this operation" in text:
        print(f"SKIP  {path}: already patched")
        continue

    count = text.count(ANCHOR)
    if count != 1:
        print(f"FAIL  {path}: anchor appears {count} times, expected exactly 1")
        failed = True
        continue

    with open(path, "w") as fh:
        fh.write(text.replace(ANCHOR, INSERT))
    print(f"OK    {path}: 1 substitution")

sys.exit(1 if failed else 0)
