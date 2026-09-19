# Heredoc Pattern Authoring Guide

This document describes how heredoc and inline-script patterns are defined, tested,
and allowlisted. It is intended for contributors and power users.

## Overview

Heredoc detection protects against destructive commands embedded in heredocs,
here-strings, and inline interpreter flags (for example, `python -c`). The
implementation uses a tiered pipeline (see `docs/adr-001-heredoc-scanning.md`)
that only evaluates heredoc patterns when a heredoc or inline script is detected.

Stable rule IDs are required for allowlisting. The naming convention is:

```
heredoc.<language>.<operation>
```

Example:

```
heredoc.python.shutil_rmtree
```

Rule IDs are the keys used in allowlists and explain output.

Pipeline (simplified):

```
command
  -> quick reject
  -> heredoc trigger
  -> extract content + detect language
  -> ast match (language patterns)
  -> decision (allow/warn/deny)
```

## Pattern Syntax

Heredoc patterns are authored using ast-grep pattern syntax (as implemented by
`ast-grep-core`). Common conventions used in this repo:

- `$$$` matches any subtree.
- `$X` captures a single AST node.
- Patterns are language-specific and only evaluated on code parsed for that
  language.
- A pattern whose RECEIVER is `$M`, or whose call is a bare name, is gated on
  the body's own imports (`BindingGate` in `src/ast_matcher.rs`): the receiver
  must be the module itself, a local name the body binds to that module
  (`import shutil as sh`, `const f = require('fs')`, `import * as fs from
  'fs'`), or an inline `require("fs")`; a bare call must have been imported
  from that module (`from shutil import rmtree`, `const { rmSync } =
  require('fs')`). This is why `$M.remove($$$)` does not match
  `items.remove(x)`. See `.agent-config-artmu`.

Examples:

- `shutil.rmtree($$$)`
- `child_process.execSync($$$)`
- `exec.Command($$$).Run()`

Perl patterns are handled via targeted regex scanning of string literals and
shell payloads (see `src/ast_matcher.rs`).

## Where Patterns Live

The built-in pattern inventory is defined in:

- `src/ast_matcher.rs` (`default_patterns()` and Perl scanners)

Suggestions for some patterns are mapped in:

- `src/suggestions.rs`

The high-level design and rationale are documented in:

- `docs/adr-001-heredoc-scanning.md`
- `docs/pattern-library-design.md`

## Adding New Patterns

1. **Choose a stable rule ID** (`heredoc.<language>.<operation>`). Do not rename
   existing IDs; deprecate instead.
2. **Add a `CompiledPattern::new(...)` entry** in `src/ast_matcher.rs` for
   language-specific AST matches, or extend the Perl scanners for regex-based
   matching.
3. **Provide a concise reason** (short, human-readable, under 100 chars).
4. **Set severity** (Critical / High / Medium / Low). Consider false-positive
   risk and catastrophic targets.
5. **Add a suggestion** when a safer alternative exists.
6. **Add tests** (positive and negative fixtures) in `src/ast_matcher.rs`.
7. **Update docs** (this file and any relevant design notes).

## Adding a New Language

1. Add the language to `ScriptLanguage` in `src/heredoc.rs`.
2. Map string aliases in `src/config.rs` heredoc language parsing.
3. Map to an AST language in `src/ast_matcher.rs` (`script_language_to_ast_lang`).
4. Add default patterns in `src/ast_matcher.rs`.
5. Add suggestions in `src/suggestions.rs` (if applicable).
6. Add positive and negative fixtures in `src/ast_matcher.rs`.

## Pattern Inventory (Current Defaults)

This list is derived from `src/ast_matcher.rs` and reflects the current
built-in rule IDs. Use these IDs for allowlisting and tests.

### Bash

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.bash.rm_r` | `rm -r $$$` | `rm -r` recursively deletes |
| `heredoc.bash.rm_rf` | `rm -rf $$$` | `rm -rf` recursively deletes files/directories |
| `heredoc.bash.git_reset_hard` | `git reset --hard` | discards uncommitted changes |
| `heredoc.bash.git_clean_fd` | `git clean -fd` | deletes untracked files |

### Go

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.go.os_remove` | `os.Remove($$$)` | deletes files |
| `heredoc.go.os_removeall` | `os.RemoveAll($$$)` | recursively deletes directories |
| `heredoc.go.exec_command` | `exec.Command($$$)` | executes shell commands |
| `heredoc.go.exec_command_run` | `exec.Command($$$).Run()` | executes shell commands |
| `heredoc.go.exec_command_output` | `exec.Command($$$).Output()` | executes shell commands |
| `heredoc.go.exec_command_combined_output` | `exec.Command($$$).CombinedOutput()` | executes shell commands |

### JavaScript (Node)

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.javascript.fs_rm` | `$M.rm($$$)` / `rm($$$)`, bound to `fs` | deletes files/directories |
| `heredoc.javascript.fs_rmdir` | `$M.rmdir($$$)` / `rmdir($$$)`, bound to `fs` | deletes directories |
| `heredoc.javascript.fs_rmsync` | `$M.rmSync($$$)` / `rmSync($$$)`, bound to `fs` | deletes files/directories |
| `heredoc.javascript.fs_rmdirsync` | `$M.rmdirSync($$$)` / `rmdirSync($$$)`, bound to `fs` | deletes directories |
| `heredoc.javascript.fs_unlink` | `$M.unlink($$$)` / `unlink($$$)`, bound to `fs` | deletes files |
| `heredoc.javascript.fs_unlinksync` | `$M.unlinkSync($$$)` / `unlinkSync($$$)`, bound to `fs` | deletes files |
| `heredoc.javascript.fspromises_rm` | `$M.rm($$$)` / `rm($$$)`, bound to `fs/promises` | deletes files/directories |
| `heredoc.javascript.fspromises_rmdir` | `$M.rmdir($$$)` / `rmdir($$$)`, bound to `fs/promises` | deletes directories |
| `heredoc.javascript.execsync` | `child_process.execSync($$$)` | executes shell commands |
| `heredoc.javascript.require_execsync` | `require('child_process').execSync($$$)` | executes shell commands |
| `heredoc.javascript.spawnsync` | `child_process.spawnSync($$$)` | executes shell commands |

### TypeScript

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.typescript.fs_rm` | `$M.rm($$$)` / `rm($$$)`, bound to `fs` | deletes files/directories |
| `heredoc.typescript.fs_rmdir` | `$M.rmdir($$$)` / `rmdir($$$)`, bound to `fs` | deletes directories |
| `heredoc.typescript.fs_rmsync` | `$M.rmSync($$$)` / `rmSync($$$)`, bound to `fs` | deletes files/directories |
| `heredoc.typescript.fs_rmdirsync` | `$M.rmdirSync($$$)` / `rmdirSync($$$)`, bound to `fs` | deletes directories |
| `heredoc.typescript.fs_unlink` | `$M.unlink($$$)` / `unlink($$$)`, bound to `fs` | deletes files |
| `heredoc.typescript.fs_unlinksync` | `$M.unlinkSync($$$)` / `unlinkSync($$$)`, bound to `fs` | deletes files |
| `heredoc.typescript.fspromises_rm` | `$M.rm($$$)` / `rm($$$)`, bound to `fs/promises` | deletes files/directories |
| `heredoc.typescript.fspromises_rmdir` | `$M.rmdir($$$)` / `rmdir($$$)`, bound to `fs/promises` | deletes directories |
| `heredoc.typescript.execsync` | `child_process.execSync($$$)` | executes shell commands |
| `heredoc.typescript.require_execsync` | `require('child_process').execSync($$$)` | executes shell commands |
| `heredoc.typescript.spawnsync` | `child_process.spawnSync($$$)` | executes shell commands |
| `heredoc.typescript.deno_remove` | `Deno.remove($$$)` | deletes files/directories |

### Python

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.python.shutil_rmtree` | `$M.rmtree($$$)` / `rmtree($$$)`, bound to `shutil` | recursively deletes directories |
| `heredoc.python.os_remove` | `$M.remove($$$)` / `remove($$$)`, bound to `os` | deletes files |
| `heredoc.python.os_rmdir` | `$M.rmdir($$$)` / `rmdir($$$)`, bound to `os` | deletes directories |
| `heredoc.python.os_unlink` | `$M.unlink($$$)` / `unlink($$$)`, bound to `os` | deletes files |
| `heredoc.python.pathlib_unlink` | `$M.Path($$$).unlink($$$)` bound to `pathlib`, and `Path($$$).unlink($$$)` | deletes files |
| `heredoc.python.pathlib_rmdir` | `$M.Path($$$).rmdir($$$)` bound to `pathlib`, and `Path($$$).rmdir($$$)` | deletes directories |
| `heredoc.python.subprocess_run` | `subprocess.run($$$)` | executes shell commands |
| `heredoc.python.subprocess_call` | `subprocess.call($$$)` | executes shell commands |
| `heredoc.python.subprocess_popen` | `subprocess.Popen($$$)` | spawns shell processes |
| `heredoc.python.os_system` | `os.system($$$)` | executes shell commands |
| `heredoc.python.os_popen` | `os.popen($$$)` | executes shell commands |

### Ruby

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.ruby.file_delete` | `File.delete($$$)` | deletes files |
| `heredoc.ruby.file_unlink` | `File.unlink($$$)` | deletes files |
| `heredoc.ruby.dir_delete` | `Dir.delete($$$)` | deletes directories |
| `heredoc.ruby.dir_rmdir` | `Dir.rmdir($$$)` | deletes directories |
| `heredoc.ruby.fileutils_rm` | `FileUtils.rm($$$)` | deletes files |
| `heredoc.ruby.fileutils_remove` | `FileUtils.remove($$$)` | deletes files |
| `heredoc.ruby.fileutils_remove_dir` | `FileUtils.remove_dir($$$)` | deletes directories |
| `heredoc.ruby.fileutils_rm_rf` | `FileUtils.rm_rf($$$)` | recursively deletes directories |
| `heredoc.ruby.system` | `system($$$)` | executes shell commands |
| `heredoc.ruby.exec` | `exec($$$)` | replaces process with shell command |
| `heredoc.ruby.kernel_system` | `Kernel.system($$$)` | executes shell commands |
| `heredoc.ruby.kernel_exec` | `Kernel.exec($$$)` | replaces process with shell command |
| `heredoc.ruby.open3_capture3` | `Open3.capture3($$$)` | executes shell commands |
| `heredoc.ruby.open3_popen3` | `Open3.popen3($$$)` | executes shell commands |
| `heredoc.ruby.backticks` | `` `$$$` `` | executes shell commands |

### Perl

Perl scanning uses targeted regexes plus shell-payload analysis. The following
rule IDs are emitted:

- `heredoc.perl.file_path.rmtree`
- `heredoc.perl.file_path.<fn_name>` (for `File::Path::<fn_name>`)
- `heredoc.perl.unlink`
- `heredoc.perl.rmdir`
- `heredoc.perl.system.<suffix>`
- `heredoc.perl.exec.<suffix>`
- `heredoc.perl.backticks.<suffix>`
- `heredoc.perl.qx.<suffix>`

Supported `<suffix>` values (from shell-payload detection):

- `git_reset_hard`
- `git_clean_fd`
- `rm_rf`
- `rm_rf_catastrophic`

## Derived Rule IDs

Some patterns refine their rule IDs based on detected arguments:

- For JavaScript/TypeScript `fs.*` and `fsPromises.*` patterns, a literal
  catastrophic path appends `.catastrophic` to the rule ID
  (example: `heredoc.javascript.fs_rmsync.catastrophic`).
- For TypeScript `deno_remove`, a catastrophic path appends `.catastrophic`.
- For Ruby `FileUtils`/`File`/`Dir` patterns, catastrophic paths append
  `.catastrophic`.
- For Ruby `system`/`exec`/`Open3`/backticks and Perl shell calls, literal
  payloads produce rule IDs with suffixes such as `.rm_rf` and
  `.rm_rf_catastrophic`.

All derived rule IDs are valid allowlist targets.

## Limitations and False Positive Notes

- Shell execution helpers (for example, `execSync`, `system`, `os.system`) only
  escalate to high-severity decisions when a literal payload is detected. Dynamic
  payloads are warn-only to avoid false positives.
- Some file deletion APIs are refined at match time. Non-recursive or
  non-catastrophic paths may result in warn-only severity.
- Patterns are evaluated only for supported languages and only when heredoc
  triggers are detected. Non-heredoc destructive code outside the supported
  languages is out of scope.
- The import gate reads only bindings whose LOCAL name is the one the pattern
  spells. A renamed destructure or from-import (`from shutil import rmtree as
  rt`, `const { rmSync: r } = require('fs')`), a receiver that is itself an
  expression (`fs.promises.rm(..)`), a computed or optional member
  (`fs?.rmSync`, `fs["rmSync"]`) and `import fs = require("fs")` are NOT read.
  Catching them needs a pattern compiled per body, which the hook budget does
  not allow (`.agent-config-artmu`).
- An inline `require("fs").rmSync(..)` resolves as a receiver but still does
  not deny: the payload refinement reads the first string literal in the match
  as the target path, and for that spelling it is `"fs"`
  (`.agent-config-rmxds`).
- The fallback regex sweep in `src/evaluator.rs` reads only text the extractor
  says went unread, has no AST and therefore no imports to resolve an alias
  against. It matches the distinctive bare call shapes (`rmtree(`, `rmSync(`,
  `rmdirSync(`, `execSync(`, `spawnSync(`) in addition to the receiver
  spellings; `remove(`, `rmdir(` and `unlink(` are too common to sweep on and
  stay receiver-bound there.

## Testing Requirements

Add tests under `src/ast_matcher.rs`:

- At least one positive and one negative fixture per new rule.
- Ensure comments/strings do not match (false positive guard).
- Include catastrophic-path fixtures when applicable.

Run:

```
cargo test ast_matcher
```

