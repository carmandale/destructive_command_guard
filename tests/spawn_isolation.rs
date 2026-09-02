//! Every spawn of the dcg binary under `tests/` comes from
//! `tests/common/spawn.rs`.
//!
//! Why this exists, measured rather than imagined (2026-09-02, one session):
//! a harness that named the binary itself and spawned it without a cleared
//! environment measured the developer's own `~/.config/dcg/config.toml`.
//! That made fourteen tests fail for reasons unrelated to dcg, made
//! `git_bypass.rs` report `git -C` and `--work-tree` as live bypasses that
//! dcg denies, and let an 18,723-row replay report "identical" for a binary
//! that was answering Claude Code in the wrong protocol. A comment saying
//! "use the helper" would not have caught any of those. This test does.
//!
//! What it checks: a line scan over every `.rs` under `tests/` for the
//! spellings that name or resolve the binary. The helper's own path function
//! is private, so the type system already refuses that route outside the
//! helper; this scan refuses the others.
//!
//! What it cannot see: a path assembled from pieces, a spelling that is not
//! in the list, and the shell scripts under `tests/e2e/` and `tests/scripts/`,
//! which resolve `target/release/dcg` themselves and run outside cargo. It is
//! a syntactic proxy and is meant to stay one.

use std::path::Path;

/// The one file allowed to name the binary.
const HELPER: &str = "common/spawn.rs";

/// Spellings that name or resolve the dcg binary, and what each one reaches.
const FORBIDDEN: &[(&str, &str)] = &[
    ("CARGO_BIN_EXE_dcg", "cargo's path to the built binary"),
    ("cargo_bin", "assert_cmd's resolver for the built binary"),
    ("current_exe(", "a target directory path built by hand"),
    ("target/release/dcg", "a build artifact by path"),
    ("target/debug/dcg", "a build artifact by path"),
    (
        "which(\"dcg\")",
        "whatever dcg is on PATH, i.e. the installed one",
    ),
    (
        "Command::new(\"dcg\")",
        "whatever dcg is on PATH, i.e. the installed one",
    ),
    (
        "dcg_binary(",
        "the helper's private path function, or a local copy of it",
    ),
];

#[test]
fn every_dcg_spawn_goes_through_the_helper() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let this_file = Path::new(file!())
        .file_name()
        .expect("this file has a name");

    // Positive control: the helper must contain a spelling on the list, or
    // the scan could pass over a tree where nothing spawns dcg the way it
    // actually does.
    let helper = std::fs::read_to_string(tests_dir.join(HELPER))
        .unwrap_or_else(|e| panic!("read {HELPER}: {e}"));
    assert!(
        FORBIDDEN.iter().any(|(needle, _)| helper.contains(needle)),
        "{HELPER} no longer contains any spelling this scan looks for; \
         the scan can no longer tell a spawn from anything else"
    );

    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(&tests_dir) {
        let entry = entry.expect("walk tests/");
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let rel = path.strip_prefix(&tests_dir).expect("path is under tests/");
        if rel == Path::new(HELPER) || rel == Path::new(this_file) {
            continue;
        }
        let source =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", rel.display()));
        for (index, line) in source.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for (needle, reaches) in FORBIDDEN {
                if code.contains(needle) {
                    offenders.push(format!(
                        "tests/{}:{}: `{needle}` reaches {reaches}\n        {}",
                        rel.display(),
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} spawn site(s) name the dcg binary outside tests/{HELPER}. \
         Get the Command from spawn::dcg(), spawn::dcg_in(&sandbox) or \
         spawn::dcg_with_packs(..) instead, so the child cannot read the \
         developer's own dcg config:\n\n{}\n",
        offenders.len(),
        offenders.join("\n")
    );
}
