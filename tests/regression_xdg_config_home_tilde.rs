//! `XDG_CONFIG_HOME='~/cfg'` must not put dcg's state in a directory named `~`.
//!
//! Two resolvers answer "where is the dcg user config dir". `config::user_config_dir`
//! routes its `XDG_CONFIG_HOME` through `config::resolve_config_path_value`, which
//! expands a leading `~`. `pending_exceptions::config_dir_override` — the one the
//! pending-exception and allow-once stores use — was `PathBuf::from(value).join("dcg")`,
//! so the two disagreed for every `XDG_CONFIG_HOME` that is not a plain absolute path.
//!
//! Measured against the pre-fix binary with `XDG_CONFIG_HOME='~/cfg'`
//! (`.agent-config-piua5`):
//!
//! ```text
//! allowlist    <sandbox>/home/cfg/dcg/allowlist.toml             expanded
//! allow-once   <sandbox>/work/~/cfg/dcg/pending_exceptions.jsonl a real dir named "~"
//! ```
//!
//! A shell hands over exactly this value whenever the variable was quoted —
//! `export XDG_CONFIG_HOME='~/cfg'` — and the consequence is not cosmetic: dcg
//! writes the short code for a denial into one file and looks for it in another,
//! so `dcg allow-once <code>` cannot find the code dcg just printed.
//!
//! This file spawns the real binary rather than calling the resolver, because the
//! resolver being right is not the claim — the claim is that the state dcg writes
//! and the state dcg reads land in the same place.

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

use std::process::Stdio;

/// A command the shipped `core.git` pack denies, so the hook records a pending
/// exception and the store path becomes observable.
const DENIED: &str = "git reset --hard";

/// Run the hook once with `XDG_CONFIG_HOME` set to `xdg_value`, returning stdout.
fn run_denied_with_xdg(sandbox: &spawn::Sandbox, xdg_value: &str) -> String {
    let input = payload::pre_tool_use(sandbox.root(), DENIED);

    let mut child = spawn::dcg_in(sandbox)
        .env("XDG_CONFIG_HOME", xdg_value)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn tilde_xdg_config_home_writes_the_pending_store_under_home() {
    let sandbox = spawn::sandbox();

    let output = run_denied_with_xdg(&sandbox, "~/cfg");

    // The denial has to have happened, or the store was never written and every
    // assertion below is satisfied by dcg having done nothing at all.
    assert!(
        output.contains("deny"),
        "control: `{DENIED}` must be denied, or this test proves nothing; got:\n{output}"
    );

    let expected = sandbox
        .home
        .join("cfg")
        .join("dcg")
        .join("pending_exceptions.jsonl");
    assert!(
        expected.exists(),
        "XDG_CONFIG_HOME='~/cfg' must resolve through the same tilde expansion as \
         config::user_config_dir, putting the pending store at {}; it is not there. \
         Present under the sandbox: {:?}",
        expected.display(),
        listing(sandbox.root())
    );

    // The failure this pins: a relative path whose first component is a literal
    // `~`, created under whatever directory dcg happened to be run from.
    let literal_tilde = sandbox.root().join("~");
    assert!(
        !literal_tilde.exists(),
        "dcg created a directory literally named `~` at {} — an unexpanded \
         XDG_CONFIG_HOME reached the filesystem",
        literal_tilde.display()
    );
}

/// The store still lands in `$XDG_CONFIG_HOME/dcg` when the value needs no
/// expansion, so the fix cannot have been "ignore XDG_CONFIG_HOME".
#[test]
fn absolute_xdg_config_home_still_selects_the_store() {
    let sandbox = spawn::sandbox();

    let output = run_denied_with_xdg(&sandbox, &sandbox.xdg_config.to_string_lossy());

    assert!(
        output.contains("deny"),
        "control: `{DENIED}` must be denied; got:\n{output}"
    );

    let expected = sandbox.dcg_config_dir().join("pending_exceptions.jsonl");
    assert!(
        expected.exists(),
        "an absolute XDG_CONFIG_HOME must still select the pending store at {}; \
         present under the sandbox: {:?}",
        expected.display(),
        listing(sandbox.root())
    );
}

/// Every path under `root`, so a failing assertion names what dcg actually wrote
/// instead of only what it did not.
fn listing(root: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            found.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned(),
            );
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    found.sort();
    found
}
