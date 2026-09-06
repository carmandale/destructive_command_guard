//! The hook and `dcg history` must resolve the history database to one path.
//!
//! Five call sites asked "where is the history database" — `main.rs` for the hook that
//! writes, and four `cli.rs` sites for the subcommands that read — and they answered
//! differently three ways. Each of these was measured against the pre-fix binary under
//! `.agent-config-x2f60`; each is one test below.
//!
//! ```text
//! DCG_HISTORY_DB='~/hist/history.db'   ->  <cwd>/~/hist/history.db   a real dir named "~"
//! XDG_CONFIG_HOME set, nothing else    ->  config.toml and the pending store read from
//!                                          $XDG_CONFIG_HOME/dcg/, history database written
//!                                          to $HOME/Library/Application Support/dcg/
//! env AND config.toml both set a path  ->  hook wrote 1 row to the env path;
//!                                          `dcg history stats` reported "Total commands: 0"
//!                                          off the config path
//! ```
//!
//! The third is the one that matters most and the one a unit test on a resolver would
//! never have caught: `dcg history stats` exists to show you what dcg recorded, and it
//! confidently showed you an empty database while the records sat in another file. So
//! these tests spawn the real binary at both ends — write with the hook, read with the
//! subcommand — rather than asserting that a resolver returns a `PathBuf`.

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// A command the shipped `core.git` pack denies, so the hook records one row.
const DENIED: &str = "git reset --hard";

/// History collection is opt-in (`HistoryConfig::default().enabled == false`), so every
/// test here has to turn it on before the hook will write anything at all.
fn enable_history(sandbox: &spawn::Sandbox, extra: &str) {
    let dir = sandbox.dcg_config_dir();
    std::fs::create_dir_all(&dir).expect("create config dir");
    std::fs::write(
        dir.join("config.toml"),
        format!("[history]\nenabled = true\n{extra}"),
    )
    .expect("write config.toml");
}

/// Run the hook once against `sandbox`, with any extra env the caller needs.
fn run_hook(sandbox: &spawn::Sandbox, env: &[(&str, &str)]) {
    let input = payload::pre_tool_use(sandbox.root(), DENIED);

    let mut cmd = spawn::dcg_in(sandbox);
    cmd.env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent");
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = cmd
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("deny"),
        "control: `{DENIED}` must be denied, or no history row is written and every \
         assertion below passes over an empty filesystem; got:\n{stdout}"
    );
}

/// `dcg history stats` against `sandbox`, with the same extra env the hook had.
fn history_stats(sandbox: &spawn::Sandbox, env: &[(&str, &str)]) -> String {
    let mut cmd = spawn::dcg_in(sandbox);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd
        .arg("history")
        .arg("stats")
        .output()
        .expect("failed to run dcg history stats");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Wait briefly for `path` to appear — the history writer batches on its own thread.
///
/// Returns whether it showed up, so a caller can assert with a real message instead of
/// hanging. A bare sleep would either be slower than this or racy.
fn appeared(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A tilde in `DCG_HISTORY_DB` is expanded, not written to disk as a directory name.
///
/// `DCG_PENDING_EXCEPTIONS_PATH` and `DCG_ALLOW_ONCE_PATH` already expanded it; this
/// one env override was the odd one out, and `PathBuf::from("~/hist/history.db")` is a
/// *relative* path whose first component is a literal `~`.
#[test]
fn tilde_in_the_history_db_env_override_is_expanded() {
    let sandbox = spawn::sandbox();
    enable_history(&sandbox, "");

    run_hook(&sandbox, &[("DCG_HISTORY_DB", "~/hist/history.db")]);

    let expected = sandbox.home.join("hist").join("history.db");
    assert!(
        appeared(&expected),
        "DCG_HISTORY_DB='~/hist/history.db' must expand to {}; it did not appear. \
         Under the sandbox: {:?}",
        expected.display(),
        listing(sandbox.root())
    );

    let literal_tilde = sandbox.root().join("~");
    assert!(
        !literal_tilde.exists(),
        "dcg created a directory literally named `~` at {}",
        literal_tilde.display()
    );
}

/// The history database lands under `$XDG_CONFIG_HOME/dcg`, where the rest of dcg's
/// state already lives.
///
/// It used to ignore the variable entirely, so a hook run read its `config.toml` from
/// `$XDG_CONFIG_HOME/dcg/` and wrote the pending store there while putting the database
/// somewhere else — and a harness that set the variable to isolate dcg still grew the
/// live database.
#[test]
fn history_db_follows_xdg_config_home() {
    let sandbox = spawn::sandbox();
    enable_history(&sandbox, "");

    run_hook(&sandbox, &[]);

    let expected = sandbox.dcg_config_dir().join("history.db");
    assert!(
        appeared(&expected),
        "with XDG_CONFIG_HOME set, the history database belongs beside the config and \
         the pending store at {}. Under the sandbox: {:?}",
        expected.display(),
        listing(sandbox.root())
    );

    // The point is that dcg's state is in ONE place, so name the neighbour too.
    let pending = sandbox.dcg_config_dir().join("pending_exceptions.jsonl");
    assert!(
        pending.exists(),
        "the pending store should already be at {} — if it is not, this test is no \
         longer measuring the two ends agreeing",
        pending.display()
    );
}

/// The hook and `dcg history stats` pick the same database when the env override and
/// `config.history.database_path` disagree.
///
/// This is the regression with teeth. `main.rs` preferred `DCG_HISTORY_DB`; the readers
/// passed the configured path straight to `HistoryDb::open` and so preferred the config.
/// With both set the hook wrote its row to one file and `dcg history stats` reported
/// `Total commands: 0` off the other.
#[test]
fn writer_and_reader_agree_when_env_and_config_disagree() {
    let sandbox = spawn::sandbox();
    let from_config = sandbox.root().join("from_config.db");
    let from_env = sandbox.root().join("from_env.db");
    enable_history(
        &sandbox,
        &format!("database_path = \"{}\"\n", from_config.display()),
    );

    let env = [("DCG_HISTORY_DB", from_env.to_string_lossy().to_string())];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    run_hook(&sandbox, &env);
    assert!(
        appeared(&from_env),
        "the env override must still outrank config.history.database_path for the \
         writer; {} never appeared. Under the sandbox: {:?}",
        from_env.display(),
        listing(sandbox.root())
    );

    let stats = history_stats(&sandbox, &env);
    assert!(
        stats.contains("Total commands: 1"),
        "`dcg history stats` must read the database the hook just wrote. It reported:\n\
         {stats}\n\
         env path {} exists={}, config path {} exists={}",
        from_env.display(),
        from_env.exists(),
        from_config.display(),
        from_config.exists(),
    );

    // Control: the reader's number has to be able to be wrong. The configured database
    // is the file the reader used to open, and nothing ever wrote it.
    assert!(
        !from_config.exists(),
        "the configured path {} was written after all — then 'Total commands: 1' does \
         not distinguish the two databases and this test proves nothing",
        from_config.display()
    );
}

/// Every path under `root`, so a failing assertion names what dcg actually wrote.
fn listing(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
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
