//! One isolated way to spawn dcg from an integration test.
//!
//! Every harness in `tests/` runs the real binary. Spawned without a cleared
//! environment, the child inherits the developer's own environment and loads
//! their real `~/.config/dcg/config.toml`, so a local policy line — not dcg —
//! decides the verdict. On a machine whose config carries
//! `"core.git:reset-hard" = "warn"`, fourteen tests failed that way, and
//! `git_bypass.rs` reported `git -C` and `--work-tree` as live security
//! bypasses when dcg denies both.
//!
//! The same blind spot hid a real bug for far longer. dcg answered Claude Code
//! in Gemini's protocol — a correct verdict Claude Code cannot read, which on
//! the wire is an allow — and the whole suite stayed green, because every
//! harness sent a minimal payload that took a different branch. A test that
//! cannot see the machine it is protecting is worth less than no test, because
//! it reports confidence.
//!
//! So: get the `Command` from here, or the guard test in
//! `tests/spawn_isolation.rs` fails.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Temp roots backing an isolated dcg invocation.
///
/// Hold it for as long as the child runs — dropping it removes the directories
/// the child was pointed at.
pub struct Sandbox {
    temp: TempDir,
    pub home: PathBuf,
    pub xdg_config: PathBuf,
}

impl Sandbox {
    /// The working directory the child runs in.
    pub fn root(&self) -> &Path {
        self.temp.path()
    }

    /// `$XDG_CONFIG_HOME/dcg`, where a test can drop a config or a pack.
    pub fn dcg_config_dir(&self) -> PathBuf {
        self.xdg_config.join("dcg")
    }
}

/// Path to the dcg binary built alongside this test.
///
/// Private on purpose. A harness that can name the binary can spawn it
/// un-isolated, so the only thing that leaves this file is a `Command` that
/// already carries the isolation. `tests/spawn_isolation.rs` refuses the
/// other spellings of the path.
fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// The hook evaluation budget every harness runs under, in milliseconds.
///
/// dcg's production default is 200ms (`perf::HOOK_EVALUATION_BUDGET_MS`), and
/// it is a WALL CLOCK: past it the hook fails closed under
/// `core.limits:evaluation-timeout` instead of under the rule that matched. A
/// test asserting a `ruleId` is then decided by how busy the machine is.
///
/// Measured 2026-09-18 (.agent-config-0o2q1): `cli_e2e`
/// `hook_mode_safe_exemption_does_not_hide_a_later_destructive_command` went
/// red at load 273/801/640 on the ruleId assert alone -- the deny above it
/// passed -- and again in a second, independent session at load ~550-717
/// ("spent 222ms" of 200ms). Alone it passed 5/5. Nothing was slow: the same
/// command through the same binary denies on `remote.rsync:rsync-delete` at
/// 10000ms and on the timeout rule at 1ms. It is a ~50x margin that only a
/// loaded box closes, and the sibling `.agent-config-uq1ui` is the same class.
///
/// Ten minutes is far past what any command in this suite needs, so a run that
/// still trips it has found something real. A test that means to measure the
/// budget removes this (see `run_dcg_hook_under_config_budget` in
/// `tests/cli_e2e.rs`) and says what it wants instead; the production default
/// is unchanged and pinned by `fail_closed_tests`.
pub const GENEROUS_HOOK_TIMEOUT_MS: &str = "600000";

/// An isolated `Command` for the dcg binary, plus the sandbox backing it.
///
/// The environment is cleared, so nothing the developer happens to export can
/// change a verdict. `HOME` and `XDG_CONFIG_HOME` point at fresh temp dirs, the
/// system allowlist is disabled, a fixed pack set is selected, and the hook
/// budget is [`GENEROUS_HOOK_TIMEOUT_MS`], so the answer depends on dcg and the
/// test alone.
pub fn dcg() -> (Command, Sandbox) {
    let sandbox = sandbox();
    let cmd = dcg_in(&sandbox);
    (cmd, sandbox)
}

/// The same isolated `Command`, against a sandbox the caller already holds.
///
/// For a harness that writes a config, a pack, or a `.git` into the sandbox
/// before spawning, or spawns more than once against the same state. Layer
/// what the test needs on top with `.env(..)`; a test that measures dcg's own
/// default pack selection says so with `.env_remove("DCG_PACKS")`, and one
/// that measures the hook budget with `.env_remove("DCG_HOOK_TIMEOUT_MS")`.
pub fn dcg_in(sandbox: &Sandbox) -> Command {
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &sandbox.home)
        .env("XDG_CONFIG_HOME", &sandbox.xdg_config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .env("DCG_HOOK_TIMEOUT_MS", GENEROUS_HOOK_TIMEOUT_MS)
        .current_dir(sandbox.root());
    cmd
}

/// Like [`dcg`], but with the caller's pack selection instead of the default.
pub fn dcg_with_packs(packs: &str) -> (Command, Sandbox) {
    let (mut cmd, sandbox) = dcg();
    cmd.env("DCG_PACKS", packs);
    (cmd, sandbox)
}

/// Fresh temp roots without a `Command`, for tests that build their own.
pub fn sandbox() -> Sandbox {
    let temp = tempfile::tempdir().expect("create sandbox temp dir");
    let home = temp.path().join("home");
    let xdg_config = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home).expect("create sandbox HOME");
    std::fs::create_dir_all(&xdg_config).expect("create sandbox XDG_CONFIG_HOME");
    Sandbox {
        temp,
        home,
        xdg_config,
    }
}
