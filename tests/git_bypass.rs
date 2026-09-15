#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

fn run_hook(command: &str) -> String {
    // Cleared for the same reason as `cli_e2e.rs`: without it these tests read
    // the developer's real dcg config, and a local `"core.git:reset-hard" =
    // "warn"` downgrade turns a genuine bypass finding into an unrelated red.
    let (mut cmd, sandbox) = spawn::dcg();
    let input = payload::pre_tool_use(sandbox.root(), command);
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
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
fn git_global_flag_bypass() {
    // This command is destructive but currently bypassed because regex expects "git reset" directly
    let cmd = "git -C /tmp reset --hard";
    let output = run_hook(cmd);

    assert!(
        !output.trim().is_empty(),
        "Bypass confirmed: '{cmd}' was allowed!"
    );

    assert!(output.contains("deny"), "Should be denied");
}

#[test]
fn git_work_tree_bypass() {
    let cmd = "git --work-tree=/tmp clean -fd";
    let output = run_hook(cmd);

    assert!(
        !output.trim().is_empty(),
        "Bypass confirmed: '{cmd}' was allowed!"
    );

    assert!(output.contains("deny"), "Should be denied");
}

/// A safe git command after a separator must not exempt a destructive git
/// command in front of it. The core.git safe patterns opened with a skipper
/// that crossed `&&`, `;`, `||`, `|` and newlines, so the leftmost match of
/// e.g. `checkout -b` started at the FIRST `git` on the line: the span covered
/// the force push, and the start-inside-span rule exempted it
/// (.agent-config-t17jx, the safe-side half of .agent-config-it2wk).
#[test]
fn safe_git_command_after_separator_does_not_exempt_the_one_in_front() {
    let mut allowed = Vec::new();
    for cmd in [
        "git push --force origin main && git checkout -b feat",
        "git stash clear && git checkout -b feat",
        "git push --force origin main ; git checkout -b feat",
        "git push --force origin main || git checkout --orphan feat",
        "git push --force origin main\ngit checkout -b feat",
        "git reset --hard && git clean -n",
    ] {
        let output = run_hook(cmd);
        if !output.contains("deny") {
            allowed.push(format!("{cmd:?} -> {}", output.trim()));
        }
    }
    assert!(
        allowed.is_empty(),
        "a safe git command exempted a destructive one: {allowed:#?}"
    );
}

/// The narrowing must not cost the safe patterns their own commands.
#[test]
fn safe_git_commands_are_still_allowed_on_their_own() {
    let mut denied = Vec::new();
    for cmd in [
        "git checkout -b new-feature",
        "git -C /tmp/repo checkout -b new-feature",
        "git --no-pager checkout --orphan gh-pages",
        "git restore --staged f.txt",
        "git restore -S f.txt",
        "git clean -n",
        "git clean -nfd",
        "git clean --dry-run",
        "git status && git checkout -b new-feature",
    ] {
        let output = run_hook(cmd);
        if output.contains("deny") {
            denied.push(format!("{cmd:?} -> {}", output.trim()));
        }
    }
    assert!(denied.is_empty(), "safe git commands denied: {denied:#?}");
}
