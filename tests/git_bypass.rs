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
