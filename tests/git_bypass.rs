use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path.push("dcg");
    path
}

fn run_hook(command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    // Cleared for the same reason as `cli_e2e.rs`: without it these tests read
    // the developer's real dcg config, and a local `"core.git:reset-hard" =
    // "warn"` downgrade turns a genuine bypass finding into an unrelated red.
    let temp = tempfile::tempdir().expect("temp dir");
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).expect("HOME dir");
    std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
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
