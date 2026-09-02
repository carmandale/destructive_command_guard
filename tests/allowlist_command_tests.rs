
#[path = "common/spawn.rs"]
mod spawn;

fn run_hook_with_allowlist(command: &str, allowlist_content: &str) -> String {
    let (mut dcg_cmd, sandbox) = spawn::dcg();
    let user_config_dir = sandbox.dcg_config_dir();
    std::fs::create_dir_all(&user_config_dir).unwrap();
    std::fs::write(user_config_dir.join("allowlist.toml"), allowlist_content).unwrap();

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut child = dcg_cmd
        // Ensure system allowlist doesn't interfere
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
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
fn test_exact_command_allowlist_works() {
    let cmd = "git reset --hard";
    let allowlist = format!(
        r#"
[[allow]]
exact_command = "{cmd}"
reason = "allowed explicitly"
"#
    );

    let output = run_hook_with_allowlist(cmd, &allowlist);

    assert!(
        !output.contains("deny"),
        "ExactCommand allowlist should allow the command, but got denial: {output}",
    );
    assert!(
        output.is_empty(),
        "Expected empty output for allowed command"
    );
}
