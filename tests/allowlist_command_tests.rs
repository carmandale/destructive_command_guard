
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

/// The user allowlist is read from the directory it is written to.
///
/// `dcg allowlist add --user` resolves through `config::user_config_dir`, which
/// prefers `$XDG_CONFIG_HOME/dcg`. `load_default_allowlists` used to resolve the
/// User layer through `dirs::home_dir()` alone, so with `XDG_CONFIG_HOME` set a
/// user's own entry was written to one file and read from another and silently
/// never took effect (`.agent-config-0kt9v`). No test pinned the precedence in
/// either direction, before or after; this is that pin.
#[test]
fn test_user_allowlist_precedence_follows_xdg_config_home() {
    let cmd = "git reset --hard";
    let allowlist = format!(
        r#"
[[allow]]
exact_command = "{cmd}"
reason = "allowed explicitly"
"#
    );

    let sandbox = spawn::sandbox();

    // The entry lives ONLY under $XDG_CONFIG_HOME, never under $HOME/.config.
    let xdg_dir = sandbox.dcg_config_dir();
    std::fs::create_dir_all(&xdg_dir).unwrap();
    std::fs::write(xdg_dir.join("allowlist.toml"), &allowlist).unwrap();

    let home_dir = sandbox.home.join(".config").join("dcg");
    std::fs::create_dir_all(&home_dir).unwrap();
    assert!(
        !home_dir.join("allowlist.toml").exists(),
        "the $HOME/.config candidate must be empty, or this proves nothing"
    );

    let output = run_hook_in_sandbox(&sandbox, cmd);
    assert!(
        output.is_empty(),
        "the allowlist under $XDG_CONFIG_HOME must be the one that is read; \
         got a denial:\n{output}"
    );

    // Control: the same directory layout without the entry must still deny, so
    // the assertion above cannot be satisfied by dcg simply allowing this
    // command.
    let bare = spawn::sandbox();
    std::fs::create_dir_all(bare.dcg_config_dir()).unwrap();
    let denied = run_hook_in_sandbox(&bare, cmd);
    assert!(
        denied.contains("deny"),
        "control: with no allowlist anywhere this command must be denied, \
         got:\n{denied}"
    );
}

fn run_hook_in_sandbox(sandbox: &spawn::Sandbox, command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut child = spawn::dcg_in(sandbox)
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
