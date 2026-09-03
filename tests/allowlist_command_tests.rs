
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

/// An allowlist in an older location is still read when XDG_CONFIG_HOME is set.
///
/// `dcg allowlist add --user` writes to one directory, but a file may already
/// sit in another — a config predating `XDG_CONFIG_HOME`, or the macOS
/// platform-native path. The reader tries every candidate, so setting
/// `XDG_CONFIG_HOME` does not silently orphan an allowlist that is really
/// there. The first fix for `.agent-config-0kt9v` read one directory only and
/// would have dropped this file (cold review finding 3).
#[test]
fn test_user_allowlist_in_an_older_location_is_still_read() {
    let cmd = "git reset --hard";
    let allowlist = format!(
        r#"
[[allow]]
exact_command = "{cmd}"
reason = "allowed explicitly"
"#
    );

    let sandbox = spawn::sandbox();

    // XDG_CONFIG_HOME is set and its dcg dir exists but holds NO allowlist.
    std::fs::create_dir_all(sandbox.dcg_config_dir()).unwrap();

    // The entry lives only in the older $HOME/.config/dcg location.
    let home_dir = sandbox.home.join(".config").join("dcg");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::write(home_dir.join("allowlist.toml"), &allowlist).unwrap();

    let output = run_hook_in_sandbox(&sandbox, cmd);
    assert!(
        output.is_empty(),
        "an allowlist at $HOME/.config/dcg must still be read when \
         XDG_CONFIG_HOME is set and holds no allowlist of its own; got:\n{output}"
    );
}

/// When both locations hold an allowlist, XDG_CONFIG_HOME wins.
///
/// Falling through candidates must not turn into "whichever file we happen to
/// find first is as good as any" — the preference order still has to be the
/// writer's, or a stale file outranks the one `dcg allowlist add --user` just
/// wrote.
#[test]
fn test_xdg_allowlist_outranks_the_older_location() {
    let denied = "git reset --hard";
    let sandbox = spawn::sandbox();

    // $XDG_CONFIG_HOME allows nothing relevant; $HOME/.config would allow.
    let xdg_dir = sandbox.dcg_config_dir();
    std::fs::create_dir_all(&xdg_dir).unwrap();
    std::fs::write(
        xdg_dir.join("allowlist.toml"),
        "\n[[allow]]\nexact_command = \"echo unrelated\"\nreason = \"decoy\"\n",
    )
    .unwrap();

    let home_dir = sandbox.home.join(".config").join("dcg");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::write(
        home_dir.join("allowlist.toml"),
        format!("\n[[allow]]\nexact_command = \"{denied}\"\nreason = \"stale\"\n"),
    )
    .unwrap();

    let output = run_hook_in_sandbox(&sandbox, denied);
    assert!(
        output.contains("deny"),
        "the $XDG_CONFIG_HOME allowlist must win, so the stale entry at \
         $HOME/.config/dcg must NOT allow this command; got:\n{output}"
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
