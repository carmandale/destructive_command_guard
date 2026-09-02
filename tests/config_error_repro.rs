use std::fs;

#[path = "common/spawn.rs"]
mod spawn;

#[test]
fn test_config_load_swallows_parse_error() {
    let (mut cmd, sandbox) = spawn::dcg();
    let config_path = sandbox.root().join("config.toml");

    // Write invalid TOML
    let invalid_toml = r#"
[general]
verbose = true
color = "always"
invalid_syntax_here =
"#;
    fs::write(&config_path, invalid_toml).expect("failed to write config file");

    // Run `dcg config` pointing to this file.
    //
    // We EXPECT it to succeed (exit 0) but ignore the file (so verbose=false default).
    // If it failed on parse error, this test would fail (assertion failure).
    // If it parsed correctly, verbose would be true.
    // If it swallowed the error, it succeeds but uses defaults (verbose=false).
    let output = cmd
        .env("DCG_CONFIG", &config_path)
        .arg("config")
        .output()
        .expect("run dcg config");

    assert!(
        output.status.success(),
        "dcg config should succeed on an unparseable file\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verbose: false"),
        "expected the invalid file to be ignored (default verbose=false)\nstdout:\n{stdout}"
    );
}
