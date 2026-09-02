#![allow(clippy::uninlined_format_args)]
//! Focused coverage for `dcg test` command behavior.

use std::path::Path;
use std::process::Output;

#[path = "common/spawn.rs"]
mod spawn;

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Run dcg with an isolated HOME/XDG config to avoid machine-specific allowlists.
fn run_dcg_isolated(args: &[&str], cwd: Option<&Path>) -> Output {
    let (mut cmd, _sandbox) = spawn::dcg();
    cmd.args(args);

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    cmd.output().expect("run dcg")
}

fn parse_json(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout_text(output)).expect("stdout should be valid JSON")
}

#[test]
fn test_basic_blocked_command_exits_one() {
    let output = run_dcg_isolated(&["test", "--format", "json", "git reset --hard"], None);

    assert_eq!(
        output.status.code(),
        Some(1),
        "blocked command should exit 1\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
}

#[test]
fn test_basic_allowed_command_exits_zero() {
    let output = run_dcg_isolated(&["test", "--format", "json", "ls -la"], None);

    assert_eq!(
        output.status.code(),
        Some(0),
        "allowed command should exit 0\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_allowlist_match_allows_blocked_command() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    std::fs::write(
        repo.path().join(".dcg").join("allowlist.toml"),
        r#"
[[allow]]
exact_command = "git reset --hard"
reason = "test fixture allowlist entry"
"#,
    )
    .expect("write allowlist");

    let output = run_dcg_isolated(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "allowlist match should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_json_output_has_expected_fields() {
    let output = run_dcg_isolated(&["test", "--format", "json", "git reset --hard"], None);
    let json = parse_json(&output);

    assert!(json.get("schema_version").is_some());
    assert!(json.get("dcg_version").is_some());
    assert!(json.get("robot_mode").is_some());
    assert!(json.get("command").is_some());
    assert!(json.get("decision").is_some());
}

#[test]
fn test_custom_config_is_applied() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[overrides]
allow = ["git reset --hard"]
"#,
    )
    .expect("write config");

    let config_arg = config_path.to_string_lossy().to_string();
    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--config",
            config_arg.as_str(),
            "git reset --hard",
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "custom config override should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_project_config_discovery_is_applied_without_config_flag() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::write(
        repo.path().join(".dcg.toml"),
        r#"
[overrides]
allow = ["git reset --hard"]
"#,
    )
    .expect("write project config");

    let output = run_dcg_isolated(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "project config should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_with_packs_enables_extra_pack_detection() {
    let cmd = "aws ec2 terminate-instances --instance-ids i-1234567890abcdef0";

    let baseline = run_dcg_isolated(&["test", "--format", "json", cmd], None);
    assert_eq!(
        baseline.status.code(),
        Some(0),
        "baseline should allow without extra pack\nstderr: {}",
        stderr_text(&baseline)
    );
    let baseline_json = parse_json(&baseline);
    assert_eq!(baseline_json["decision"], "allow");

    let with_pack = run_dcg_isolated(
        &["test", "--format", "json", "--with-packs", "cloud.aws", cmd],
        None,
    );
    assert_eq!(
        with_pack.status.code(),
        Some(1),
        "extra pack should block command\nstderr: {}",
        stderr_text(&with_pack)
    );

    let with_pack_json = parse_json(&with_pack);
    assert_eq!(with_pack_json["decision"], "deny");
    assert_eq!(with_pack_json["pack_id"], "cloud.aws");
}

#[test]
fn test_test_subcommand_help_text_includes_key_flags() {
    let output = run_dcg_isolated(&["help", "test"], None);
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));

    assert!(
        matches!(output.status.code(), Some(0) | Some(2)),
        "help should exit with clap help code\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    assert!(combined.contains("Usage: dcg test [OPTIONS] <COMMAND>"));
    assert!(combined.contains("--config"));
    assert!(combined.contains("--with-packs"));
    assert!(combined.contains("--format"));
    assert!(combined.contains("--heredoc-scan"));
}

#[test]
fn test_verbose_output_includes_diagnostics() {
    let output = run_dcg_isolated(&["test", "--verbose", "git reset --hard"], None);
    let stdout = stdout_text(&output);

    assert_eq!(
        output.status.code(),
        Some(1),
        "blocked command should exit 1 in verbose mode\nstderr: {}",
        stderr_text(&output)
    );
    assert!(
        stdout.contains("Reason:"),
        "expected Reason in verbose output"
    );
    assert!(
        stdout.contains("Result: BLOCKED"),
        "expected blocked result in verbose output"
    );
}
