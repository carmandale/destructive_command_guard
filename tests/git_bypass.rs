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

/// The rule the hook denied with, or `None` when it allowed (printed nothing).
fn denied_rule(command: &str) -> Option<String> {
    let output = run_hook(command);
    if output.trim().is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(&output)
        .unwrap_or_else(|e| panic!("hook output is not JSON ({e}): {output}"));
    let hook = &json["hookSpecificOutput"];
    assert_eq!(
        hook["permissionDecision"], "deny",
        "for {command}: {output}"
    );
    Some(
        hook["ruleId"]
            .as_str()
            .unwrap_or_else(|| panic!("deny without a ruleId for {command}: {output}"))
            .to_string(),
    )
}

/// The allow direction for the reverse order: a safe git command in front of
/// another safe one (.agent-config-uyc9l). These are false-positive controls,
/// not pins on the search-past-an-exemption path -- they pass on both sides of
/// 35ysf's fix, which is the point. `denied_rule` is the oracle here rather
/// than a `contains("deny")` substring, so an `ask` verdict or a rule id with
/// "deny" in its text cannot read as either answer.
#[test]
fn a_safe_git_command_in_front_of_another_safe_one_is_allowed() {
    let mut denied = Vec::new();
    for cmd in [
        "git checkout -b feat && git status",
        "git restore --staged a.txt && git restore --staged b.txt",
        "git clean -n\ngit checkout -b feat",
    ] {
        if let Some(rule) = denied_rule(cmd) {
            denied.push(format!("{cmd:?} -> {rule}"));
        }
    }
    assert!(denied.is_empty(), "safe lines denied: {denied:#?}");
}

/// The reverse order: a safe git command FIRST must not exempt a destructive
/// git command after it (.agent-config-uyc9l).
///
/// These same commands are also in `tests/corpus/true_positives/git_safe_span.toml`
/// on purpose, and neither copy is redundant: this one runs the real hook
/// binary end to end, while the corpus runs the evaluator and is additionally
/// consumed by the isomorphism and keyword-index tests.
///
/// A safe span exempts a destructive match that STARTS inside it. The core.git
/// destructive patterns open with a skipper that crosses `&&` (qv9dy keeps it:
/// bounding it opened bypasses), so the leftmost destructive match started at
/// the first `git` on the line, inside the safe `git checkout -b feat` span,
/// although the command it matched came after it. Narrowing the safe side
/// (t17jx) cannot reach this: that span is already one command.
#[test]
fn safe_git_command_first_does_not_exempt_a_destructive_one_after_it() {
    let mut wrong = Vec::new();
    for (cmd, rule) in [
        (
            "git checkout -b feat && git push --force origin main",
            "core.git:push-force-long",
        ),
        (
            "git checkout -b feat ; git reset --hard",
            "core.git:reset-hard",
        ),
        ("git clean -n && git clean -fd", "core.git:clean-force"),
        // Agents emit multi-line Bash, so the newline separator carries the
        // same weight as `&&` here as it does on t17jx's side of the corpus.
        (
            "git checkout -b feat\ngit push --force origin main",
            "core.git:push-force-long",
        ),
        (
            "git restore --staged a.txt && git restore b.txt",
            "core.git:restore-worktree",
        ),
        // .agent-config-qv9dy's review spellings, behind a safe command.
        (
            "git checkout -b feat && git -C \"$(cd a && pwd)\" push --force",
            "core.git:push-force-long",
        ),
        (
            "git checkout -b feat && git -c a.b=x\\;y checkout HEAD -- f",
            "core.git:checkout-ref-discard",
        ),
    ] {
        let got = denied_rule(cmd);
        if got.as_deref() != Some(rule) {
            wrong.push(format!("{cmd:?}: want {rule}, got {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a safe git command in front exempted a destructive one: {wrong:#?}"
    );
}
