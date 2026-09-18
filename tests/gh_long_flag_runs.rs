//! The destructive rules of `platform.github` and `cicd.github_actions` answer a long run of
//! dash tokens after `gh` instead of giving up (.agent-config-kf3dq).
//!
//! Their option skipper lets each dash token be a flag or the previous flag's value, so a run
//! of n tokens has Fibonacci-many parses. While a subcommand lookahead kept the rules on the
//! backtracking engine, `gh` + `-f ` x24 + `pr list` (82 bytes) ran out of backtracks, and a
//! search that gives up denies, as `platform.github:gh-repo-delete`. Without the lookahead the
//! rules run on the linear engine, which has no limit to reach.

use std::io::Write;
use std::process::Stdio;

use destructive_command_guard::packs::regex_engine::{CompiledRegex, needs_backtracking_engine};
use destructive_command_guard::packs::{Pack, cicd, platform};

#[path = "common/payload.rs"]
mod payload;
#[path = "common/spawn.rs"]
mod spawn;

/// One destructive command per rule, without its leading `gh `.
const GITHUB: &[(&str, &str)] = &[
    ("gh-repo-delete", "repo delete o/r"),
    ("gh-repo-archive", "repo archive o/r"),
    ("gh-gist-delete", "gist delete 123"),
    ("gh-release-delete", "release delete v1.0"),
    ("gh-issue-delete", "issue delete 1"),
    ("gh-ssh-key-delete", "ssh-key delete 1"),
    ("gh-secret-delete", "secret delete FOO"),
    ("gh-variable-delete", "variable delete FOO"),
    ("gh-repo-deploy-key-delete", "repo deploy-key delete 1"),
    ("gh-run-cancel", "run cancel 1"),
    (
        "gh-api-delete-actions-secret",
        "api -X DELETE /repos/o/r/actions/secrets/FOO",
    ),
    (
        "gh-api-delete-actions-variable",
        "api -X DELETE /repos/o/r/actions/variables/FOO",
    ),
    ("gh-api-delete-hook", "api -X DELETE /repos/o/r/hooks/1"),
    (
        "gh-api-delete-deploy-key",
        "api -X DELETE /repos/o/r/keys/1",
    ),
    (
        "gh-api-delete-release",
        "api -X DELETE /repos/o/r/releases/1",
    ),
    ("gh-api-delete-repo", "api -X DELETE /repos/o/r"),
];

const GITHUB_ACTIONS: &[(&str, &str)] = &[
    ("gh-actions-secret-remove", "secret remove FOO"),
    ("gh-actions-variable-remove", "variable remove FOO"),
    ("gh-actions-workflow-disable", "workflow disable 1"),
    ("gh-actions-run-cancel", "run cancel 1"),
    (
        "gh-actions-api-delete-secrets",
        "api -X DELETE repos/o/r/actions/secrets/FOO",
    ),
    (
        "gh-actions-api-delete-variables",
        "api --method DELETE repos/o/r/actions/variables/FOO",
    ),
];

/// Harmless flag runs in front of `pr list`, which no rule in either pack names.
fn flag_runs() -> Vec<(String, String)> {
    let mut runs = Vec::new();
    for n in [24, 32, 40] {
        runs.push((format!("-f x{n}"), "-f ".repeat(n)));
    }
    for n in [12, 20] {
        runs.push((format!("'--flag -v' x{n}"), "--flag -v ".repeat(n)));
    }
    // Under the hook's 64 KiB command limit, to show there is no limit left to reach.
    runs.push(("-f x20000".to_string(), "-f ".repeat(20_000)));
    runs
}

#[test]
fn every_destructive_gh_rule_runs_on_the_linear_engine_and_answers_long_flag_runs() {
    let mut failures = Vec::new();
    let runs = flag_runs();
    for (pack, examples) in [
        (platform::github::create_pack(), GITHUB),
        (cicd::github_actions::create_pack(), GITHUB_ACTIONS),
    ] {
        check_pack(&pack, examples, &runs, &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn check_pack(
    pack: &Pack,
    examples: &[(&str, &str)],
    runs: &[(String, String)],
    failures: &mut Vec<String>,
) {
    let mut names: Vec<&str> = pack
        .destructive_patterns
        .iter()
        .filter_map(|p| p.name)
        .collect();
    let mut covered: Vec<&str> = examples.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    covered.sort_unstable();
    assert_eq!(
        names, covered,
        "{}: one example per destructive rule",
        pack.id
    );

    for (name, example) in examples {
        let id = format!("{}:{name}", pack.id);
        let pattern = pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some(*name))
            .unwrap_or_else(|| panic!("{id} is missing"));
        let source = pattern.regex.as_str();
        match CompiledRegex::new(source) {
            Ok(re) if re.uses_backtracking() || needs_backtracking_engine(source) => {
                failures.push(format!("{id} is on the backtracking engine"));
            }
            Ok(_) => {}
            Err(e) => failures.push(format!("{id} does not compile: {e}")),
        }
        // try_is_match, not is_match: is_match reports a search that gave up as `false`.
        for (label, run) in runs {
            let harmless = pattern.regex.try_is_match(&format!("gh {run}pr list"));
            if harmless != Ok(false) {
                failures.push(format!(
                    "{id} on gh {label} pr list: {harmless:?}, want Ok(false)"
                ));
            }
            let real = pattern.regex.try_is_match(&format!("gh {run}{example}"));
            if real != Ok(true) {
                failures.push(format!(
                    "{id} on gh {label} {example}: {real:?}, want Ok(true)"
                ));
            }
        }
    }
}

const BOTH_PACKS: &str = "core,cicd.github_actions,platform.github";

/// Runs the hook with `packs` enabled and returns (ruleId, whole stdout); `None` is allow.
fn hook(packs: &str, command: &str) -> Option<(String, String)> {
    let (mut cmd, sandbox) = spawn::dcg_with_packs(packs);
    // The budget that keeps an allow here from being the evaluation clock
    // failing open is `spawn::GENEROUS_HOOK_TIMEOUT_MS`, which every harness
    // now carries (.agent-config-0o2q1). This file used to set its own.
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn dcg");
    let input = payload::pre_tool_use(sandbox.root(), command).to_string();
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write hook input");
    let output = child.wait_with_output().expect("wait for dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // dcg exits 0 for an allow AND for a deny, so a non-zero status is dcg failing to answer at
    // all. Without this, a crash reads as empty stdout, which reads as an allow.
    assert!(
        output.status.success(),
        "dcg exited {:?} on {command:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    if stdout.trim().is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hook output is JSON");
    let rule = json["hookSpecificOutput"]["ruleId"]
        .as_str()
        .unwrap_or_default();
    Some((rule.to_string(), stdout))
}

/// The real hook. Each allow is paired with the same run in front of a real destructive command,
/// denied by its own rule, so the allow is the rules answering "no". The github_actions rule is
/// checked with that pack alone: with both enabled platform.github names every High command first,
/// and the pack's Low/Medium rules only warn.
#[test]
fn hook_allows_long_harmless_gh_flag_runs_with_both_gh_packs_enabled() {
    let mut failures = Vec::new();
    for n in [24, 32, 40] {
        let run = "-f ".repeat(n);
        if let Some((rule, _)) = hook(BOTH_PACKS, &format!("gh {run}pr list")) {
            failures.push(format!("gh -f x{n} pr list: denied as {rule}"));
        }
        for (packs, command, want) in [
            (
                BOTH_PACKS,
                format!("gh {run}repo delete o/r"),
                "platform.github:gh-repo-delete",
            ),
            (
                "core,cicd.github_actions",
                format!("gh {run}secret remove FOO"),
                "cicd.github_actions:gh-actions-secret-remove",
            ),
        ] {
            match hook(packs, &command) {
                Some((rule, stdout)) if rule == want && !stdout.contains("could not finish") => {}
                found => failures.push(format!("{command}: {found:?}, want {want} on its merits")),
            }
        }
    }
    // The lookahead refused a flag value starting with a subcommand word, which only ever lost
    // real commands like these: both were allowed while it was there.
    for (packs, command, want) in [
        (
            BOTH_PACKS,
            "gh -R repo repo delete",
            "platform.github:gh-repo-delete",
        ),
        (
            "core,cicd.github_actions",
            "gh --repo api-team/svc secret remove FOO",
            "cicd.github_actions:gh-actions-secret-remove",
        ),
    ] {
        match hook(packs, command) {
            Some((rule, _)) if rule == want => {}
            found => failures.push(format!("{command}: {found:?}, want {want}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A safe gh command must not exempt the destructive one beside it.
///
/// Dropping the lookahead lets a rule match an earlier `gh` whose flag value starts with a
/// subcommand word, and `gh-status` matches that same value, so the new match starts inside a safe
/// span. While an exempted match ended the search for its rule, that cost the rule its only look at
/// the line and these were ALLOW (.agent-config-kf3dq cold review; 154 of 154 generated lines moved
/// DENY -> ALLOW). .agent-config-35ysf made the search resume past the span, which is what holds
/// them. This is the pin for that pair: it cannot live in tests/corpus, because `verify_corpus_case`
/// evaluates with `Config::default()`, whose pack list forces on `core` alone, so a gh case there
/// would run with both gh packs off and pass while proving nothing.
#[test]
fn a_safe_gh_command_does_not_exempt_the_destructive_one_beside_it() {
    let mut failures = Vec::new();
    for (command, want) in [
        (
            "gh -R status/dashboard repo delete && gh repo delete groovejones/site",
            "platform.github:gh-repo-delete",
        ),
        (
            "gh --hostname status/dashboard release delete v1 | gh release delete v9 --yes",
            "platform.github:gh-release-delete",
        ),
        (
            "gh -f status api -X GET /user ; gh api -X DELETE /repos/o/r/hooks/7",
            "platform.github:gh-api-delete-hook",
        ),
        (
            "gh -R status/dashboard repo delete\ngh repo delete groovejones/site\n",
            "platform.github:gh-repo-delete",
        ),
        // The one that needs the safe patterns' `api ... GET` span to stop at its own command:
        // with `.*` the span ran to the last GET on the line and covered the deletion in the
        // middle of it. Revert either bound and this case alone goes ALLOW.
        (
            "gh -R status repo delete\ngh api -X GET /rate_limit\ngh api -X GET /user \
             && gh repo delete groovejones/site --yes ; gh api -X GET /meta",
            "platform.github:gh-repo-delete",
        ),
    ] {
        match hook(BOTH_PACKS, command) {
            Some((rule, _)) if rule == want => {}
            found => failures.push(format!("{command:?}: {found:?}, want {want}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A flag value is not a subcommand.
///
/// The skipper's lookahead refuses a value that starts with a subcommand word, which left the value
/// for the tail to read as the subcommand: `gh -R status/x repo delete` matched the safe `gh-status`
/// at (0, 12), because `status\b` is happy with `status/x`, and that span starts where the deletion
/// starts, so the deletion was exempted and ALLOWED (.agent-config-cjqsf). Every safe pattern's last
/// word is now a whole token.
///
/// Not fixed, and not fixable this way: a value that is EXACTLY a subcommand word
/// (`gh --hostname status repo delete o/r`) is still exempt, because the skipper may stop before it
/// and `gh ... status` is then a real `gh status`. Telling those apart needs each flag's arity.
#[test]
fn a_flag_value_is_not_read_as_a_safe_subcommand() {
    let mut failures = Vec::new();
    for (command, want) in [
        (
            "gh -R status/x repo delete",
            Some("platform.github:gh-repo-delete"),
        ),
        (
            "gh -R status-page/x repo delete",
            Some("platform.github:gh-repo-delete"),
        ),
        (
            "gh -R status.io/x run cancel 1",
            Some("platform.github:gh-run-cancel"),
        ),
        // The same reach through a subcommand word that is not a tail: `gh-api-explicit-get` read
        // `-R api/x` as a safe `gh api ... GET`. Both of these were allowed before this change.
        (
            "gh -R api/x repo delete o/r -X GET",
            Some("platform.github:gh-repo-delete"),
        ),
        (
            "gh -R api-team/svc repo delete o/r -X GET",
            Some("platform.github:gh-repo-delete"),
        ),
        // The exemptions that have to survive: a real `gh status`, the list/view commands, and a
        // GET that covers its own command.
        ("gh status", None),
        ("gh repo list", None),
        ("gh repo view o/r", None),
        ("gh auth status", None),
        ("gh secret list --json x", None),
        ("gh api -X GET /repos/o/r", None),
        // Allowed, and pinned as it is rather than as it should be. `gh-status` stops matching
        // `-R status/x` and matches `--hostname status` instead, which exempts the deletion behind
        // it. Each of these two commands is allowed standing alone as well, so nothing dcg was
        // protecting is lost. That a safe pattern's ONE recorded match decides which command gets
        // the exemption is .agent-config-nlid7; a flag value that is exactly a subcommand word is
        // the residue named above.
        (
            "gh -R status/x pr list ; gh --hostname status repo delete o/r",
            None,
        ),
    ] {
        let found = hook(BOTH_PACKS, command).map(|(rule, _)| rule);
        if found.as_deref() != want {
            failures.push(format!("{command:?}: {found:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
