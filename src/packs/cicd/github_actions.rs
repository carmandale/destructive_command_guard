//! GitHub Actions pack - protections for destructive GitHub Actions operations via `gh`.
//!
//! This pack targets high-impact operations when managing GitHub Actions workflows,
//! secrets, and variables:
//! - Deleting secrets / variables
//! - Disabling workflows
//! - Canceling runs
//! - `gh api` DELETE calls against `/actions/*` endpoints

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitHub Actions pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cicd.github_actions".to_string(),
        name: "GitHub Actions",
        description: "Protects against destructive GitHub Actions operations like deleting secrets/variables \
             or using gh api DELETE against /actions endpoints.",
        // Broad on purpose: global `gh` flags can appear before the subcommand.
        keywords: &["gh"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "gh-actions-secret-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+secret\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-variable-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+variable\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-workflow-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-workflow-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+view\b"
        ),
        safe_pattern!(
            "gh-actions-run-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-run-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+view\b"
        ),
        // Safe only when GET is explicit (default method can vary by flags).
        // The span stops at the command it covers. `.*` ran to the end of the line, and a match
        // is exempted when it starts inside a safe span, so one harmless GET anywhere on a line
        // exempted a real deletion elsewhere on it (.agent-config-kf3dq cold review look 2).
        // The lookahead is not decoration: this safe pattern and the destructive
        // `api ... DELETE` ones all START at the command word, and the exemption
        // rule asks whether a destructive match starts INSIDE a safe span. Two
        // spans that both start here satisfy that unconditionally, so before
        // `.agent-config-nh7t4` a `-X GET` anywhere in the command exempted a
        // `-X DELETE` in the SAME command -- in either order, and even when the
        // GET was only text inside a quoted value. A GET pattern may only speak
        // for a command that names no state-changing method.
        safe_pattern!(
            "gh-actions-api-explicit-get",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b(?![^;&|\n]*(?:-X|--method)\s+(?:DELETE|PUT|PATCH|POST)\b)[^;&|\n]*(?:-X|--method)\s+GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Without the safe patterns' subcommand lookahead, for the reason in platform/github.rs
    // (.agent-config-kf3dq).
    vec![
        destructive_pattern!(
            "gh-actions-secret-remove",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+secret\s+(?:delete|remove)\b",
            "gh secret delete/remove deletes GitHub Actions secrets. This can break CI and may be hard to recover.",
            High,
            "Deleting a GitHub Actions secret removes it from the repository, organization, \
             or environment. Workflows using this secret will fail with authentication or \
             configuration errors. Secret values are not recoverable after deletion.\n\n\
             Safer alternatives:\n\
             - gh secret list: Review existing secrets first\n\
             - Update the secret value instead of deleting\n\
             - Check workflow files for secret usage before removing"
        ),
        destructive_pattern!(
            "gh-actions-variable-remove",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+variable\s+(?:delete|remove)\b",
            "gh variable delete/remove deletes GitHub Actions variables. This can break workflows.",
            Medium,
            "Removing a GitHub Actions variable makes it unavailable to all workflows that \
             reference it. Unlike secrets, variable values are visible, but workflows may \
             fail with undefined variable errors after deletion.\n\n\
             Safer alternatives:\n\
             - gh variable list: Review existing variables first\n\
             - gh variable set: Update value instead of removing\n\
             - Search workflows for variable usage before removing"
        ),
        destructive_pattern!(
            "gh-actions-workflow-disable",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+workflow\s+disable\b",
            "gh workflow disable disables workflows. This is reversible, but can disrupt CI.",
            Low,
            "Disabling a workflow prevents it from running on any triggers. This is reversible \
             with 'gh workflow enable', but can disrupt CI/CD pipelines, scheduled jobs, and \
             automated deployments while disabled.\n\n\
             Safer alternatives:\n\
             - gh workflow list: Review workflow status first\n\
             - gh workflow view: Check workflow details\n\
             - Use workflow_dispatch for manual control instead"
        ),
        destructive_pattern!(
            "gh-actions-run-cancel",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+run\s+cancel\b",
            "gh run cancel cancels a running workflow. This is reversible, but may disrupt deployments.",
            Low,
            "Canceling a workflow run stops it mid-execution. Any in-progress deployments, \
             tests, or builds will be interrupted. The run can be re-triggered, but partial \
             work may leave systems in an inconsistent state.\n\n\
             Safer alternatives:\n\
             - gh run view: Check run status and progress first\n\
             - gh run list: Review running workflows\n\
             - Wait for natural completion if possible"
        ),
        destructive_pattern!(
            "gh-actions-api-delete-secrets",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*\b/?repos/[^\s/]+/[^\s/]+/actions/secrets\b",
            "gh api DELETE against /actions/secrets deletes GitHub Actions secrets.",
            High,
            "Making DELETE requests to the GitHub Actions secrets API removes secrets from \
             the repository. This bypasses CLI confirmations and directly modifies repository \
             settings. Workflows will fail when referencing deleted secrets.\n\n\
             Safer alternatives:\n\
             - Use gh secret delete for safer deletion with prompts\n\
             - gh api GET first: Verify secret exists\n\
             - Prefer CLI commands over direct API calls"
        ),
        destructive_pattern!(
            "gh-actions-api-delete-variables",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*\b/?repos/[^\s/]+/[^\s/]+/actions/variables\b",
            "gh api DELETE against /actions/variables deletes GitHub Actions variables.",
            Medium,
            "Making DELETE requests to the GitHub Actions variables API removes variables \
             from the repository. This bypasses CLI confirmations and directly modifies \
             repository settings. Workflows referencing these variables will fail.\n\n\
             Safer alternatives:\n\
             - Use gh variable delete for safer deletion with prompts\n\
             - gh api GET first: Verify variable exists\n\
             - Prefer CLI commands over direct API calls"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_safe_list_variants() {
        let pack = create_pack();
        assert!(pack.check("gh secret list").is_none());
        assert!(pack.check("gh variable list").is_none());
        assert!(pack.check("gh workflow list").is_none());
        assert!(pack.check("gh run list").is_none());
    }

    #[test]
    fn blocks_secret_and_variable_removal() {
        let pack = create_pack();

        let matched = pack
            .check("gh secret delete FOO")
            .expect("secret delete should be detected");
        assert_eq!(matched.name, Some("gh-actions-secret-remove"));

        let matched = pack
            .check("gh -R owner/repo secret remove FOO")
            .expect("secret remove with global flags should be detected");
        assert_eq!(matched.name, Some("gh-actions-secret-remove"));

        let matched = pack
            .check("gh variable delete FOO")
            .expect("variable delete should be detected");
        assert_eq!(matched.name, Some("gh-actions-variable-remove"));
    }

    #[test]
    fn blocks_workflow_disable_and_run_cancel() {
        let pack = create_pack();

        let matched = pack
            .check("gh workflow disable 123")
            .expect("workflow disable should be detected");
        assert_eq!(matched.name, Some("gh-actions-workflow-disable"));

        let matched = pack
            .check("gh run cancel 123")
            .expect("run cancel should be detected");
        assert_eq!(matched.name, Some("gh-actions-run-cancel"));
    }

    #[test]
    fn detects_gh_api_delete_against_actions_endpoints() {
        let pack = create_pack();

        let matched = pack
            .check("gh api -X DELETE repos/o/r/actions/secrets/FOO")
            .expect("gh api DELETE secrets should be detected");
        assert_eq!(matched.name, Some("gh-actions-api-delete-secrets"));

        let matched = pack
            .check("gh api --method DELETE /repos/o/r/actions/variables/FOO")
            .expect("gh api DELETE variables should be detected");
        assert_eq!(matched.name, Some("gh-actions-api-delete-variables"));
    }
}
