//! Core git patterns - protections against destructive git commands.
//!
//! This includes patterns for:
//! - Work destruction (reset --hard, checkout --, restore)
//! - History rewriting (push --force, branch -D)
//! - Stash destruction (stash drop, stash clear)

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the core git pack.
#[must_use]
/// Command words that let this pack be consulted at all.
///
/// The registry's `PackEntry` points at this same const. They used to be two
/// lists, and 26 of 80 packs had drifted: the pack claimed a keyword the
/// registry gate did not carry, so rules for those words could never run
/// (`.agent-config-x74pe`).
pub const KEYWORDS: &[&str] = &["git"];

pub fn create_pack() -> Pack {
    Pack {
        id: "core.git".to_string(),
        name: "Core Git",
        description: "Protects against destructive git commands that can lose uncommitted work, \
                      rewrite history, or destroy stashes",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // The skipper between `git` and the safe subcommand walks only its OWN
    // command: `[^\s;&|]` stops at a separator and at a newline, `[^\S\n]`
    // gaps stop at a newline. With `(?:\S+\s+)*` and `\s+` gaps the leftmost
    // match started at the FIRST `git` on the line and ran through `&&` to the
    // safe subcommand, so the span covered a destructive git command in front
    // of it and the start-inside-span rule exempted that command: `git push
    // --force origin main && git checkout -b feat` was allowed
    // (.agent-config-t17jx, the safe-side half of .agent-config-it2wk).
    vec![
        // Branch creation is safe
        safe_pattern!(
            "checkout-new-branch",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*checkout\s+-b\s+"
        ),
        safe_pattern!(
            "checkout-orphan",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*checkout\s+--orphan\s+"
        ),
        // restore --staged only affects index, not working tree
        safe_pattern!(
            "restore-staged-long",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        safe_pattern!(
            "restore-staged-short",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        // clean dry-run just previews, doesn't delete
        safe_pattern!(
            "clean-dry-run-short",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*clean\s+-[a-z]*n[a-z]*"
        ),
        safe_pattern!(
            "clean-dry-run-long",
            r"git[^\S\n]+(?:[^\s;&|]+[^\S\n]+)*clean\s+--dry-run"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // checkout -- discards uncommitted changes
        destructive_pattern!(
            "checkout-discard",
            r"git\s+(?:\S+\s+)*checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.",
            High,
            "git checkout -- <path> discards all uncommitted changes to the specified files \
             in your working directory. These changes are permanently lost - they cannot be \
             recovered because they were never committed.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes temporarily, restore later with 'git stash pop'\n\
             - git diff <path>: Review what would be lost before discarding\n\n\
             Preview changes first:\n  git diff -- <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save changes temporarily, restore later with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git diff -- {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        // checkout-ref-discard, restore-worktree and push-force-long are spelled without
        // lookahead so they run on the linear engine. With lookahead they ran on the
        // backtracking engine, which counts backtracks over a whole search; the skipper
        // re-walks the rest of the command from every `git`, so long harmless git
        // scripts ran out (.agent-config-qv9dy). Each matches the same commands as its
        // lookahead form (the test below holds those forms as the oracle), but a match
        // can end later: these spellings consume what the lookahead only looked at.
        //
        // The ref is any word except `-b` or `--orphan` as a whole option, which is
        // what `(?!-b\b)(?!--orphan\b)[^\s]+` said.
        destructive_pattern!(
            "checkout-ref-discard",
            r"git\s+(?:\S+\s+)*checkout\s+(?:[^\s-]\S*|-(?:[^\s\-b]\S*|b\w\S*|-(?:[^\so]\S*|o(?:[^\sr]\S*|r(?:[^\sp]\S*|p(?:[^\sh]\S*|h(?:[^\sa]\S*|a(?:[^\sn]\S*|n\w\S*)?)?)?)?)?)?)?)\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first.",
            High,
            "git checkout <ref> -- <path> replaces your working tree files with versions from \
             another commit or branch. Any uncommitted changes to those files are permanently \
             lost - they cannot be recovered.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes first, then checkout, then restore with 'git stash pop'\n\
             - git show <ref>:<path>: View the file content without overwriting\n\n\
             Preview what would change:\n  git diff HEAD <ref> -- <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save changes first, then checkout, then restore with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git show {ref}:{path}",
                        "View the file content without overwriting",
                    ),
                    PatternSuggestion::new(
                        "git diff HEAD {ref} -- {path}",
                        "Preview what would change before overwriting",
                    ),
                ]
            }
        ),
        // restore without --staged affects working tree. After `restore` and one blank:
        // another blank, the end, or anything but `--staged`/`-S` as a whole option,
        // which is what `restore\s+(?!--staged\b)(?!-S\b)` said.
        destructive_pattern!(
            "restore-worktree",
            r"git\s+(?:\S+\s+)*restore\s(?:\s|$|[^\s-]|-(?:$|[^-S]|S\w)|--(?:$|[^s]|s(?:$|[^t]|t(?:$|[^a]|a(?:$|[^g]|g(?:$|[^e]|e(?:$|[^d]|d\w)))))))",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first.",
            High,
            "git restore <path> discards uncommitted changes in your working directory, \
             reverting files to their last committed state. Changes that were never \
             committed are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory changes\n\
             - git stash: Save all changes temporarily\n\
             - git diff <path>: Review what would be lost\n\n\
             Preview changes first:\n  git diff <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git restore --staged {path}",
                        "Only unstage, keeps working directory changes intact",
                    ),
                    PatternSuggestion::new(
                        "git stash",
                        "Save all changes temporarily, restore later with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git diff {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "restore-worktree-explicit",
            r"git\s+(?:\S+\s+)*restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently.",
            High,
            "git restore --worktree (or -W) explicitly targets your working directory, \
             discarding uncommitted changes. Even when combined with --staged, the worktree \
             changes are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory\n\
             - git stash: Save changes first\n\n\
             Preview changes first:\n  git diff <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git restore --staged {path}",
                        "Only unstage, keeps working directory changes intact",
                    ),
                    PatternSuggestion::new(
                        "git stash",
                        "Save all changes temporarily before discarding",
                    ),
                    PatternSuggestion::new(
                        "git diff {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        // reset --hard destroys uncommitted work (CRITICAL - extremely common mistake)
        destructive_pattern!(
            "reset-hard",
            r"git\s+(?:\S+\s+)*reset\s+--hard",
            "git reset --hard destroys uncommitted changes. Use 'git stash' first.",
            Critical,
            "git reset --hard discards ALL uncommitted changes in your working directory \
             AND staging area. This is one of the most dangerous git commands because \
             changes that were never committed cannot be recovered by any means.\n\n\
             What gets destroyed:\n\
             - All modified files revert to the target commit\n\
             - All staged changes are lost\n\
             - Untracked files remain (use git clean to remove those)\n\n\
             Safer alternatives:\n\
             - git reset --soft <ref>: Move HEAD but keep all changes staged\n\
             - git reset --mixed <ref>: Move HEAD, unstage changes, keep working dir (default)\n\
             - git stash: Save changes before resetting\n\n\
             Preview what would be lost:\n  git status && git diff",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save all uncommitted changes before reset",
                    ),
                    PatternSuggestion::new(
                        "git reset --soft HEAD~1",
                        "Undo commit but keep all changes staged",
                    ),
                    PatternSuggestion::new(
                        "git reset --mixed HEAD~1",
                        "Undo commit, unstage changes, but keep working directory",
                    ),
                    PatternSuggestion::new(
                        "git checkout -- {file}",
                        "Reset a specific file only, preserving other changes",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "reset-merge",
            r"git\s+(?:\S+\s+)*reset\s+--merge",
            "git reset --merge can lose uncommitted changes.",
            High,
            "git reset --merge resets the index and updates files in the working tree that \
             differ between the target commit and HEAD, but keeps changes that are not staged. \
             However, if there are uncommitted changes in files that need to be updated, \
             those changes will be lost.\n\n\
             Safer alternatives:\n\
             - git stash: Save uncommitted changes before reset\n\
             - git merge --abort: If in the middle of a merge, abort safely\n\n\
             Preview what would change:\n  git status && git diff",
            &const {
                [
                    PatternSuggestion::new("git stash", "Save uncommitted changes before reset"),
                    PatternSuggestion::new(
                        "git merge --abort",
                        "Abort the current merge safely without losing changes",
                    ),
                    PatternSuggestion::new(
                        "git status && git diff",
                        "Preview what would change before resetting",
                    ),
                ]
            }
        ),
        // clean -f deletes untracked files (CRITICAL - permanently removes files)
        destructive_pattern!(
            "clean-force",
            r"git\s+(?:\S+\s+)*clean\s+(?:-[a-z]*f|--force\b)",
            "git clean -f/--force removes untracked files permanently. Review with 'git clean -n' first.",
            Critical,
            "git clean -f permanently deletes untracked files from your working directory. \
             These are files that have never been committed to git, so they cannot be \
             recovered from git history. If you haven't backed them up elsewhere, they \
             are gone forever.\n\n\
             Common dangerous combinations:\n\
             - git clean -fd: Also removes untracked directories\n\
             - git clean -xf: Also removes ignored files (build artifacts, .env, etc.)\n\n\
             Safer alternatives:\n\
             - git clean -n: Dry-run, shows what would be deleted\n\
             - git clean -i: Interactive mode, choose what to delete\n\n\
             ALWAYS preview first:\n  git clean -n -d",
            &const {
                [
                    PatternSuggestion::new(
                        "git clean -n",
                        "Dry run first (shows what would be deleted)",
                    ),
                    PatternSuggestion::new("git clean -nd", "Dry run including directories"),
                    PatternSuggestion::new(
                        "git clean -i",
                        "Interactive mode, choose what to delete",
                    ),
                    PatternSuggestion::new(
                        "git stash --include-untracked",
                        "Stash instead of delete (recoverable)",
                    ),
                ]
            }
        ),
        // force push can destroy remote history (CRITICAL - affects shared history).
        // `(?:$|[^-a-z])` is `(?![-a-z])`, consuming the character it checks.
        destructive_pattern!(
            "push-force-long",
            r"git\s+(?:\S+\s+)*push\s+[^;&|\n]*--force(?:$|[^-a-z])",
            "Force push can destroy remote history. Use --force-with-lease if necessary.",
            Critical,
            "git push --force overwrites remote history with your local history. This can \
             permanently destroy commits that others have already pulled, causing data loss \
             for your entire team. Collaborators may lose work, and recovering requires \
             manual intervention from everyone affected.\n\n\
             What can go wrong:\n\
             - Commits others pushed are deleted from remote\n\
             - Team members get diverged histories\n\
             - CI/CD pipelines may reference deleted commits\n\n\
             Safer alternative:\n\
             - git push --force-with-lease: Only forces if remote matches your last fetch\n\n\
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
            &const {
                [
                    PatternSuggestion::new(
                        "git push --force-with-lease",
                        "Fails if remote has new commits you haven't fetched",
                    ),
                    PatternSuggestion::new(
                        "git push --force-with-lease --force-if-includes",
                        "Even safer: also checks that your local ref includes the remote ref",
                    ),
                    PatternSuggestion::new(
                        "git fetch && git log origin/{branch}..HEAD",
                        "Preview what you're about to overwrite on the remote",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "push-force-short",
            r"git\s+(?:\S+\s+)*push\s+[^;&|\n]*-f\b",
            "Force push (-f) can destroy remote history. Use --force-with-lease if necessary.",
            Critical,
            "git push -f (short for --force) overwrites remote history with your local history. \
             This can permanently destroy commits that others have already pulled, causing data \
             loss for your entire team.\n\n\
             What can go wrong:\n\
             - Commits others pushed are deleted from remote\n\
             - Team members get diverged histories\n\
             - CI/CD pipelines may reference deleted commits\n\n\
             Safer alternative:\n\
             - git push --force-with-lease: Only forces if remote matches your last fetch\n\n\
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
            &const {
                [
                    PatternSuggestion::new(
                        "git push --force-with-lease",
                        "Fails if remote has new commits you haven't fetched",
                    ),
                    PatternSuggestion::new(
                        "git push --force-with-lease --force-if-includes",
                        "Even safer: also checks that your local ref includes the remote ref",
                    ),
                    PatternSuggestion::new(
                        "git fetch && git log origin/{branch}..HEAD",
                        "Preview what you're about to overwrite on the remote",
                    ),
                ]
            }
        ),
        // branch -D/-f force deletes or overwrites without checks (Medium: recoverable via reflog)
        destructive_pattern!(
            "branch-force-delete",
            r"git\s+(?:\S+\s+)*branch\s+.*(?:-D\b|--force\b|-f\b)",
            "git branch -D/--force deletes branches without checks. Recoverable via 'git reflog'.",
            Medium,
            "git branch -D force-deletes a branch without checking if it has been merged. \
             If the branch contains unmerged commits, you may lose access to that work. \
             However, the commits still exist in git's object database and can be recovered \
             using reflog (for a limited time, typically 90 days).\n\n\
             Safer alternatives:\n\
             - git branch -d <branch>: Safe delete, fails if branch is not fully merged\n\
             - Merge the branch first, then delete with -d\n\n\
             Recovery if needed:\n\
               git reflog  # Find the commit hash\n\
               git checkout -b <branch> <commit-hash>",
            &const {
                [
                    PatternSuggestion::new(
                        "git branch -d {branch}",
                        "Safe delete: only works if branch is fully merged",
                    ),
                    PatternSuggestion::new(
                        "git branch -v {branch}",
                        "Show branch info (last commit) before deleting",
                    ),
                    PatternSuggestion::new(
                        "git log {branch} --oneline -10",
                        "Review branch commits before deleting",
                    ),
                ]
            }
        ),
        // stash destruction (Medium: single stash, recoverable via fsck/unreachable objects)
        destructive_pattern!(
            "stash-drop",
            r"git\s+(?:\S+\s+)*stash\s+drop",
            "git stash drop deletes a single stash. Recoverable via `git fsck` (unreachable objects).",
            Medium,
            "git stash drop removes a specific stash entry from your stash list. The stashed \
             changes become unreferenced but remain in git's object database temporarily. \
             They can often be recovered using git fsck, but this is not guaranteed and \
             becomes harder over time as git garbage collects.\n\n\
             Safer alternatives:\n\
             - git stash pop: Apply and drop in one step (only drops if apply succeeds)\n\
             - git stash apply: Apply without dropping, verify first\n\n\
             Recovery if needed:\n\
               git fsck --unreachable | grep commit\n\
               git show <commit-hash>  # Inspect each to find your stash",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash pop",
                        "Apply and drop atomically (only drops if apply succeeds)",
                    ),
                    PatternSuggestion::new(
                        "git stash apply",
                        "Apply without dropping, verify changes first",
                    ),
                    PatternSuggestion::new(
                        "git stash show stash@{0}",
                        "Preview stash contents before dropping",
                    ),
                    PatternSuggestion::new(
                        "git stash list",
                        "Review all stashes before dropping any",
                    ),
                ]
            }
        ),
        // stash clear destroys ALL stashes (CRITICAL)
        destructive_pattern!(
            "stash-clear",
            r"git\s+(?:\S+\s+)*stash\s+clear",
            "git stash clear permanently deletes ALL stashed changes.",
            Critical,
            "git stash clear removes ALL stash entries at once. Unlike git stash drop, \
             which removes one at a time, this command wipes your entire stash list. \
             All stashed changes become unreferenced and are very difficult to recover.\n\n\
             What gets destroyed:\n\
             - All entries in 'git stash list' are removed\n\
             - Multiple sets of saved work-in-progress may be lost\n\n\
             Safer alternatives:\n\
             - git stash drop stash@{n}: Remove one specific stash at a time\n\
             - git stash list: Review what would be lost first\n\
             - git stash show stash@{n}: Inspect each stash before deciding\n\n\
             Recovery (difficult, not guaranteed):\n\
               git fsck --unreachable | grep commit",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash drop stash@{n}",
                        "Remove one specific stash at a time",
                    ),
                    PatternSuggestion::new("git stash list", "Review all stashes before clearing"),
                    PatternSuggestion::new(
                        "git stash show stash@{n}",
                        "Inspect each stash before deciding to delete",
                    ),
                ]
            }
        ),
    ]
}

#[cfg(test)]
mod tests {
    //! Unit tests for core.git pack using the `test_helpers` framework.
    //!
    //! This module serves as an example of how to use the pack testing
    //! infrastructure. See `docs/pack-testing-guide.md` for details.

    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    // =========================================================================
    // Pack Creation Tests
    // =========================================================================

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();

        assert_eq!(pack.id, "core.git");
        assert_eq!(pack.name, "Core Git");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"git"));

        // Validate patterns
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    // =========================================================================
    // Critical Severity Pattern Tests
    // =========================================================================

    #[test]
    fn test_reset_hard_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git reset --hard", "reset-hard");
        assert_blocks(&pack, "git reset --hard HEAD", "destroys uncommitted");
        assert_blocks(&pack, "git reset --hard HEAD~1", "destroys uncommitted");
        assert_blocks(
            &pack,
            "git reset --hard origin/main",
            "destroys uncommitted",
        );
    }

    #[test]
    fn test_clean_force_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git clean -f", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git clean -f", "clean-force");
        assert_blocks(&pack, "git clean -fd", "removes untracked files");
        assert_blocks(&pack, "git clean -xf", "removes untracked files");
    }

    #[test]
    fn test_push_force_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git push --force", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push -f", Severity::Critical);
        assert_blocks(
            &pack,
            "git push origin main --force",
            "destroy remote history",
        );
        assert_blocks(
            &pack,
            "git push --force origin main",
            "destroy remote history",
        );
    }

    #[test]
    fn test_stash_clear_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git stash clear", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git stash clear", "stash-clear");
    }

    // =========================================================================
    // High Severity Pattern Tests
    // =========================================================================

    #[test]
    fn test_checkout_discard_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git checkout -- file.txt", Severity::High);
        assert_blocks_with_pattern(&pack, "git checkout -- file.txt", "checkout-discard");
        assert_blocks(&pack, "git checkout -- .", "discards uncommitted changes");
    }

    #[test]
    fn test_restore_worktree_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git restore file.txt", Severity::High);
        assert_blocks(
            &pack,
            "git restore --worktree file.txt",
            "discards uncommitted",
        );
    }

    #[test]
    fn test_branch_force_medium() {
        // Branch force delete is Medium severity (recoverable via reflog)
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git branch -D feature", Severity::Medium);
        assert_blocks_with_pattern(&pack, "git branch -D feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch --force feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -f feature", "branch-force-delete");
    }

    #[test]
    fn test_stash_drop_medium() {
        // Stash drop is Medium severity (recoverable via fsck)
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git stash drop", Severity::Medium);
        assert_blocks(&pack, "git stash drop stash@{0}", "Recoverable");
    }

    // =========================================================================
    // Safe Pattern Tests
    // =========================================================================

    #[test]
    fn test_safe_checkout_new_branch() {
        let pack = create_pack();

        assert_safe_pattern_matches(&pack, "git checkout -b feature");
        assert_safe_pattern_matches(&pack, "git checkout -b feature/new-thing");
        assert_allows(&pack, "git checkout -b fix-123");
    }

    #[test]
    fn test_safe_checkout_orphan() {
        let pack = create_pack();

        assert_safe_pattern_matches(&pack, "git checkout --orphan gh-pages");
        assert_allows(&pack, "git checkout --orphan new-root");
    }

    #[test]
    fn test_safe_restore_staged() {
        let pack = create_pack();

        assert_allows(&pack, "git restore --staged file.txt");
        assert_allows(&pack, "git restore -S file.txt");
    }

    #[test]
    fn test_safe_clean_dry_run() {
        let pack = create_pack();

        assert_allows(&pack, "git clean -n");
        assert_allows(&pack, "git clean -dn");
        assert_allows(&pack, "git clean --dry-run");
    }

    // =========================================================================
    // Specificity Tests (False Positive Prevention)
    // =========================================================================

    #[test]
    fn test_specificity_safe_git_commands() {
        let pack = create_pack();

        test_batch_allows(
            &pack,
            &[
                "git status",
                "git log",
                "git log --oneline",
                "git diff",
                "git diff --cached",
                "git show HEAD",
                "git branch",
                "git branch -a",
                "git remote -v",
                "git fetch",
                "git pull",
                "git push", // Without --force
                "git add .",
                "git commit -m 'message'",
                "git branch -d feature", // Safe delete with -d
            ],
        );
    }

    #[test]
    fn test_specificity_unrelated_commands() {
        let pack = create_pack();

        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "cargo build");
        assert_no_match(&pack, "npm install");
        assert_no_match(&pack, "docker run");
    }

    #[test]
    fn test_specificity_substring_not_matched() {
        let pack = create_pack();

        // "git" as substring should not trigger
        assert_no_match(&pack, "cat .gitignore");
        assert_no_match(&pack, "echo digit");
    }

    // =========================================================================
    // Performance Tests
    // =========================================================================

    #[test]
    fn test_performance_normal_commands() {
        let pack = create_pack();

        assert_matches_within_budget(&pack, "git reset --hard");
        assert_matches_within_budget(&pack, "git push --force origin main");
        assert_matches_within_budget(&pack, "git checkout -b feature/new");
    }

    #[test]
    fn test_performance_pathological_inputs() {
        let pack = create_pack();

        let long_flags = format!("git {}", "-".repeat(500));
        assert_matches_within_budget(&pack, &long_flags);

        let many_spaces = format!("git{}status", " ".repeat(100));
        assert_matches_within_budget(&pack, &many_spaces);
    }

    /// Repeat `unit` until the text reaches `bytes`.
    fn repeat_to(unit: &str, bytes: usize) -> String {
        unit.repeat(bytes.div_ceil(unit.len()))
    }

    /// With lookahead these three rules ran on the backtracking engine, which gives up
    /// after a fixed number of backtracks over one search and then cannot say "no
    /// match": 'git status' x400, 4,400 bytes, was already too much
    /// (.agent-config-qv9dy). The linear engine has no limit to reach. Every shape
    /// stays under the hook's 64 KiB command limit, so the hook can reach it.
    #[test]
    fn test_lookahead_free_rules_run_on_the_linear_engine() {
        use crate::packs::regex_engine::{CompiledRegex, needs_backtracking_engine};

        let pack = create_pack();
        let loop_unit = "cd ~/dev/repo && git fetch origin && git status -sb && cd -\n";
        let harmless = [
            ("git status x400", "git status\n".repeat(400)),
            (
                "bash heredoc multi-repo loop 60 KiB",
                format!("bash <<'SH'\n{}SH\n", repeat_to(loop_unit, 60 * 1024)),
            ),
            (
                "one-line chain 60 KiB",
                repeat_to(
                    "cd repo && git add -A && git commit -m wip && cd - ; ",
                    60 * 1024,
                ),
            ),
            ("one line of 'git status ' x300", "git status ".repeat(300)),
            (
                "python heredoc 16 KiB",
                format!(
                    "python3 - <<'PY'\nimport os\n{}PY\n",
                    repeat_to("os.system('git log -1 --oneline')\n", 16 * 1024)
                ),
            ),
        ];

        // Collect every failure before asserting, so one run names each rule that regressed.
        let mut failures = Vec::new();
        for (name, destructive) in [
            ("checkout-ref-discard", "git checkout HEAD -- f.txt"),
            ("restore-worktree", "git restore f.txt"),
            ("push-force-long", "git push origin main --force"),
        ] {
            let pattern = pack
                .destructive_patterns
                .iter()
                .find(|p| p.name == Some(name))
                .unwrap_or_else(|| panic!("core.git:{name} is missing"));
            let source = pattern.regex.as_str();
            if needs_backtracking_engine(source)
                || !CompiledRegex::new(source).is_ok_and(|re| !re.uses_backtracking())
            {
                failures.push(format!("core.git:{name} is on the backtracking engine"));
            }
            // try_is_match, not is_match: is_match reports a search that gave up as `false`,
            // which is the very answer these shapes used to produce.
            for (label, text) in &harmless {
                let alone = pattern.regex.try_is_match(text);
                if alone != Ok(false) {
                    failures.push(format!(
                        "core.git:{name} on {label}: {alone:?}, want Ok(false)"
                    ));
                }
                for sep in ["\n", "; "] {
                    let with_real = pattern
                        .regex
                        .try_is_match(&format!("{text}{sep}{destructive}"));
                    if with_real != Ok(true) {
                        failures.push(format!(
                            "core.git:{name} on {label} + {sep:?} + `{destructive}`: {with_real:?}, want Ok(true)"
                        ));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Through the evaluator, which denies when a search gives up (.agent-config-ryyfo).
    /// With lookahead each script here was denied as core.git:checkout-ref-discard because
    /// the search ran out, not because anything matched (.agent-config-qv9dy).
    #[test]
    fn test_evaluator_allows_long_harmless_git_scripts() {
        use crate::allowlist::LayeredAllowlist;
        use crate::config::{CompiledOverrides, Config};
        use crate::evaluator::evaluate_command;

        let config = Config::default();
        let overrides = CompiledOverrides::default();
        let allowlists = LayeredAllowlist::default();
        let scripts = [
            ("git status x400", "git status\n".repeat(400)),
            (
                "bash heredoc multi-repo loop 16 KiB",
                format!(
                    "bash <<'SH'\n{}SH\n",
                    repeat_to(
                        "cd ~/dev/repo && git fetch origin && git status -sb && cd -\n",
                        16 * 1024
                    )
                ),
            ),
            (
                "git add/commit lines 16 KiB",
                repeat_to("git add f.txt && git commit -m wip\n", 16 * 1024),
            ),
            (
                "fetch/push lines 16 KiB",
                repeat_to("git fetch origin && git push origin HEAD\n", 16 * 1024),
            ),
        ];

        let mut failures = Vec::new();
        for (label, script) in &scripts {
            let result = evaluate_command(script, &config, &["git"], &overrides, &allowlists);
            if !result.is_allowed() {
                let rule = result.pattern_info.and_then(|p| p.pattern_name);
                failures.push(format!("{label}: denied as core.git:{rule:?}"));
            }
            // A denial has to be the rule's own finding: a search that gives up is reported
            // under the same rule id, so the reason is what separates the two.
            let with_real = format!("{script}git checkout HEAD -- f.txt\n");
            let result = evaluate_command(&with_real, &config, &["git"], &overrides, &allowlists);
            let found = result.pattern_info.map(|p| (p.pattern_name, p.reason));
            match &found {
                Some((Some(rule), reason))
                    if rule == "checkout-ref-discard" && !reason.contains("could not finish") => {}
                _ => failures.push(format!(
                    "{label} + `git checkout HEAD -- f.txt`: {found:?}, want checkout-ref-discard on its merits"
                )),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The lookahead forms these rules replaced, kept as the oracle for "matches exactly
    /// what it matched" (.agent-config-qv9dy). The texts are the edges of each lookahead
    /// and the git-option spellings a narrower skipper was measured to miss.
    #[test]
    fn test_lookahead_free_rules_match_their_lookahead_forms() {
        let pack = create_pack();
        let texts = [
            "git restore f.txt",
            "git restore --staged f.txt",
            "git restore  --staged f.txt",
            "git restore -S f.txt",
            "git restore -Sx f.txt",
            "git restore --staged=x f.txt",
            "git restore --stagedx f.txt",
            "git restore -s f.txt",
            "git restore -- f.txt",
            "git restore ",
            "git restore -",
            "git restore --",
            "git restore --sta",
            "git restore --staged",
            "git restore -S",
            "git restore -S\n",
            "git restore --staged\nx",
            "git restore\t--staged f",
            "git restore -\n",
            "git restore\n",
            "git checkout HEAD -- f",
            "git checkout -b -- f",
            "git checkout -b.x -- f",
            "git checkout -bx -- f",
            "git checkout -b_x -- f",
            "git checkout --orphan -- f",
            "git checkout --orphan=x -- f",
            "git checkout --orphanx -- f",
            "git checkout --orp -- f",
            "git checkout - -- f",
            "git checkout -- -- f",
            "git checkout --b -- f",
            "git checkout  -b -- f",
            "git checkout --orphan\t-- f",
            "git push --force",
            "git push --force-with-lease",
            "git push --forcex",
            "git push --force=1",
            "git push --force\n",
            "git push --force;",
            "git push --forceA",
            "git push origin --force main",
            r#"git -C "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" push --force origin main"#,
            "git -C $(cd a && pwd) restore f.txt",
            r"git -c a.b=x\;y checkout HEAD -- f.txt",
            "git -c alias.x='a;b' checkout HEAD -- f.txt",
            "git -C repo \\\n  checkout HEAD -- f.txt",
        ];

        let mut failures = Vec::new();
        for (name, before) in [
            (
                "checkout-ref-discard",
                r"git\s+(?:\S+\s+)*checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            ),
            (
                "restore-worktree",
                r"git\s+(?:\S+\s+)*restore\s+(?!--staged\b)(?!-S\b)",
            ),
            (
                "push-force-long",
                r"git\s+(?:\S+\s+)*push\s+[^;&|\n]*--force(?![-a-z])",
            ),
        ] {
            let before = fancy_regex::Regex::new(before).expect("the oracle compiles");
            let pattern = pack
                .destructive_patterns
                .iter()
                .find(|p| p.name == Some(name))
                .unwrap_or_else(|| panic!("core.git:{name} is missing"));
            for text in texts {
                let want = before
                    .is_match(text)
                    .expect("a short text stays under the backtrack limit");
                if pattern.regex.is_match(text) != want {
                    failures.push(format!("core.git:{name} on {text:?}: want {want}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
