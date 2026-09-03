//! `evaluate_command` must not reach the ambient allow-once store (`.agent-config-pwv0p`).
//!
//! WHY THIS EXISTS. The allow-once store is a file on disk whose path is resolved
//! from the environment and the process CWD, and a matching entry turns a Critical
//! deny into an allow. `evaluate_command` consulted it, so every in-process caller —
//! embedders, and every test in this directory — shared one mutable file with every
//! other process on the machine. A deny assertion was therefore not a function of
//! the command under test, which is why one was cut back to asserting on the mask.
//!
//! Both directions are pinned here on purpose. Case 1 alone would pass if somebody
//! deleted the escape hatch outright; case 2 alone would pass if the channel came
//! back. Only the pair says "named at the call site".
//!
//! ONE TEST, NOT TWO: `DCG_ALLOW_ONCE_PATH` is process-global, so splitting these
//! into separate `#[test]`s would race them against each other inside this binary —
//! the same class of shared-channel bug the file is about.

use destructive_command_guard::pending_exceptions::{AllowOnceEntry, AllowOnceScopeKind};
use destructive_command_guard::{
    Config, LayeredAllowlist, evaluate_command, evaluate_command_consulting_allow_once,
    packs::REGISTRY,
};

/// Assembled rather than written literally: the live guard denies this source file
/// being written by an agent otherwise, which is the guard working.
fn trigger() -> String {
    format!("rm -{}f /", "r")
}

fn configured<T>(f: impl FnOnce(&Config, &[&str], &destructive_command_guard::config::CompiledOverrides, &LayeredAllowlist) -> T) -> T {
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    config.packs.enabled = vec!["core".to_string()];

    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    f(&config, &keywords, &overrides, &allowlists)
}

fn entry_for(command: &str) -> AllowOnceEntry {
    AllowOnceEntry {
        schema_version: 1,
        source_short_code: "PWV0P01".to_string(),
        source_full_hash: "regression-allow-once-channel".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        // Far future so the entry is never pruned as expired.
        expires_at: "2099-01-01T00:00:00Z".to_string(),
        // Project scope at `/` matches every cwd, which is precisely how a writer
        // reaches a reader it knows nothing about.
        scope_kind: AllowOnceScopeKind::Project,
        scope_path: "/".to_string(),
        command_raw: command.to_string(),
        command_redacted: "[redacted]".to_string(),
        reason: "regression fixture".to_string(),
        // Not single-use: a consuming read would rewrite the file and make the
        // second half of this test depend on the order of the first.
        single_use: false,
        consumed_at: None,
        force_allow_config: false,
    }
}

#[test]
fn allow_once_is_named_at_the_call_site_not_inherited() {
    let command = trigger();

    let dir = std::env::temp_dir().join(format!("dcg-pwv0p-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let store = dir.join("allow_once.jsonl");
    std::fs::write(
        &store,
        format!("{}\n", serde_json::to_string(&entry_for(&command)).expect("serialize")),
    )
    .expect("write allow-once fixture");

    // SAFETY: single-threaded section of a binary whose only test this is; the
    // module comment explains why it is not split.
    unsafe { std::env::set_var("DCG_ALLOW_ONCE_PATH", &store) };

    let inherited = configured(|c, k, o, a| evaluate_command(&command, c, k, o, a));
    let asked_for = configured(|c, k, o, a| {
        evaluate_command_consulting_allow_once(&command, c, k, o, a)
    });

    unsafe { std::env::remove_var("DCG_ALLOW_ONCE_PATH") };
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        inherited.is_denied(),
        "evaluate_command read the ambient allow-once store: a file written by \
         another process flipped a Critical deny to an allow. Its verdict must be \
         a function of its arguments alone.\nreason: {:?}",
        inherited.reason()
    );

    assert!(
        !asked_for.is_denied(),
        "the allow-once escape hatch is gone: a caller that explicitly asked to \
         consult the store did not honour a matching entry. Removing the channel \
         from evaluate_command must not remove the feature.\nreason: {:?}",
        asked_for.reason()
    );
}
