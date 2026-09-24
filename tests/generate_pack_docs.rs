//! Pack documentation generator and coverage verification.
//!
//! This test generates per-pack reference documentation from `PackRegistry` metadata
//! and verifies that all packs have documentation entries.

use destructive_command_guard::packs::core::filesystem::resolved_temp_roots;
use destructive_command_guard::packs::{Pack, PackRegistry};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Get the category from a pack ID (e.g., "core.git" -> "core").
fn category_from_pack_id(pack_id: &str) -> &str {
    pack_id.split('.').next().unwrap_or(pack_id)
}

/// Generate a slug-friendly filename from a category name.
fn category_filename(category: &str) -> String {
    format!("{category}.md")
}

/// Replace the directory the live `$TMPDIR` names with a stable placeholder.
///
/// `core.find`'s `find-temp-root` is built at startup and contains the resolved
/// per-user temp root -- on macOS `/var/folders/<2>/<hash>/T` and its
/// `/private` twin (`.agent-config-o4e8j`). That string is machine- and
/// user-specific, so rendering it verbatim would commit one machine's temp hash
/// to a doc every other machine then disagrees with, and would publish a path no
/// reader can use. The placeholder says what is actually there.
///
/// With `TMPDIR` unset or degenerate the root list is empty and this is a no-op,
/// which is also the state the checked-in doc is written for.
fn redact_resolved_temp_roots(pattern: &str) -> String {
    let mut out = pattern.to_string();
    // Longest first: `/var/folders/<..>/T` is a substring of its own
    // `/private/var/folders/<..>/T` twin, so replacing the short one first
    // leaves `/private<placeholder>` behind.
    let mut roots: Vec<&String> = resolved_temp_roots().iter().collect();
    roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
    for root in roots {
        // The pattern holds the root regex-escaped, then pipe-escaped for the
        // markdown table; match it the same way round.
        let needle = regex::escape(root).replace('|', "\\|");
        out = out.replace(&needle, "<the resolved $TMPDIR>");
    }
    out
}

/// Generate markdown documentation for a single pack.
fn generate_pack_section(pack: &Pack) -> String {
    let mut out = String::new();

    // Pack header
    let _ = writeln!(out, "## {}\n", pack.name);
    let _ = writeln!(out, "**Pack ID:** `{}`\n", pack.id);
    let _ = writeln!(out, "{}\n", pack.description);

    // Keywords
    if !pack.keywords.is_empty() {
        out.push_str("### Keywords\n\n");
        out.push_str("Commands containing these keywords are checked against this pack:\n\n");
        for kw in pack.keywords {
            let _ = writeln!(out, "- `{kw}`");
        }
        out.push('\n');
    }

    // Safe patterns (what's allowed)
    if !pack.safe_patterns.is_empty() {
        out.push_str("### Safe Patterns (Allowed)\n\n");
        out.push_str("These patterns match safe commands that are always allowed:\n\n");
        out.push_str("| Pattern Name | Pattern |\n");
        out.push_str("|--------------|----------|\n");
        for p in &pack.safe_patterns {
            let pattern_str = p.regex.as_str();
            // Escape pipe characters in markdown tables
            let escaped = redact_resolved_temp_roots(&pattern_str.replace('|', "\\|"));
            let _ = writeln!(out, "| `{}` | `{escaped}` |", p.name);
        }
        out.push('\n');
    }

    // Destructive patterns (what's blocked)
    if !pack.destructive_patterns.is_empty() {
        out.push_str("### Destructive Patterns (Blocked)\n\n");
        out.push_str("These patterns match potentially destructive commands:\n\n");
        out.push_str("| Pattern Name | Reason | Severity |\n");
        out.push_str("|--------------|--------|----------|\n");
        for p in &pack.destructive_patterns {
            let name = p.name.unwrap_or("(unnamed)");
            let severity = p.severity.label();
            // Escape pipe characters
            let reason = p.reason.replace('|', "\\|");
            let _ = writeln!(out, "| `{name}` | {reason} | {severity} |");
        }
        out.push('\n');
    }

    // Allowlist guidance
    out.push_str("### Allowlist Guidance\n\n");
    out.push_str("To allowlist a specific rule from this pack, add to your allowlist:\n\n");
    out.push_str("```toml\n");
    out.push_str("[[allow]]\n");
    let _ = writeln!(out, "rule = \"{}:<pattern-name>\"", pack.id);
    out.push_str("reason = \"Your reason here\"\n");
    out.push_str("```\n\n");

    // Wildcard allowlist
    out.push_str("To allowlist all rules from this pack (use with caution):\n\n");
    out.push_str("```toml\n");
    out.push_str("[[allow]]\n");
    let _ = writeln!(out, "rule = \"{}:*\"", pack.id);
    out.push_str("reason = \"Your reason here\"\n");
    out.push_str("risk_acknowledged = true\n");
    out.push_str("```\n\n");

    out.push_str("---\n\n");

    out
}

/// Generate documentation for a category (all packs in that category).
fn generate_category_doc(category: &str, packs: &[&Pack]) -> String {
    let mut out = String::new();

    // Category header
    let category_title = match category {
        "core" => "Core Packs",
        "storage" => "Storage Packs",
        "remote" => "Remote Access Packs",
        "cicd" => "CI/CD Packs",
        "secrets" => "Secrets Management Packs",
        "platform" => "Platform Packs",
        "dns" => "DNS Packs",
        "email" => "Email Packs",
        "featureflags" => "Feature Flags Packs",
        "loadbalancer" => "Load Balancer Packs",
        "monitoring" => "Monitoring Packs",
        "payment" => "Payment Packs",
        "messaging" => "Messaging Packs",
        "search" => "Search Packs",
        "backup" => "Backup Packs",
        "database" => "Database Packs",
        "containers" => "Container Packs",
        "kubernetes" => "Kubernetes Packs",
        "cloud" => "Cloud Provider Packs",
        "cdn" => "CDN Packs",
        "apigateway" => "API Gateway Packs",
        "infrastructure" => "Infrastructure as Code Packs",
        "system" => "System Packs",
        "safe" => "Safe Packs",
        "strict_git" => "Strict Git Packs",
        "package_managers" => "Package Manager Packs",
        _ => category,
    };

    let _ = writeln!(out, "# {category_title}\n");
    let _ = writeln!(
        out,
        "This document describes packs in the `{category}` category.\n"
    );

    // Table of contents
    out.push_str("## Packs in this Category\n\n");
    for pack in packs {
        let anchor = pack.id.replace('.', "");
        let _ = writeln!(out, "- [{}](#{anchor})", pack.name);
    }
    out.push_str("\n---\n\n");

    // Individual pack sections
    for pack in packs {
        out.push_str(&generate_pack_section(pack));
    }

    out
}

/// Build every `docs/packs/*.md` file as (filename, content), doing no I/O.
///
/// The regenerator and the drift check both read this one function, so the
/// check cannot go green against content the writer would not produce.
fn generated_docs() -> BTreeMap<String, String> {
    let registry = PackRegistry::new();

    // Group packs by category
    let mut by_category: BTreeMap<String, Vec<&Pack>> = BTreeMap::new();
    for pack_id in registry.all_pack_ids() {
        let category = category_from_pack_id(pack_id).to_string();
        let pack = registry.get(pack_id).expect("pack should exist");
        by_category.entry(category).or_default().push(pack);
    }

    let mut docs: BTreeMap<String, String> = BTreeMap::new();

    // Generate per-category documentation
    for (category, packs) in &by_category {
        let content = generate_category_doc(category, packs);
        docs.insert(category_filename(category), content);
    }

    // Update index (README.md) with links to category files
    let mut index = String::new();
    index.push_str("# Pack Reference Documentation\n\n");
    index.push_str(
        "This directory contains detailed reference documentation for all dcg packs.\n\n",
    );
    index.push_str("## Quick Start\n\n");
    index.push_str("Enable packs in `~/.config/dcg/config.toml`:\n\n");
    index.push_str("```toml\n");
    index.push_str("[packs]\n");
    index.push_str("enabled = [\"kubernetes\", \"database\", \"containers\"]\n");
    index.push_str("```\n\n");
    index.push_str("## Categories\n\n");
    index.push_str("| Category | Packs | Description |\n");
    index.push_str("|----------|-------|-------------|\n");

    for (category, packs) in &by_category {
        let pack_names: Vec<&str> = packs.iter().map(|p| p.name).collect();
        let pack_count = packs.len();
        let first_packs: String = pack_names
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if pack_count > 3 { ", ..." } else { "" };
        let filename = category_filename(category);
        let _ = writeln!(
            index,
            "| [{category}]({filename}) | {pack_count} | {first_packs}{suffix} |"
        );
    }

    index.push_str("\n## All Pack IDs\n\n");
    for pack_id in registry.all_pack_ids() {
        let category = category_from_pack_id(pack_id);
        let filename = category_filename(category);
        let anchor = pack_id.replace('.', "");
        let _ = writeln!(index, "- [`{pack_id}`]({filename}#{anchor})");
    }

    index.push_str("\n## Notes\n\n");
    index.push_str("- Enable a whole category by specifying its prefix (e.g., `kubernetes`).\n");
    index.push_str(
        "- Heredoc/inline-script scanning is configured under `[heredoc]`, not `[packs]`.\n",
    );
    index.push_str("- See `docs/configuration.md` for full configuration details.\n");
    index.push_str("\n---\n\n");
    index.push_str("*This documentation is auto-generated from PackRegistry metadata.*\n");

    docs.insert("README.md".to_string(), index);

    docs
}

/// Write every generated doc into `docs/packs/`.
fn generate_all_docs() -> std::io::Result<()> {
    let docs_packs_dir = repo_root().join("docs/packs");

    // Ensure directory exists
    fs::create_dir_all(&docs_packs_dir)?;

    for (filename, content) in generated_docs() {
        fs::write(docs_packs_dir.join(&filename), &content)?;
        println!("Generated: docs/packs/{filename}");
    }

    Ok(())
}

#[test]
fn verify_all_packs_have_documentation() -> std::io::Result<()> {
    let registry = PackRegistry::new();
    let docs_packs_dir = repo_root().join("docs/packs");

    // Check each pack has a documentation entry
    let mut missing: Vec<String> = Vec::new();

    for pack_id in registry.all_pack_ids() {
        let category = category_from_pack_id(pack_id);
        let doc_path = docs_packs_dir.join(category_filename(category));

        if !doc_path.exists() {
            missing.push(format!(
                "Category doc missing for pack '{pack_id}': expected {}",
                doc_path.display()
            ));
            continue;
        }

        // Check the pack ID is mentioned in the doc
        let content = fs::read_to_string(&doc_path)?;
        if !content.contains(&format!("**Pack ID:** `{pack_id}`")) {
            missing.push(format!(
                "Pack '{pack_id}' not documented in {}",
                doc_path.display()
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "Documentation coverage issues:\n{}",
        missing.join("\n")
    );

    Ok(())
}

/// Describe the first line on which the checked-in doc and the generated one
/// disagree, so a failure names the drifted rule instead of "files differ".
fn first_difference(on_disk: &str, generated: &str) -> String {
    let mut disk_lines = on_disk.lines();
    let mut gen_lines = generated.lines();
    let mut lineno = 0usize;

    loop {
        lineno += 1;
        match (disk_lines.next(), gen_lines.next()) {
            (None, None) => return "files differ only in trailing bytes".to_string(),
            (Some(d), Some(g)) if d == g => {}
            (d, g) => {
                return format!(
                    "line {lineno}:\n      checked in: {}\n      generated:  {}",
                    d.unwrap_or("<end of file>"),
                    g.unwrap_or("<end of file>")
                );
            }
        }
    }
}

/// The docs are generated, so a pack edit that skips the regenerator must go
/// red here. Byte equality is what makes that true for rule names AND pattern
/// strings: `.agent-config-it2wk` narrowed every wildcard in the remote pack
/// and `docs/packs/remote.md` kept advertising the old regex for a day, past a
/// coverage test that only compared pack IDs (`.agent-config-phupc`).
#[test]
fn pack_docs_match_generated_content() -> std::io::Result<()> {
    let docs_packs_dir = repo_root().join("docs/packs");
    let generated = generated_docs();
    let mut stale: Vec<String> = Vec::new();

    for (filename, expected) in &generated {
        let path = docs_packs_dir.join(filename);
        let Ok(actual) = fs::read_to_string(&path) else {
            stale.push(format!("docs/packs/{filename}: missing"));
            continue;
        };
        if actual != *expected {
            stale.push(format!(
                "docs/packs/{filename}: {}",
                first_difference(&actual, expected)
            ));
        }
    }

    // A doc for a category the registry no longer has is stale in the other
    // direction: it documents rules that cannot fire.
    for entry in fs::read_dir(&docs_packs_dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_markdown = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_markdown && !generated.contains_key(&name) {
            stale.push(format!(
                "docs/packs/{name}: no pack category generates this file"
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "docs/packs is stale against PackRegistry — regenerate with \
         `cargo test --test generate_pack_docs -- --ignored`:\n  {}",
        stale.join("\n  ")
    );

    Ok(())
}

#[test]
#[ignore = "Run with `cargo test generate_pack_docs -- --ignored` to regenerate"]
fn regenerate_pack_docs() -> std::io::Result<()> {
    generate_all_docs()
}
