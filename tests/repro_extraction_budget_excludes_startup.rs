//! `.agent-config-uq1ui` — the extraction budget must measure the command's own
//! work, never one-time process startup.
//!
//! The seven extraction patterns are `LazyLock`s, so the first `extract_content`
//! call in a process compiles them. That compilation used to happen *inside* the
//! time budget, which made the first call 1679us in a debug build against every
//! later call's 2-4us — a 420x tax charged to whichever command went first.
//!
//! That is why three `repro_heredoc_indent` tests failed on CI (run 35062485196,
//! `Skipped([Timeout { elapsed_ms: 278, budget_ms: 50 }])` on a three-line
//! heredoc) and passed locally. nextest gives every test its own process, so
//! every test is "first" and every test pays; `cargo test` shares one process
//! per binary, so only one test pays and the rest run warm.
//!
//! A timeout is FAIL-OPEN (see the pipeline diagram in `src/heredoc.rs`), so the
//! production form of this bug is a real user's first guarded command having its
//! heredoc silently left unread on a busy machine.
//!
//! THIS TEST MUST BE THE ONLY TEST IN THIS FILE. It has to run in a cold
//! process to mean anything; a sibling test in the same binary would compile the
//! patterns first under `cargo test` and leave this one asserting nothing.

use destructive_command_guard::{ExtractionLimits, ExtractionResult, extract_content};

#[test]
fn first_call_in_a_process_does_not_pay_startup_from_its_budget() {
    // The exact input from the CI failure: three lines, microseconds of work.
    let cmd = "cat <<~EOF\nline1\n  EOF";

    // 1ms. Chosen to sit between the two measured populations: warm extraction
    // of this input is 2-4us (a ~250x margin, so scheduler noise cannot reach
    // it), while the startup compilation this test exists to keep out of the
    // budget measured 1679us — above this budget, so the defect trips the test.
    let limits = ExtractionLimits {
        timeout_ms: 1,
        ..ExtractionLimits::default()
    };

    let result = extract_content(cmd, &limits);

    match result {
        ExtractionResult::Extracted(contents) => {
            assert_eq!(contents.len(), 1, "expected exactly one heredoc body");
            assert_eq!(contents[0].content, "line1");
        }
        ExtractionResult::Skipped(ref reasons)
        | ExtractionResult::Partial {
            skipped: ref reasons,
            ..
        } if reasons.iter().any(|r| format!("{r:?}").contains("Timeout")) => {
            panic!(
                "a 22-byte heredoc exhausted a 1ms budget, so pattern compilation \
                 is being charged to the per-command budget again: {result:?}"
            );
        }
        other => panic!("expected Extracted, got {other:?}"),
    }
}
