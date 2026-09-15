//! Build script for `dcg`.
//!
//! Embeds build metadata (timestamp, git commit, rustc version) into the binary
//! for display in --version output and debugging.

use vergen_gix::{Build, Cargo, Emitter, Rustc};

fn main() {
    // Emit build metadata as environment variables at compile time
    let build = Build::builder().build_timestamp(true).build();
    let cargo = Cargo::builder().target_triple(true).build();
    let rustc = Rustc::builder().semver(true).build();

    let mut emitter = Emitter::default();

    // Add build, cargo, and rustc instructions if available
    if let Err(e) = emitter.add_instructions(&build) {
        eprintln!("cargo:warning=vergen build instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&cargo) {
        eprintln!("cargo:warning=vergen cargo instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&rustc) {
        eprintln!("cargo:warning=vergen rustc instructions failed: {e}");
    }

    // Emit all collected instructions
    if let Err(e) = emitter.emit() {
        eprintln!("cargo:warning=vergen emit failed: {e}");
    }

    // vergen narrows cargo's rerun set to build.rs plus VERGEN_IDEMPOTENT and
    // SOURCE_DATE_EPOCH, so editing src/ recompiles the binary WITHOUT re-running
    // this script: VERGEN_BUILD_TIMESTAMP stays frozen at whenever build.rs last
    // ran, and `dcg --version` reports a build date older than the binary it is
    // describing. Freshness after installing a fix is the one question --version
    // exists to answer, so widen the watch set back over the crate's own inputs.
    // (.agent-config-9gf4e)
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
