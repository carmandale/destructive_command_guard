//! Common test utilities for DCG history E2E tests.
//!
//! This module provides shared infrastructure for testing history functionality:
//! - Isolated test databases via `TestDb`
//! - Test fixtures for realistic command data
//! - Logging utilities for debugging test failures
//!
//! # Usage
//!
//! ```ignore
//! mod common;
//! use common::db::TestDb;
//!
//! #[test]
//! fn my_test() {
//!     let test_db = TestDb::new();
//!     // Use test_db.db for testing...
//! }
//! ```

pub mod db;
pub mod fixtures;
pub mod logging;
/// Isolated spawning of the dcg binary. See the module docs — a harness
/// that inherits the developer's environment measures their config, not dcg.
pub mod spawn;
