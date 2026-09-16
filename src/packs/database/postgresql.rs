//! `PostgreSQL` patterns - protections against destructive psql/pg commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE/SCHEMA commands
//! - TRUNCATE commands
//! - dropdb CLI command
//! - `pg_dump` with --clean flag

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `DROP DATABASE` pattern.
const DROP_DATABASE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -h {host} -U {user} {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new(
        "psql -c '\\l' | grep {dbname}",
        "Verify database name before dropping",
    ),
    PatternSuggestion::new(
        "SELECT datname FROM pg_database WHERE datname = '{dbname}'",
        "Check if database exists",
    ),
];

/// Suggestions for `DROP TABLE` pattern.
const DROP_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -t {tablename} {dbname} > table_backup.sql",
        "Backup the table before dropping",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check row count before dropping",
    ),
    PatternSuggestion::new("\\d {tablename}", "Review table structure (in psql)"),
    PatternSuggestion::new(
        "SELECT * FROM {tablename} LIMIT 10",
        "Preview table contents",
    ),
];

/// Suggestions for `DROP SCHEMA` pattern.
const DROP_SCHEMA_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -n {schema_name} {dbname} > schema_backup.sql",
        "Backup schema before dropping",
    ),
    PatternSuggestion::new(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = '{schema_name}'",
        "List all tables in the schema",
    ),
    PatternSuggestion::new(
        "DROP SCHEMA {schema_name} RESTRICT",
        "Use RESTRICT to fail if schema is not empty",
    ),
];

/// Suggestions for `TRUNCATE TABLE` pattern.
const TRUNCATE_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check how many rows would be deleted",
    ),
    PatternSuggestion::new(
        "BEGIN; TRUNCATE {tablename}; -- ROLLBACK or COMMIT",
        "Wrap in transaction for rollback capability",
    ),
    PatternSuggestion::new(
        "CREATE TABLE {tablename}_backup AS SELECT * FROM {tablename}",
        "Backup data before truncating",
    ),
];

/// Suggestions for `DELETE without WHERE` pattern.
const DELETE_WITHOUT_WHERE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "DELETE FROM {tablename} WHERE {condition}",
        "Add a WHERE clause to limit deletion",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check how many rows exist",
    ),
    PatternSuggestion::new(
        "TRUNCATE TABLE {tablename}",
        "Use TRUNCATE if you truly want all rows deleted (faster)",
    ),
    PatternSuggestion::new(
        "BEGIN; DELETE FROM {tablename}; -- ROLLBACK or COMMIT",
        "Wrap in transaction for rollback capability",
    ),
];

/// Suggestions for `dropdb` CLI pattern.
const DROPDB_CLI_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -h {host} -U {user} {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new("psql -c '\\l'", "List databases to verify the correct one"),
    PatternSuggestion::new(
        "psql -c 'SELECT pg_database_size(''{dbname}'') / 1024 / 1024 AS size_mb'",
        "Check database size before dropping",
    ),
];

/// Suggestions for `pg_dump --clean` pattern.
const PG_DUMP_CLEAN_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump {dbname} > backup.sql",
        "Create backup without DROP statements",
    ),
    PatternSuggestion::new(
        "createdb {newdb} && pg_restore -d {newdb} backup.dump",
        "Restore to a new database first, then verify",
    ),
];

/// Command words that let this pack be consulted at all.
///
/// The registry's `PackEntry` points at this same const. They used to be two
/// lists, and 26 of 80 packs had drifted: the pack claimed a keyword the
/// registry gate did not carry, so rules for those words could never run
/// (`.agent-config-x74pe`).
/// Includes the lowercase `drop`/`delete`/`truncate` the pack has always
/// carried. They also select this pack on prose that uses those words, and
/// one bead description in an 18,723-command population is denied that way
/// (`.agent-config-w22qy`) — but removing them would stop a lowercase SQL
/// statement reaching the rules at all, which is worse.
pub const KEYWORDS: &[&str] = &[
    "psql",
    "dropdb",
    "createdb",
    "pg_dump",
    "pg_restore",
    "DROP",
    "TRUNCATE",
    "DELETE",
    "postgres",
];

/// Create the `PostgreSQL` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.postgresql".to_string(),
        name: "PostgreSQL",
        description: "Protects against destructive PostgreSQL operations like DROP DATABASE, \
                      TRUNCATE, and dropdb",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // pg_dump without --clean is safe (backup only)
        safe_pattern!("pg-dump-no-clean", r"pg_dump\s+(?!.*--clean)(?!.*-c\b)"),
        // psql with --dry-run or explain
        safe_pattern!("psql-dry-run", r"psql\s+.*--dry-run"),
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // DROP DATABASE
        destructive_pattern!(
            "drop-database",
            r"(?i)\bDROP\s+DATABASE\b",
            "DROP DATABASE permanently deletes the entire database (even with IF EXISTS). Verify and back up first.",
            Critical,
            "DROP DATABASE completely removes a database and ALL its contents:\n\n\
             - All tables, views, and indexes\n\
             - All functions, procedures, and triggers\n\
             - All data - gone permanently\n\
             - Users/roles remain but lose access\n\n\
             IF EXISTS only prevents errors if the database doesn't exist - it still deletes!\n\n\
             Before dropping:\n  \
             pg_dump -h host -U user dbname > backup.sql\n\n\
             Verify database name:\n  \
             psql -c '\\l' | grep dbname",
            DROP_DATABASE_SUGGESTIONS
        ),
        // DROP TABLE
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and back up first.",
            High,
            "DROP TABLE removes the table structure and ALL data:\n\n\
             - All rows are deleted\n\
             - Indexes, constraints, triggers are removed\n\
             - Foreign keys referencing this table may fail\n\
             - CASCADE drops dependent objects too\n\n\
             IF EXISTS only prevents errors - it still drops the table!\n\n\
             Backup table first:\n  \
             pg_dump -t tablename dbname > table_backup.sql\n\n\
             Preview table contents:\n  \
             SELECT COUNT(*) FROM tablename;\n  \
             SELECT * FROM tablename LIMIT 10;",
            DROP_TABLE_SUGGESTIONS
        ),
        // DROP SCHEMA
        destructive_pattern!(
            "drop-schema",
            r"(?i)\bDROP\s+SCHEMA\b",
            "DROP SCHEMA permanently deletes the schema and all its objects (even with IF EXISTS).",
            Critical,
            "DROP SCHEMA removes a schema and potentially ALL objects within it:\n\n\
             - With CASCADE: Drops all tables, views, functions in the schema\n\
             - With RESTRICT (default): Fails if schema is not empty\n\
             - public schema deletion is catastrophic\n\n\
             List schema contents first:\n  \
             SELECT table_name FROM information_schema.tables \n  \
             WHERE table_schema = 'schema_name';\n\n\
             Backup schema:\n  \
             pg_dump -n schema_name dbname > schema_backup.sql",
            DROP_SCHEMA_SUGGESTIONS
        ),
        // TRUNCATE (faster than DELETE, no rollback)
        destructive_pattern!(
            "truncate-table",
            r"(?i)TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
            "TRUNCATE permanently deletes all rows without logging individual deletions.",
            High,
            "TRUNCATE is faster than DELETE but more dangerous:\n\n\
             - Removes ALL rows instantly\n\
             - Cannot be rolled back outside a transaction\n\
             - Does not fire DELETE triggers\n\
             - Resets IDENTITY/SERIAL columns\n\
             - CASCADE truncates referencing tables too\n\n\
             TRUNCATE is transactional in PostgreSQL. Wrap in transaction:\n  \
             BEGIN;\n  \
             TRUNCATE tablename;\n  \
             -- verify, then COMMIT or ROLLBACK\n\n\
             Check row count first:\n  \
             SELECT COUNT(*) FROM tablename;",
            TRUNCATE_TABLE_SUGGESTIONS
        ),
        // DELETE without WHERE (deletes all rows)
        destructive_pattern!(
            "delete-without-where",
            r#"(?i)DELETE\s+FROM\s+(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+")(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+"))?)\s*(?:;|$)"#,
            "DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally.",
            High,
            "DELETE without WHERE removes ALL rows from the table:\n\n\
             - Each row deletion is logged (slower than TRUNCATE)\n\
             - Can be rolled back within a transaction\n\
             - Fires DELETE triggers for each row\n\
             - Does not reset IDENTITY/SERIAL counters\n\n\
             If you meant to delete all rows, use TRUNCATE for speed.\n\
             Otherwise, add a WHERE clause:\n  \
             DELETE FROM tablename WHERE condition;\n\n\
             Preview what would be deleted:\n  \
             SELECT COUNT(*) FROM tablename;  -- all rows!\n  \
             SELECT * FROM tablename LIMIT 10;",
            DELETE_WITHOUT_WHERE_SUGGESTIONS
        ),
        // dropdb CLI command
        destructive_pattern!(
            "dropdb-cli",
            r"dropdb\s+",
            "dropdb permanently deletes the entire database. Verify the database name carefully.",
            Critical,
            "dropdb is the CLI equivalent of DROP DATABASE:\n\n\
             - Completely removes the database\n\
             - All data is lost permanently\n\
             - No confirmation prompt by default\n\
             - Cannot be undone\n\n\
             Triple-check the database name. Common mistake:\n  \
             dropdb myapp_production  # Oops, meant myapp_staging\n\n\
             Backup first:\n  \
             pg_dump -h host -U user dbname > backup.sql\n\n\
             List databases to verify:\n  \
             psql -c '\\l'",
            DROPDB_CLI_SUGGESTIONS
        ),
        // pg_dump with --clean (drops before creating)
        destructive_pattern!(
            "pg-dump-clean",
            r"pg_dump\s+.*(?:--clean|-c\b)",
            "pg_dump --clean drops objects before creating them. This can be destructive on restore.",
            High,
            "pg_dump --clean adds DROP statements to the backup file. On restore:\n\n\
             - DROP TABLE is run before CREATE TABLE\n\
             - Existing data is deleted before restore\n\
             - If restore fails partway, data may be lost\n\n\
             This is safe for backup, but dangerous when restoring to a database \
             with existing data you want to keep.\n\n\
             Safer approach for restoring:\n\
             - Restore to a new database first\n\
             - Verify the restore\n\
             - Then swap databases\n\n\
             Without --clean:\n  \
             pg_dump dbname > backup.sql  # Creates only, no drops",
            PG_DUMP_CLEAN_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    /// Pack selection must not key on ordinary English words.
    ///
    /// The gate carried lowercase `drop`/`delete`/`truncate`
    /// (`.agent-config-x74pe`), and byte-exact keyword matching then handed any
    /// prose containing those words to these `(?i)` rules: eight ordinary
    /// developer commands measured newly DENY (`.agent-config-w22qy`). A
    /// lowercase SQL statement a shell actually runs always arrives with its
    /// client, and every client word is still in the gate — which is what the
    /// controls below assert.
    #[test]
    fn the_gate_does_not_select_this_pack_on_prose() {
        let pack = super::create_pack();
        for cmd in [
            r#"python3 -c "print('drop table foo')""#,
            r#"node -e "const q='delete from sessions;'; console.log(q)""#,
            r#"ruby -e "puts 'truncate table logs'""#,
            r#"bash -c 'echo "drop table students"'"#,
            r"go test -run 'TestDropTable/truncate table'",
            r#"br create "the action audit log will truncate table rows older than 90 days""#,
        ] {
            assert!(
                !pack.might_match(cmd),
                "no PostgreSQL client here — the gate must not select this pack: {cmd}"
            );
        }
        // Controls: with a client on the line the gate still selects the pack
        // and the rules still fire, including on lowercase SQL. Without these,
        // emptying KEYWORDS would pass the assertions above.
        for cmd in [r"psql -c 'truncate table users'", r"dropdb appdb"] {
            assert!(
                pack.check(cmd).is_some(),
                "a real PostgreSQL destructive command must still be denied: {cmd}"
            );
        }
    }

    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_delete_without_where() {
        let pack = create_pack();
        assert_blocks(&pack, "DELETE FROM users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM public.users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM \"Users\";", "DELETE without WHERE");
        assert_blocks(
            &pack,
            "DELETE FROM \"Public\".\"Users\";",
            "DELETE without WHERE",
        );
        // A lowercase SQL statement only reaches a shell with its client:
        // the gate no longer carries bare `drop`/`delete`/`truncate`, because
        // those words select this pack on ordinary prose (.agent-config-w22qy).
        assert_blocks(
            &pack,
            "psql -c 'delete from users;'",
            "DELETE without WHERE",
        );

        // Should NOT block if WHERE clause is present
        assert_allows(&pack, "DELETE FROM users WHERE id = 1;");
        assert_allows(&pack, "DELETE FROM users WHERE active = false");
    }
}
