# Database Packs

This document describes packs in the `database` category.

## Packs in this Category

- [PostgreSQL](#databasepostgresql)
- [MySQL/MariaDB](#databasemysql)
- [MongoDB](#databasemongodb)
- [Redis](#databaseredis)
- [SQLite](#databasesqlite)

---

## PostgreSQL

**Pack ID:** `database.postgresql`

Protects against destructive PostgreSQL operations like DROP DATABASE, TRUNCATE, and dropdb

### Keywords

Commands containing these keywords are checked against this pack:

- `psql`
- `dropdb`
- `createdb`
- `pg_dump`
- `pg_restore`
- `DROP`
- `TRUNCATE`
- `DELETE`
- `postgres`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `pg-dump-no-clean` | `pg_dump\s+(?!.*--clean)(?!.*-c\b)` |
| `psql-dry-run` | `psql\s+.*--dry-run` |
| `select-query` | `(?i)^\s*SELECT\s+` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | DROP DATABASE permanently deletes the entire database (even with IF EXISTS). Verify and back up first. | critical |
| `drop-table` | DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and back up first. | high |
| `drop-schema` | DROP SCHEMA permanently deletes the schema and all its objects (even with IF EXISTS). | critical |
| `truncate-table` | TRUNCATE permanently deletes all rows without logging individual deletions. | high |
| `delete-without-where` | DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally. | high |
| `dropdb-cli` | dropdb permanently deletes the entire database. Verify the database name carefully. | critical |
| `pg-dump-clean` | pg_dump --clean drops objects before creating them. This can be destructive on restore. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.postgresql:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.postgresql:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## MySQL/MariaDB

**Pack ID:** `database.mysql`

Protects against destructive MySQL/MariaDB operations like DROP DATABASE, TRUNCATE, and mysqladmin drop

### Keywords

Commands containing these keywords are checked against this pack:

- `mysql`
- `mysqldump`
- `DROP`
- `TRUNCATE`
- `DELETE`
- `mysqladmin`
- `mariadb`
- `GRANT`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `select-query` | `(?i)^\s*SELECT\s+` |
| `show-command` | `(?i)^\s*SHOW\s+` |
| `describe-query` | `(?i)^\s*(?:DESCRIBE\|DESC\|EXPLAIN)\s+` |
| `mysqldump-no-drop` | `mysqldump\s+(?!.*--add-drop-database)(?!.*--add-drop-table)` |
| `mysql-select` | `mysql\s+.*(?:-e\|--execute)\s*['"]?\s*SELECT` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | DROP DATABASE permanently deletes the entire database. Verify and back up first. | critical |
| `drop-table` | DROP TABLE permanently deletes the table. Verify and back up first. | high |
| `truncate-table` | TRUNCATE permanently deletes all rows. Cannot be rolled back in MySQL. | high |
| `delete-without-where` | DELETE without WHERE clause deletes ALL rows. Add a WHERE clause. | high |
| `mysqladmin-drop` | mysqladmin drop permanently deletes the database. Verify carefully. | critical |
| `mysqldump-add-drop-database` | mysqldump --add-drop-database drops the database before restore. | high |
| `mysqldump-add-drop-table` | mysqldump --add-drop-table drops tables before creating them on restore. | medium |
| `grant-all` | GRANT ALL ON *.* gives unrestricted access to all databases. | high |
| `drop-user` | DROP USER permanently removes the user account and all their privileges. | medium |
| `reset-master` | RESET MASTER deletes all binary logs and resets the binlog position. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.mysql:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.mysql:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## MongoDB

**Pack ID:** `database.mongodb`

Protects against destructive MongoDB operations like dropDatabase, dropCollection, and remove without criteria

### Keywords

Commands containing these keywords are checked against this pack:

- `mongo`
- `mongosh`
- `mongodump`
- `mongorestore`
- `dropDatabase`
- `dropCollection`
- `deleteMany`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `mongo-find` | `\.find\s*\(` |
| `mongo-count` | `\.count(?:Documents)?\s*\(` |
| `mongo-aggregate` | `\.aggregate\s*\(` |
| `mongodump-no-drop` | `mongodump\s+(?!.*--drop)` |
| `mongo-explain` | `\.explain\s*\(` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | dropDatabase permanently deletes the entire database. | critical |
| `drop-collection` | drop/dropCollection permanently deletes the collection. | high |
| `delete-all` | remove({}) or deleteMany({}) deletes ALL documents. Add filter criteria. | high |
| `mongorestore-drop` | mongorestore --drop deletes existing data before restoring. | high |
| `collection-drop` | collection.drop() permanently deletes the collection. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.mongodb:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.mongodb:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Redis

**Pack ID:** `database.redis`

Protects against destructive Redis operations like FLUSHALL, FLUSHDB, and mass key deletion

### Keywords

Commands containing these keywords are checked against this pack:

- `redis-cli`
- `FLUSHALL`
- `FLUSHDB`
- `DEBUG`
- `redis`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `redis-get` | `(?i)\b(?:GET\|MGET)\b` |
| `redis-scan` | `(?i)\bSCAN\b` |
| `redis-info` | `(?i)\bINFO\b` |
| `redis-keys` | `(?i)\bKEYS\b` |
| `redis-dbsize` | `(?i)\bDBSIZE\b` |
| `redis-config-get` | `(?i)\bCONFIG\s+GET\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `flushall` | FLUSHALL permanently deletes ALL keys in ALL databases. | critical |
| `flushdb` | FLUSHDB permanently deletes ALL keys in the current database. | high |
| `debug-crash` | DEBUG SEGFAULT/CRASH will crash the Redis server. | critical |
| `debug-sleep` | DEBUG SLEEP blocks the Redis server and can cause availability issues. | high |
| `shutdown` | SHUTDOWN stops the Redis server. Use carefully. | high |
| `config-dangerous` | CONFIG SET for dir/dbfilename/slaveof can be used for security attacks. | critical |
| `config-set-maxmemory` | CONFIG SET maxmemory can trigger immediate mass key eviction if new limit is below current usage. | critical |
| `config-set-maxmemory-policy` | CONFIG SET maxmemory-policy changes how Redis evicts keys, risking silent data loss. | critical |
| `config-set-save` | CONFIG SET save can disable RDB persistence entirely, risking data loss on restart. | high |
| `config-set-appendonly` | CONFIG SET appendonly can disable AOF persistence, risking data loss on restart. | high |
| `config-rewrite` | CONFIG REWRITE persists all runtime CONFIG SET changes to redis.conf permanently. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.redis:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.redis:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## SQLite

**Pack ID:** `database.sqlite`

Protects against destructive SQLite operations like DROP TABLE, DELETE without WHERE, and accidental data loss

### Keywords

Commands containing these keywords are checked against this pack:

- `sqlite3`
- `DROP`
- `DELETE`
- `TRUNCATE`
- `sqlite`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `select-query` | `(?i)^\s*SELECT\s+` |
| `dot-schema` | `\.schema` |
| `dot-tables` | `\.tables` |
| `dot-dump` | `\.dump` |
| `dot-backup` | `\.backup` |
| `explain` | `(?i)^\s*EXPLAIN\s+` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-table` | DROP TABLE permanently deletes the table (even with IF EXISTS). Verify it is intended. | critical |
| `delete-without-where` | DELETE without WHERE deletes ALL rows. Add a WHERE clause. | critical |
| `vacuum-into` | VACUUM INTO overwrites the target file if it exists. | medium |
| `sqlite3-stdin` | Running SQL from file could contain destructive commands. Review the file first. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.sqlite:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.sqlite:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

