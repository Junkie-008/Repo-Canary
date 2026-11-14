# Database Design

*SQLite schema, indexes, integrity rules and migration from findings.json.*

## 1. Choice of store

The prototype wrote a JSON array and truncated it at 50 entries. That lost evidence, could not be queried, and corrupted on concurrent access. The current store is SQLite: a single canary.db file with no server to install, real transactions, indexes and a WAL mode that lets the engine write while the dashboard reads.

## 2. Connection settings

```
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
```

Every operation opens and closes its own connection. Nothing is shared across threads, so there is no cross-thread connection state to corrupt, and WAL keeps readers from blocking the writer.

## 3. Tables

| Table | Columns | Purpose |
| --- | --- | --- |
| schema_meta | key TEXT PK, value TEXT | Schema version and one-off migration flags. |
| processes | id, name, exe_path, cmdline, username, first_seen, last_seen | Normalised process dimension shared by findings; UNIQUE(name, exe_path, cmdline). |
| known_hashes | sha256 PK CHECK(length=64), label, source, added_at | Mirror of the local SHA-256 threat-intel feed. |
| findings | id, occurred_at, severity, severity_rank, rule, trigger_rule, summary, path, event_type, process_id, pid, attribution_method, file_sha256, intel_label, matched_hash, report_path, report_created_at, source, dedupe_key, created_at | One row per alert. CHECK constraints on severity, rule, attribution_method and source; UNIQUE(dedupe_key). |
| event_counters | minute, event_type, count | Buffered per-minute event volume for the dashboard chart; PRIMARY KEY(minute, event_type). |
| engine_state | id CHECK(id=1), started_at, last_heartbeat, watch_dir, version | Single-row heartbeat read by /api/health and the dashboard. |

## 4. Integrity rules

- severity is constrained to the six allowed values; severity_rank stores the numeric order.
- rule is one of hash_match, canary, mass_change or legacy; trigger_rule records which rule fired first.
- attribution_method is sysmon, heuristic or none - the column cannot claim an unnamed source.
- dedupe_key is UNIQUE, so a restart or a repeated alert cannot duplicate evidence.
- processes rows are de-duplicated by (name, exe_path, cmdline) and reused by foreign key.
- known_hashes enforces a 64-character SHA-256.

## 5. Indexes

| Index | Columns | Used for |
| --- | --- | --- |
| idx_findings_time | occurred_at DESC | Newest-first listing and pagination. |
| idx_findings_sev | severity, occurred_at DESC | Severity filters and the counters. |
| idx_findings_rule | rule, occurred_at DESC | Per-rule statistics. |
| idx_findings_process | process_id | Top-process and heatmap aggregation. |
| idx_findings_sha256 | file_sha256 | Threat-intel lookups for a hash. |
| idx_findings_sev_rank | severity_rank DESC, occurred_at DESC | Ordering by severity then time. |

## 6. Write path

The engine builds an in-memory finding record, derives a dedupe key from the rule, the path and a time bucket, and inserts with ON CONFLICT(dedupe_key) DO NOTHING. INSERT OR REPLACE is deliberately not used: it deletes and re-inserts the row, which resets the primary key and discards enrichment already attached to the evidence.

## 7. Migration

On startup the engine looks for a legacy findings.json beside the database. If present, each entry becomes a row with source='json_migration' and rule='legacy', and the file is renamed to findings.json.migrated. The original evidence file is never deleted.

## 8. Retention and backup

Evidence is append-only during operation. Backing up the lab means copying canary.db (plus the -wal and -shm files while the engine runs) and the reports directory. A retention policy is listed in the future scope; today nothing is pruned automatically.

## 9. Example queries

```
SELECT severity, COUNT(*) FROM findings GROUP BY severity;
SELECT occurred_at, rule, path, pid, attribution_method
  FROM findings WHERE severity = 'Critical'
  ORDER BY occurred_at DESC LIMIT 10;
SELECT p.name, COUNT(*) AS hits FROM findings f
  JOIN processes p ON p.id = f.process_id
  GROUP BY p.name ORDER BY hits DESC;
```
