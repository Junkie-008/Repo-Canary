"""SQLite persistence for Repo-Canary.

Replaces the old ``findings.json`` store with a queryable, indexed database.

Design notes
------------
- WAL journal mode so the dashboard can read while the engine writes.
- One short-lived connection per operation; SQLite connections are cheap and
  are not safe to share between the watchdog, enrichment and HTTP threads.
- Findings are inserted with ``ON CONFLICT(dedupe_key) DO NOTHING``. Replacing
  a row (``INSERT OR REPLACE``) would reset its id and drop enrichment fields.
- Timestamps are UTC ISO-8601 text, which sorts correctly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

from models import (
    FindingRecord,
    ProcessDetails,
    normalize_severity,
    severity_rank,
)

logger = logging.getLogger(__name__)

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
LEGACY_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MINUTE_LENGTH = 16  # len("YYYY-MM-DDTHH:MM")

# 2: SQLite store. 3: canary_baseline (additive, created by the schema script).
SCHEMA_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    exe_path   TEXT NOT NULL DEFAULT '',
    cmdline    TEXT NOT NULL DEFAULT '[]',
    username   TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (name, exe_path, cmdline)
);

CREATE TABLE IF NOT EXISTS known_hashes (
    sha256   TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    label    TEXT NOT NULL,
    source   TEXT,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canary_baseline (
    name        TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL CHECK (length(sha256) = 64),
    size        INTEGER NOT NULL,
    mtime_ns    INTEGER,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY,
    occurred_at        TEXT NOT NULL,
    severity           TEXT NOT NULL CHECK (severity IN
                          ('Confirmed Ransomware','Critical','High','Medium','Low','Info')),
    severity_rank      INTEGER NOT NULL,
    rule               TEXT NOT NULL CHECK (rule IN
                          ('hash_match','canary','mass_change','legacy')),
    trigger_rule       TEXT CHECK (trigger_rule IN ('canary','mass_change')),
    summary            TEXT NOT NULL,
    path               TEXT,
    event_type         TEXT,
    process_id         INTEGER REFERENCES processes(id) ON DELETE SET NULL,
    pid                INTEGER,
    attribution_method TEXT CHECK (attribution_method IN ('sysmon','heuristic','none')),
    file_sha256        TEXT,
    intel_label        TEXT,
    matched_hash       TEXT,
    report_path        TEXT,
    report_created_at  TEXT,
    source             TEXT NOT NULL DEFAULT 'engine'
                          CHECK (source IN ('engine','json_migration')),
    dedupe_key         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    UNIQUE (dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_findings_time      ON findings(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev       ON findings(severity, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_rule      ON findings(rule, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_process   ON findings(process_id);
CREATE INDEX IF NOT EXISTS idx_findings_sha256    ON findings(file_sha256);
CREATE INDEX IF NOT EXISTS idx_findings_sev_rank  ON findings(severity_rank DESC, occurred_at DESC);

CREATE TABLE IF NOT EXISTS event_counters (
    minute     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (minute, event_type)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS engine_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    started_at     TEXT,
    last_heartbeat TEXT,
    watch_dir      TEXT,
    version        TEXT
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def utc_minute(moment: Optional[datetime] = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M")


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse the formats this project writes, plus legacy local time."""

    if not value:
        return None

    text = value.strip()

    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1]).replace(tzinfo=timezone.utc)

        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        # Legacy findings.json used naive local time; interpret it as local.
        parsed = datetime.fromtimestamp(parsed.timestamp(), tz=timezone.utc)

    return parsed.astimezone(timezone.utc)


class FindingsDB:
    """All reads and writes for ``canary.db``."""

    def __init__(self, path: Path | str):
        self.path = Path(path)

    # ------------------------------------------------------------------
    # Schema / connection
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self.connection(write=True) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) "
                "VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            # Additive upgrades need no ALTER TABLE; future column changes must
            # add an explicit migration step here before bumping the version.
            conn.execute(
                "UPDATE schema_meta SET value = ? WHERE key = 'schema_version' "
                "AND CAST(value AS INTEGER) < ?",
                (str(SCHEMA_VERSION), SCHEMA_VERSION),
            )

    @contextmanager
    def connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=5.0)
        conn.row_factory = sqlite3.Row

        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")

            if not write:
                conn.execute("PRAGMA query_only=ON")

            yield conn

            if write:
                conn.commit()

        except BaseException:
            if write:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise

        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def insert_finding(self, record: FindingRecord) -> tuple[int, bool]:
        """Insert one finding. Returns ``(id, inserted)``.

        A duplicate dedupe_key is not an error: the existing row's id is
        returned with ``inserted=False`` so callers can skip enrichment.
        """

        created_at = utc_now()

        with self.connection(write=True) as conn:
            process_id = None
            pid = None

            if record.process is not None:
                process_id = self._upsert_process(conn, record.process, record.occurred_at)
                pid = record.process.pid

            cursor = conn.execute(
                """
                INSERT INTO findings (
                    occurred_at, severity, severity_rank, rule, trigger_rule,
                    summary, path, event_type, process_id, pid,
                    attribution_method, file_sha256, intel_label, matched_hash,
                    source, dedupe_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dedupe_key) DO NOTHING
                """,
                (
                    record.occurred_at,
                    normalize_severity(record.severity),
                    severity_rank(record.severity),
                    record.rule,
                    record.trigger_rule,
                    record.summary,
                    record.path,
                    record.event_type,
                    process_id,
                    pid,
                    record.attribution_method,
                    record.file_sha256,
                    record.intel_label,
                    record.matched_hash,
                    record.source,
                    record.dedupe_key,
                    created_at,
                ),
            )

            if cursor.rowcount == 1 and cursor.lastrowid:
                return int(cursor.lastrowid), True

            row = conn.execute(
                "SELECT id FROM findings WHERE dedupe_key = ?",
                (record.dedupe_key,),
            ).fetchone()

            return (int(row["id"]) if row else 0), False

    def enrich_finding(
        self,
        finding_id: int,
        *,
        process: Optional[ProcessDetails] = None,
        attribution_method: Optional[str] = None,
        file_sha256: Optional[str] = None,
        intel_label: Optional[str] = None,
        matched_hash: Optional[str] = None,
        severity: Optional[str] = None,
        rule: Optional[str] = None,
        trigger_rule: Optional[str] = None,
    ) -> None:
        """Add enrichment data after the finding is already durable.

        ``attribution_method='none'`` is meaningful, so None means "leave it".
        """

        assignments: list[str] = []
        values: list[Any] = []

        if attribution_method is not None:
            assignments.append("attribution_method = ?")
            values.append(attribution_method)

        if file_sha256 is not None:
            assignments.append("file_sha256 = ?")
            values.append(file_sha256)

        if intel_label is not None:
            assignments.append("intel_label = ?")
            values.append(intel_label)

        if matched_hash is not None:
            assignments.append("matched_hash = ?")
            values.append(matched_hash)

        if severity is not None:
            assignments.extend(["severity = ?", "severity_rank = ?"])
            values.extend([normalize_severity(severity), severity_rank(severity)])

        if rule is not None:
            assignments.append("rule = ?")
            values.append(rule)

        if trigger_rule is not None:
            assignments.append("trigger_rule = ?")
            values.append(trigger_rule)

        with self.connection(write=True) as conn:
            if process is not None:
                process_id = self._upsert_process(conn, process, utc_now())
                assignments.extend(["process_id = ?", "pid = ?"])
                values.extend([process_id, process.pid])

            if not assignments:
                return

            values.append(finding_id)
            conn.execute(
                f"UPDATE findings SET {', '.join(assignments)} WHERE id = ?",
                values,
            )

    def attach_report(self, finding_id: int, report_path: str) -> None:
        with self.connection(write=True) as conn:
            conn.execute(
                "UPDATE findings SET report_path = ?, report_created_at = ? "
                "WHERE id = ?",
                (report_path, utc_now(), finding_id),
            )

    def bump_event_counters(self, counts: dict[tuple[str, str], int]) -> None:
        """Add buffered per-minute event counts atomically."""

        if not counts:
            return

        rows = [
            (minute, event_type, count)
            for (minute, event_type), count in counts.items()
            if count
        ]

        if not rows:
            return

        with self.connection(write=True) as conn:
            conn.executemany(
                """
                INSERT INTO event_counters(minute, event_type, count)
                VALUES (?, ?, ?)
                ON CONFLICT(minute, event_type)
                DO UPDATE SET count = count + excluded.count
                """,
                rows,
            )

    def heartbeat(
        self,
        *,
        watch_dir: str,
        version: str,
        started_at: Optional[str] = None,
    ) -> None:
        with self.connection(write=True) as conn:
            conn.execute(
                """
                INSERT INTO engine_state (
                    id, started_at, last_heartbeat, watch_dir, version
                ) VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_heartbeat = excluded.last_heartbeat,
                    watch_dir      = excluded.watch_dir,
                    version        = excluded.version
                """,
                (started_at or utc_now(), utc_now(), watch_dir, version),
            )

    def replace_known_hashes(self, entries: Iterable[tuple[str, str, str]]) -> None:
        """Replace the local feed mirror. ``entries`` is (sha256, label, source)."""

        now = utc_now()

        with self.connection(write=True) as conn:
            conn.execute("DELETE FROM known_hashes")
            conn.executemany(
                "INSERT INTO known_hashes(sha256, label, source, added_at) "
                "VALUES (?, ?, ?, ?)",
                [(sha, label, source, now) for sha, label, source in entries],
            )

    @staticmethod
    def _baseline_rows(entries: Iterable[dict]) -> list[tuple]:
        now = utc_now()
        rows = []

        for entry in entries:
            rows.append(
                (
                    entry["name"],
                    entry["sha256"],
                    int(entry["size"]),
                    entry.get("mtime_ns"),
                    entry.get("captured_at") or now,
                )
            )

        return rows

    def replace_canary_baseline(self, entries: Iterable[dict]) -> None:
        """Replace every canary baseline row in one transaction."""

        rows = self._baseline_rows(entries)

        with self.connection(write=True) as conn:
            conn.execute("DELETE FROM canary_baseline")
            conn.executemany(
                "INSERT INTO canary_baseline(name, sha256, size, mtime_ns, captured_at) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )

    def upsert_canary_baseline(self, entries: Iterable[dict]) -> None:
        """Insert baseline rows, refreshing any that already exist."""

        rows = self._baseline_rows(entries)

        with self.connection(write=True) as conn:
            conn.executemany(
                """
                INSERT INTO canary_baseline(name, sha256, size, mtime_ns, captured_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    sha256      = excluded.sha256,
                    size        = excluded.size,
                    mtime_ns    = excluded.mtime_ns,
                    captured_at = excluded.captured_at
                """,
                rows,
            )

    def canary_baseline(self) -> dict[str, dict]:
        """Return the persisted baseline keyed by canary filename."""

        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM canary_baseline").fetchall()

        return {row["name"]: dict(row) for row in rows}

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_finding(self, finding_id: int) -> Optional[dict]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT f.*, p.name AS process_name, p.exe_path AS process_exe,
                       p.cmdline AS process_cmdline, p.username AS process_user
                FROM findings f
                LEFT JOIN processes p ON p.id = f.process_id
                WHERE f.id = ?
                """,
                (finding_id,),
            ).fetchone()

        return self._finding_row(row) if row else None

    def list_findings(
        self,
        *,
        severity: Optional[Sequence[str] | str] = None,
        rule: Optional[str] = None,
        query: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        where, params = self._filters(
            severity=severity,
            rule=rule,
            query=query,
            since=since,
            until=until,
        )

        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))

        sql = f"""
            SELECT f.*, p.name AS process_name, p.exe_path AS process_exe,
                   p.cmdline AS process_cmdline, p.username AS process_user
            FROM findings f
            LEFT JOIN processes p ON p.id = f.process_id
            {where}
            ORDER BY f.occurred_at DESC, f.id DESC
            LIMIT ? OFFSET ?
        """

        with self.connection() as conn:
            rows = conn.execute(sql, [*params, limit, offset]).fetchall()

        return [self._finding_row(row) for row in rows]

    def export_findings(
        self,
        *,
        severity: Optional[Sequence[str] | str] = None,
        rule: Optional[str] = None,
        query: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict]:
        """Return a bounded result set for CSV/JSONL export."""

        where, params = self._filters(
            severity=severity,
            rule=rule,
            query=query,
            since=since,
            until=until,
        )

        sql = f"""
            SELECT f.*, p.name AS process_name, p.exe_path AS process_exe,
                   p.cmdline AS process_cmdline, p.username AS process_user
            FROM findings f
            LEFT JOIN processes p ON p.id = f.process_id
            {where}
            ORDER BY f.occurred_at DESC, f.id DESC
            LIMIT ?
        """

        with self.connection() as conn:
            rows = conn.execute(
                sql, [*params, max(1, min(int(limit), 50000))]
            ).fetchall()

        return [self._finding_row(row) for row in rows]

    def count_findings(
        self,
        *,
        severity: Optional[Sequence[str] | str] = None,
        rule: Optional[str] = None,
        query: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> int:
        where, params = self._filters(
            severity=severity,
            rule=rule,
            query=query,
            since=since,
            until=until,
        )

        with self.connection() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS n FROM findings f {where}",
                params,
            ).fetchone()

        return int(row["n"]) if row else 0

    def stats(self, hours: int = 24) -> dict:
        since = (
            datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))
        ).strftime(TIME_FORMAT)

        with self.connection() as conn:
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings "
                "WHERE occurred_at >= ? GROUP BY severity",
                (since,),
            ).fetchall()

            by_rule = conn.execute(
                "SELECT rule, COUNT(*) AS n FROM findings "
                "WHERE occurred_at >= ? GROUP BY rule",
                (since,),
            ).fetchall()

            totals = conn.execute(
                "SELECT COUNT(*) AS n, MAX(occurred_at) AS last, "
                "COUNT(DISTINCT process_id) AS processes FROM findings"
            ).fetchone()

            latest = conn.execute(
                """
                SELECT f.*, p.name AS process_name, p.exe_path AS process_exe,
                       p.cmdline AS process_cmdline, p.username AS process_user
                FROM findings f
                LEFT JOIN processes p ON p.id = f.process_id
                ORDER BY f.occurred_at DESC, f.id DESC
                LIMIT 1
                """
            ).fetchone()

        return {
            "window_hours": int(hours),
            "by_severity": {row["severity"]: int(row["n"]) for row in by_severity},
            "by_rule": {row["rule"]: int(row["n"]) for row in by_rule},
            "total": int(totals["n"] or 0),
            "last_finding": totals["last"],
            "processes": int(totals["processes"] or 0),
            "latest": self._finding_row(latest) if latest else None,
        }

    def events_per_minute(self, minutes: int = 60) -> list[dict]:
        minutes = max(1, min(int(minutes), 24 * 60))
        end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        start = end - timedelta(minutes=minutes - 1)

        with self.connection() as conn:
            rows = conn.execute(
                "SELECT minute, event_type, count FROM event_counters "
                "WHERE minute >= ? AND minute <= ?",
                (utc_minute(start), utc_minute(end)),
            ).fetchall()

        buckets: dict[str, dict[str, int]] = {}

        for offset in range(minutes):
            key = utc_minute(start + timedelta(minutes=offset))
            buckets[key] = {
                "minute": key,
                "created": 0,
                "modified": 0,
                "deleted": 0,
                "moved": 0,
                "total": 0,
            }

        for row in rows:
            bucket = buckets.get(row["minute"])
            if bucket is None:
                continue

            event_type = str(row["event_type"]).lower()
            count = int(row["count"])

            if event_type in bucket:
                bucket[event_type] += count

            bucket["total"] += count

        return list(buckets.values())

    def top_processes(self, hours: int = 24, limit: int = 10) -> list[dict]:
        since = (
            datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))
        ).strftime(TIME_FORMAT)

        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT p.id, p.name, p.exe_path, COUNT(*) AS findings,
                       MAX(f.occurred_at) AS last_seen,
                       SUM(CASE WHEN f.severity_rank >= 4 THEN 1 ELSE 0 END) AS severe
                FROM findings f
                JOIN processes p ON p.id = f.process_id
                WHERE f.occurred_at >= ?
                GROUP BY p.id
                ORDER BY findings DESC, last_seen DESC
                LIMIT ?
                """,
                (since, max(1, min(int(limit), 50))),
            ).fetchall()

        return [dict(row) for row in rows]

    def process_heatmap(self, hours: int = 12, top: int = 8) -> dict:
        hours = max(1, min(int(hours), 72))
        top = max(1, min(int(top), 20))

        since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
        since = since_dt.strftime(TIME_FORMAT)

        with self.connection() as conn:
            processes = conn.execute(
                """
                SELECT p.id, p.name, COUNT(*) AS findings
                FROM findings f
                JOIN processes p ON p.id = f.process_id
                WHERE f.occurred_at >= ?
                GROUP BY p.id
                ORDER BY findings DESC
                LIMIT ?
                """,
                (since, top),
            ).fetchall()

            ids = [row["id"] for row in processes]
            cells = []

            if ids:
                placeholders = ",".join("?" for _ in ids)
                cells = conn.execute(
                    f"""
                    SELECT process_id, substr(occurred_at, 1, 13) AS hour,
                           COUNT(*) AS n
                    FROM findings
                    WHERE occurred_at >= ? AND process_id IN ({placeholders})
                    GROUP BY process_id, hour
                    """,
                    [since, *ids],
                ).fetchall()

        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hours_list = [
            (current_hour - timedelta(hours=offset)).strftime("%Y-%m-%dT%H")
            for offset in range(hours - 1, -1, -1)
        ]

        return {
            "hours": hours_list,
            "processes": [dict(row) for row in processes],
            "cells": [dict(row) for row in cells],
        }

    def engine_state(self) -> Optional[dict]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM engine_state WHERE id = 1").fetchone()

        if not row:
            return None

        data = dict(row)
        heartbeat = parse_timestamp(data.get("last_heartbeat") or "")

        data["heartbeat_age_seconds"] = (
            (datetime.now(timezone.utc) - heartbeat).total_seconds()
            if heartbeat
            else None
        )

        return data

    # ------------------------------------------------------------------
    # Migration / maintenance
    # ------------------------------------------------------------------

    def migrate_legacy_json(self, json_path: Path | str) -> int:
        """Import findings.json once. Returns the number of rows inserted."""

        json_path = Path(json_path)

        if not json_path.exists():
            return 0

        with self.connection(write=True) as conn:
            conn.execute("BEGIN IMMEDIATE")

            done = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'legacy_json_migrated'"
            ).fetchone()

            if done:
                return 0

            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
                logger.error("Legacy findings import skipped: %s", error)
                return 0

            if not isinstance(payload, list):
                logger.error("Legacy findings import skipped: not a JSON list")
                return 0

            inserted = 0

            for index, entry in enumerate(payload):
                if not isinstance(entry, dict):
                    continue

                summary = str(entry.get("summary") or "Migrated finding")
                severity = normalize_severity(entry.get("severity"))
                occurred = parse_timestamp(str(entry.get("time") or "")) or datetime.now(
                    timezone.utc
                )
                occurred_at = occurred.strftime(TIME_FORMAT)

                lowered = summary.lower()
                rule = (
                    "canary"
                    if "canary" in lowered
                    else "mass_change"
                    if "mass" in lowered
                    else "legacy"
                )

                dedupe_key = hashlib.sha256(
                    f"legacy|{index}|{occurred_at}|{summary}|{severity}".encode("utf-8")
                ).hexdigest()

                cursor = conn.execute(
                    """
                    INSERT INTO findings (
                        occurred_at, severity, severity_rank, rule, summary,
                        source, dedupe_key, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'json_migration', ?, ?)
                    ON CONFLICT(dedupe_key) DO NOTHING
                    """,
                    (
                        occurred_at,
                        severity,
                        severity_rank(severity),
                        rule,
                        summary,
                        dedupe_key,
                        utc_now(),
                    ),
                )
                inserted += cursor.rowcount

            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) "
                "VALUES ('legacy_json_migrated', ?)",
                (utc_now(),),
            )

        self._rename_migrated(json_path)
        logger.info("Migrated %d legacy findings from %s", inserted, json_path.name)
        return inserted

    def clear_findings(self) -> None:
        with self.connection(write=True) as conn:
            for table in ("findings", "event_counters", "processes", "engine_state"):
                conn.execute(f"DELETE FROM {table}")

            try:
                conn.execute(
                    "DELETE FROM sqlite_sequence "
                    "WHERE name IN ('findings', 'processes')"
                )
            except sqlite3.OperationalError:
                # No AUTOINCREMENT column, so sqlite_sequence does not exist.
                pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _upsert_process(
        conn: sqlite3.Connection,
        process: ProcessDetails,
        seen_at: str,
    ) -> int:
        exe_path = process.exe_path or ""
        cmdline = json.dumps(list(process.cmdline), ensure_ascii=False)

        row = conn.execute(
            "SELECT id FROM processes WHERE name = ? AND exe_path = ? AND cmdline = ?",
            (process.name, exe_path, cmdline),
        ).fetchone()

        if row:
            conn.execute(
                "UPDATE processes SET last_seen = ?, username = COALESCE(?, username) "
                "WHERE id = ?",
                (seen_at, process.username, row["id"]),
            )
            return int(row["id"])

        cursor = conn.execute(
            """
            INSERT INTO processes (name, exe_path, cmdline, username, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (process.name, exe_path, cmdline, process.username, seen_at, seen_at),
        )

        return int(cursor.lastrowid)

    @staticmethod
    def _filters(
        *,
        severity: Optional[Sequence[str] | str],
        rule: Optional[str],
        query: Optional[str],
        since: Optional[str],
        until: Optional[str],
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        if severity:
            values = (
                [severity]
                if isinstance(severity, str)
                else [value for value in severity if value]
            )
            values = [normalize_severity(value) for value in values]

            if values:
                placeholders = ",".join("?" for _ in values)
                clauses.append(f"f.severity IN ({placeholders})")
                params.extend(values)

        if rule:
            clauses.append("f.rule = ?")
            params.append(rule)

        if query:
            clauses.append(
                "(instr(lower(f.summary), lower(?)) > 0 "
                "OR instr(lower(COALESCE(f.path, '')), lower(?)) > 0 "
                "OR instr(lower(COALESCE(f.intel_label, '')), lower(?)) > 0)"
            )
            lowered = query.strip()
            params.extend([lowered, lowered, lowered])

        if since:
            clauses.append("f.occurred_at >= ?")
            params.append(since)

        if until:
            clauses.append("f.occurred_at <= ?")
            params.append(until)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    @staticmethod
    def _finding_row(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["severity_rank"] = int(data.get("severity_rank") or 0)

        cmdline = data.pop("process_cmdline", None)
        process_name = data.pop("process_name", None)
        process_exe = data.pop("process_exe", None)
        process_user = data.pop("process_user", None)

        if process_name or process_exe or process_user or cmdline:
            try:
                parsed_cmdline = json.loads(cmdline) if cmdline else []
            except json.JSONDecodeError:
                parsed_cmdline = [cmdline] if cmdline else []

            data["process"] = {
                "name": process_name,
                "exe_path": process_exe,
                "cmdline": parsed_cmdline,
                "username": process_user,
            }
        else:
            data["process"] = None

        return data

    @staticmethod
    def _rename_migrated(json_path: Path) -> None:
        target = json_path.with_name(json_path.name + ".migrated")

        if target.exists():
            target = json_path.with_name(
                f"{json_path.name}.migrated.{int(datetime.now().timestamp())}"
            )

        try:
            json_path.rename(target)
        except OSError as error:
            logger.warning("Could not rename %s: %s", json_path, error)
