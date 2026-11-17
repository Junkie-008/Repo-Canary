import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import FindingsDB, utc_minute, utc_now
from models import FindingRecord, ProcessDetails


def make_db(tmp_path: Path) -> FindingsDB:
    db = FindingsDB(tmp_path / "canary.db")
    db.initialize()
    return db


def make_finding(**overrides) -> FindingRecord:
    data = {
        "occurred_at": utc_now(),
        "summary": "Canary file detected: _canary_01.txt",
        "severity": "Critical",
        "rule": "canary",
        "trigger_rule": "canary",
        "path": r"C:\lab\_canary_01.txt",
        "event_type": "MODIFIED",
    }
    data.update(overrides)
    return FindingRecord(**data)


def test_duplicate_finding_is_idempotent(tmp_path: Path):
    db = make_db(tmp_path)
    record = make_finding()

    first_id, inserted = db.insert_finding(record)
    second_id, second_inserted = db.insert_finding(record)

    assert inserted is True
    assert second_inserted is False
    assert first_id == second_id
    assert db.count_findings() == 1


def test_findings_in_different_seconds_are_distinct(tmp_path: Path):
    db = make_db(tmp_path)

    db.insert_finding(make_finding(occurred_at="2026-11-13T10:00:00.100000Z"))
    db.insert_finding(make_finding(occurred_at="2026-11-13T10:00:02.100000Z"))

    assert db.count_findings() == 2


def test_filters_and_pagination(tmp_path: Path):
    db = make_db(tmp_path)

    db.insert_finding(
        make_finding(
            summary="canary one",
            path=r"C:\lab\a.txt",
            occurred_at="2026-11-13T10:00:01.000000Z",
        )
    )
    db.insert_finding(
        make_finding(
            summary="mass change",
            severity="High",
            rule="mass_change",
            trigger_rule="mass_change",
            occurred_at="2026-11-13T10:00:02.000000Z",
        )
    )
    db.insert_finding(
        make_finding(
            summary="hash match",
            severity="Confirmed Ransomware",
            rule="hash_match",
            trigger_rule="canary",
            occurred_at="2026-11-13T10:00:03.000000Z",
        )
    )

    critical = db.list_findings(severity="Critical")
    assert len(critical) == 1
    assert critical[0]["summary"] == "canary one"

    page = db.list_findings(limit=1, offset=0)
    next_page = db.list_findings(limit=1, offset=1)

    assert page[0]["id"] != next_page[0]["id"]
    assert db.count_findings(severity="Critical") == 1
    assert db.count_findings(rule="hash_match") == 1

    stats = db.stats()
    assert stats["latest"]["summary"] == "hash match"


def test_search_matches_summary_path_and_intel(tmp_path: Path):
    db = make_db(tmp_path)

    db.insert_finding(
        make_finding(
            summary="Canary file detected: secret.txt",
            path=r"C:\lab\secret.txt",
        )
    )
    db.insert_finding(make_finding(summary="unrelated", path=r"C:\lab\other.txt"))

    assert db.count_findings(query="secret") == 1
    assert db.count_findings(query="other.txt") == 1
    assert db.count_findings(query="missing") == 0


def test_process_dimension_is_reused(tmp_path: Path):
    db = make_db(tmp_path)
    process = ProcessDetails(
        pid=42,
        name="explorer.exe",
        exe_path=r"C:\Windows\explorer.exe",
        cmdline=("explorer.exe",),
        username="lab\\user",
    )

    db.insert_finding(
        make_finding(path=r"C:\lab\one.txt", process=process)
    )
    db.insert_finding(
        make_finding(
            path=r"C:\lab\two.txt",
            # Relative to now: top_processes() uses a rolling 48-hour window.
            occurred_at=(datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            process=process,
        )
    )

    top = db.top_processes(hours=48)
    assert len(top) == 1
    assert top[0]["name"] == "explorer.exe"
    assert top[0]["findings"] == 2


def test_enrichment_upgrades_severity_and_attaches_process(tmp_path: Path):
    db = make_db(tmp_path)
    finding_id, _ = db.insert_finding(make_finding())

    process = ProcessDetails(pid=7, name="powershell.exe")
    digest = "a" * 64

    db.enrich_finding(
        finding_id,
        process=process,
        attribution_method="sysmon",
        file_sha256=digest,
        intel_label="known-ransomware",
        matched_hash=digest,
        severity="Confirmed Ransomware",
        rule="hash_match",
        trigger_rule="canary",
    )

    row = db.get_finding(finding_id)

    assert row["severity"] == "Confirmed Ransomware"
    assert row["severity_rank"] == 5
    assert row["rule"] == "hash_match"
    assert row["trigger_rule"] == "canary"
    assert row["attribution_method"] == "sysmon"
    assert row["process"]["name"] == "powershell.exe"
    assert row["file_sha256"] == digest


def test_event_counters_and_per_minute_series(tmp_path: Path):
    db = make_db(tmp_path)
    minute = utc_minute()

    db.bump_event_counters(
        {
            (minute, "created"): 3,
            (minute, "modified"): 2,
        }
    )

    buckets = db.events_per_minute(5)
    current = buckets[-1]

    assert current["minute"] == minute
    assert current["created"] == 3
    assert current["modified"] == 2
    assert current["total"] == 5


def test_legacy_json_migration(tmp_path: Path):
    legacy = tmp_path / "findings.json"
    legacy.write_text(
        json.dumps(
            [
                {
                    "time": "2026-01-02 03:04:05",
                    "summary": "Canary file detected: _canary_01.txt",
                    "severity": "Critical",
                },
                {
                    "time": "2026-01-02 03:04:06",
                    "summary": "Mass-change detected: 12 events in 10 seconds",
                    "severity": "High",
                },
            ]
        ),
        encoding="utf-8",
    )

    db = make_db(tmp_path)
    inserted = db.migrate_legacy_json(legacy)

    assert inserted == 2
    assert not legacy.exists()
    assert (tmp_path / "findings.json.migrated").exists()

    rows = db.list_findings(limit=10)
    assert {row["source"] for row in rows} == {"json_migration"}
    assert {row["rule"] for row in rows} == {"canary", "mass_change"}

    # A second run must be a no-op.
    assert db.migrate_legacy_json(tmp_path / "findings.json.migrated") == 0


def test_missing_legacy_json_is_a_noop(tmp_path: Path):
    db = make_db(tmp_path)
    assert db.migrate_legacy_json(tmp_path / "absent.json") == 0


def test_heartbeat_state(tmp_path: Path):
    db = make_db(tmp_path)
    db.heartbeat(watch_dir=r"C:\lab\testdata", version="2.0.0")

    state = db.engine_state()

    assert state["watch_dir"] == r"C:\lab\testdata"
    assert state["version"] == "2.0.0"
    assert state["heartbeat_age_seconds"] is not None
    assert state["heartbeat_age_seconds"] < 5


def test_clear_findings(tmp_path: Path):
    db = make_db(tmp_path)
    db.insert_finding(make_finding())
    db.bump_event_counters({(utc_minute(), "created"): 1})
    db.heartbeat(watch_dir="x", version="2.0.0")

    db.clear_findings()

    assert db.count_findings() == 0
    assert db.engine_state() is None
    assert all(bucket["total"] == 0 for bucket in db.events_per_minute(5))
