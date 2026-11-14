import hashlib
import os
import sqlite3
from pathlib import Path

import lab_config
import reset_lab
from canary_integrity import (
    CANONICAL_SHA256,
    CanaryIntegrityMonitor,
    canonical_baseline_entries,
    lab_baseline_entries,
    scan_canaries,
    seed_entries_for,
)
from database import FindingsDB
from detection_rules import CANARY_FILES


def make_lab(tmp_path: Path) -> tuple[Path, FindingsDB]:
    test_dir = tmp_path / "testdata"
    db_path = tmp_path / "canary.db"

    reset_lab.reset(
        test_dir,
        db_path,
        tmp_path / "findings.json",
        clear_findings=False,
    )

    return test_dir, FindingsDB(db_path)


def kinds_by_name(states) -> dict[str, str]:
    return {state.name: state.kind or "ok" for state in states}


def test_reset_lab_persists_the_canary_baseline(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)

    baseline = db.canary_baseline()

    assert set(baseline) == CANARY_FILES

    for name in CANARY_FILES:
        data = (test_dir / name).read_bytes()
        assert baseline[name]["sha256"] == hashlib.sha256(data).hexdigest()
        assert baseline[name]["size"] == len(data)
        assert baseline[name]["mtime_ns"] == (test_dir / name).stat().st_mtime_ns


def test_canonical_baseline_matches_a_fresh_lab(tmp_path: Path):
    _, db = make_lab(tmp_path)
    stored = db.canary_baseline()

    for entry in canonical_baseline_entries():
        assert entry["sha256"] == CANONICAL_SHA256
        assert entry["sha256"] == stored[entry["name"]]["sha256"]


def test_healthy_lab_scans_clean(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)

    states = scan_canaries(test_dir, db.canary_baseline())

    assert len(states) == 3
    assert all(state.ok for state in states)


def test_scan_reports_modified_missing_and_touched(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)

    modified = test_dir / "_canary_01.txt"
    modified.write_text("tampered\n", encoding="utf-8")

    (test_dir / "_canary_02.txt").unlink()

    touched = test_dir / "_canary_03.txt"
    current = touched.stat().st_mtime_ns
    os.utime(touched, ns=(current + 10_000_000_000, current + 10_000_000_000))

    kinds = kinds_by_name(scan_canaries(test_dir, db.canary_baseline()))

    assert kinds["_canary_01.txt"] == "modified"
    assert kinds["_canary_02.txt"] == "missing"
    assert kinds["_canary_03.txt"] == "touched"


def test_seeding_accepts_legacy_crlf_but_not_tampering(tmp_path: Path):
    test_dir = tmp_path / "testdata"
    test_dir.mkdir()

    legacy = test_dir / "_canary_01.txt"
    legacy.write_bytes(lab_config.CANARY_TEXT.replace("\n", "\r\n").encode("utf-8"))

    tampered = test_dir / "_canary_02.txt"
    tampered.write_bytes(b"attacker was here\n")

    entries = {
        entry["name"]: entry
        for entry in seed_entries_for(
            test_dir, ["_canary_01.txt", "_canary_02.txt", "_canary_03.txt"]
        )
    }

    assert entries["_canary_01.txt"]["sha256"] == hashlib.sha256(
        legacy.read_bytes()
    ).hexdigest()
    assert entries["_canary_02.txt"]["sha256"] == CANONICAL_SHA256
    assert entries["_canary_03.txt"]["sha256"] == CANONICAL_SHA256

    kinds = kinds_by_name(scan_canaries(test_dir, entries))

    assert kinds["_canary_01.txt"] == "ok"
    assert kinds["_canary_02.txt"] == "modified"
    assert kinds["_canary_03.txt"] == "missing"


def test_missing_baseline_entry_is_reported(tmp_path: Path):
    test_dir, _ = make_lab(tmp_path)

    states = scan_canaries(test_dir, {})

    assert {state.kind for state in states} == {"unbaselined"}


def test_monitor_alerts_on_transition_and_suppresses_repeats(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)
    problems = []
    monitor = CanaryIntegrityMonitor(test_dir, db.canary_baseline, problems.append)

    assert monitor.scan(force=True) == []

    canary = test_dir / "_canary_01.txt"
    canary.write_text("tampered\n", encoding="utf-8")

    first = monitor.scan()
    second = monitor.scan()

    assert len(first) == 1
    assert first[0].name == "_canary_01.txt"
    assert first[0].kind == "modified"
    assert second == []

    canary.unlink()
    escalation = monitor.scan()

    assert len(escalation) == 1
    assert escalation[0].kind == "missing"

    # Restoring the canary and refreshing the baseline must clear the state.
    reset_lab.reset(test_dir, db.path, tmp_path / "findings.json")

    assert monitor.scan() == []
    assert len(problems) == 2


def test_monitor_does_not_duplicate_a_live_watchdog_alert(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)
    problems = []
    monitor = CanaryIntegrityMonitor(test_dir, db.canary_baseline, problems.append)
    canary = test_dir / "_canary_01.txt"

    monitor.scan(force=True)
    canary.write_text("tampered\n", encoding="utf-8")
    monitor.note_live_alert(canary)

    assert monitor.scan() == []
    assert monitor.scan() == []
    assert problems == []


def test_schema_upgrades_a_version_two_database(tmp_path: Path):
    db = FindingsDB(tmp_path / "canary.db")
    db.initialize()

    with sqlite3.connect(db.path) as conn:
        conn.execute("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'")

    db.initialize()

    with sqlite3.connect(db.path) as conn:
        version = conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='canary_baseline'"
        ).fetchone()

    assert version == "3"
    assert table is not None


def test_clearing_findings_keeps_the_baseline(tmp_path: Path):
    test_dir, db = make_lab(tmp_path)

    reset_lab.reset(
        test_dir,
        db.path,
        tmp_path / "findings.json",
        clear_findings=True,
    )

    assert db.count_findings() == 0
    assert set(db.canary_baseline()) == CANARY_FILES
