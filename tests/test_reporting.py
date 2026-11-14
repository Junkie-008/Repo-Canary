import time
from pathlib import Path

from database import FindingsDB, utc_now
from models import FindingRecord, ProcessDetails
from reporting import IncidentReporter, ReportThrottle


def make_db(tmp_path: Path) -> FindingsDB:
    db = FindingsDB(tmp_path / "canary.db")
    db.initialize()
    return db


def insert_finding(db: FindingsDB) -> int:
    finding_id, _ = db.insert_finding(
        FindingRecord(
            occurred_at=utc_now(),
            summary="Canary file detected: café → _canary_01.txt",
            severity="Critical",
            rule="canary",
            trigger_rule="canary",
            path=r"C:\lab\_canary_01.txt",
            event_type="MODIFIED",
            process=ProcessDetails(
                pid=4,
                name="explorer.exe",
                exe_path=r"C:\Windows\explorer.exe",
                cmdline=("explorer.exe",),
                username="lab\\user",
            ),
            attribution_method="sysmon",
        )
    )
    return finding_id


def wait_for_report(db: FindingsDB, finding_id: int, timeout: float = 5.0):
    deadline = time.time() + timeout
    row = None

    while time.time() < deadline:
        row = db.get_finding(finding_id)

        if row and row.get("report_path"):
            return row

        time.sleep(0.05)

    return row


def test_report_is_generated_and_attached(tmp_path: Path):
    db = make_db(tmp_path)
    finding_id = insert_finding(db)

    reporter = IncidentReporter(db, tmp_path / "reports")
    reporter.start()

    try:
        reporter.enqueue(finding_id)
        row = wait_for_report(db, finding_id)
    finally:
        reporter.stop()

    assert row is not None
    report = Path(row["report_path"])

    assert report.exists()
    assert report.read_bytes().startswith(b"%PDF")
    assert report.stat().st_size > 500


def test_reporter_disabled_does_nothing(tmp_path: Path):
    db = make_db(tmp_path)
    finding_id = insert_finding(db)

    reporter = IncidentReporter(db, tmp_path / "reports", enabled=False)
    reporter.start()
    reporter.enqueue(finding_id)
    reporter.stop()

    assert db.get_finding(finding_id)["report_path"] is None


def test_throttle_blocks_duplicate_rule_and_path():
    throttle = ReportThrottle(max_per_minute=10, dedupe_seconds=60)

    assert throttle.allow("canary", r"C:\lab\a.txt", now=100.0) is True
    assert throttle.allow("canary", r"C:\lab\a.txt", now=110.0) is False
    assert throttle.allow("canary", r"C:\lab\b.txt", now=111.0) is True


def test_throttle_caps_rate():
    throttle = ReportThrottle(max_per_minute=2, dedupe_seconds=0)

    assert throttle.allow("canary", "a", now=100.0) is True
    assert throttle.allow("canary", "b", now=101.0) is True
    assert throttle.allow("canary", "c", now=102.0) is False
    assert throttle.allow("canary", "d", now=161.0) is True
