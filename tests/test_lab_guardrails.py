from pathlib import Path

import reset_lab
import simulate_ransomware
from database import FindingsDB, utc_now
from models import FindingRecord


def test_reset_creates_marker_canaries_and_files(tmp_path: Path):
    test_dir = tmp_path / "testdata"
    db_path = tmp_path / "canary.db"

    removed, written = reset_lab.reset(
        test_dir,
        db_path,
        tmp_path / "findings.json",
        clear_findings=False,
    )

    assert removed == []
    assert len(written) == 23
    assert (test_dir / ".repo-canary-lab").is_file()
    assert (test_dir / "_canary_01.txt").is_file()
    assert len(list(test_dir.glob("file*.txt"))) == 20


def test_reset_clears_database(tmp_path: Path):
    test_dir = tmp_path / "testdata"
    db_path = tmp_path / "canary.db"

    db = FindingsDB(db_path)
    db.initialize()
    db.insert_finding(
        FindingRecord(
            occurred_at=utc_now(),
            summary="old finding",
            severity="Critical",
            rule="canary",
            path="x",
        )
    )

    reset_lab.reset(test_dir, db_path, tmp_path / "findings.json", clear_findings=True)

    assert db.count_findings() == 0


def test_simulator_refuses_unmarked_folder(tmp_path: Path):
    (tmp_path / "real_document.txt").write_text("important", encoding="utf-8")

    exit_code = simulate_ransomware.main(["--test-dir", str(tmp_path), "--yes"])

    assert exit_code == 2
    assert (tmp_path / "real_document.txt").read_text(encoding="utf-8") == "important"


def test_simulator_dry_run_changes_nothing(tmp_path: Path):
    (tmp_path / ".repo-canary-lab").write_text("lab", encoding="utf-8")
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")

    exit_code = simulate_ransomware.main(
        ["--test-dir", str(tmp_path), "--dry-run", "--yes"]
    )

    assert exit_code == 0
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "hello"
    assert not (tmp_path / "a.txt.locked").exists()


def test_simulator_only_touches_txt(tmp_path: Path):
    (tmp_path / ".repo-canary-lab").write_text("lab", encoding="utf-8")
    (tmp_path / "a.txt").write_text("abc", encoding="utf-8")
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")

    exit_code = simulate_ransomware.main(["--test-dir", str(tmp_path), "--yes"])

    assert exit_code == 0
    assert (tmp_path / "a.txt.locked").read_text(encoding="utf-8") == "cba"
    assert (tmp_path / "binary.bin").read_bytes() == b"\x00\x01\x02"
