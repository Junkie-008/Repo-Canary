import json
from pathlib import Path

from findings_store import MAX_FINDINGS, load_findings, save_finding


def test_save_finding_creates_file_and_entry(tmp_path: Path):
    findings_file = tmp_path / "findings.json"

    entry = save_finding(
        "Canary file detected: _canary_01.txt",
        "Critical",
        findings_file=findings_file,
        timestamp="2026-01-02 03:04:05",
    )

    assert entry == {
        "time": "2026-01-02 03:04:05",
        "summary": "Canary file detected: _canary_01.txt",
        "severity": "Critical",
    }

    assert load_findings(findings_file) == [entry]


def test_save_finding_creates_missing_parent_folder(tmp_path: Path):
    findings_file = tmp_path / "lab" / "nested" / "findings.json"

    save_finding("first", "Info", findings_file=findings_file)

    assert findings_file.exists()
    assert len(load_findings(findings_file)) == 1


def test_findings_are_capped_at_the_latest_50(tmp_path: Path):
    findings_file = tmp_path / "findings.json"

    for index in range(MAX_FINDINGS + 5):
        save_finding(f"finding {index}", "High", findings_file=findings_file)

    data = load_findings(findings_file)

    assert len(data) == MAX_FINDINGS
    assert data[0]["summary"] == "finding 5"
    assert data[-1]["summary"] == f"finding {MAX_FINDINGS + 4}"


def test_invalid_json_is_treated_as_empty(tmp_path: Path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text("{not valid json", encoding="utf-8")

    assert load_findings(findings_file) == []

    save_finding("after corruption", "Info", findings_file=findings_file)

    assert load_findings(findings_file) == [
        {
            "time": load_findings(findings_file)[0]["time"],
            "summary": "after corruption",
            "severity": "Info",
        }
    ]


def test_non_list_json_is_treated_as_empty(tmp_path: Path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({"summary": "object"}), encoding="utf-8")

    assert load_findings(findings_file) == []


def test_missing_file_returns_empty_list(tmp_path: Path):
    assert load_findings(tmp_path / "absent.json") == []


def test_writes_leave_no_temporary_files(tmp_path: Path):
    findings_file = tmp_path / "findings.json"

    save_finding("one", "Info", findings_file=findings_file)
    save_finding("two", "High", findings_file=findings_file)

    leftovers = list(tmp_path.glob(".findings-*.tmp"))

    assert leftovers == []
    assert len(load_findings(findings_file)) == 2
