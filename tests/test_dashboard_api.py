import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from dashboard_server import DashboardApp, DashboardHandler
from database import FindingsDB, utc_minute, utc_now
from models import FindingRecord, ProcessDetails


@pytest.fixture()
def api(tmp_path: Path):
    db = FindingsDB(tmp_path / "canary.db")
    db.initialize()

    process = ProcessDetails(pid=4, name="explorer.exe")

    db.insert_finding(
        FindingRecord(
            occurred_at=utc_now(),
            summary="Canary file detected: _canary_01.txt",
            severity="Critical",
            rule="canary",
            trigger_rule="canary",
            path=r"C:\lab\_canary_01.txt",
            event_type="MODIFIED",
            process=process,
            attribution_method="sysmon",
        )
    )
    db.insert_finding(
        FindingRecord(
            occurred_at="2026-11-13T10:00:09.000000Z",
            summary="Mass-change detected: 12 events in 10 seconds",
            severity="High",
            rule="mass_change",
            trigger_rule="mass_change",
            path=r"C:\lab\file1.txt",
            event_type="MODIFIED",
        )
    )

    db.bump_event_counters({(utc_minute(), "created"): 2})
    db.heartbeat(watch_dir=r"C:\lab\testdata", version="2.0.0")

    handler = type("Handler", (DashboardHandler,), {"app": DashboardApp(db)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        yield base, db
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def get(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=5) as response:
        return response.status, dict(response.headers), response.read()


def test_findings_endpoint_paginates(api):
    base, _ = api

    status, _, body = get(base, "/api/findings?limit=1&offset=0")
    payload = json.loads(body)

    assert status == 200
    assert payload["total"] == 2
    assert len(payload["items"]) == 1
    assert payload["has_more"] is True
    assert payload["items"][0]["process"]["name"] == "explorer.exe"


def test_findings_endpoint_filters_by_severity(api):
    base, _ = api

    _, _, body = get(base, "/api/findings?severity=High")
    payload = json.loads(body)

    assert payload["total"] == 1
    assert payload["items"][0]["severity"] == "High"


def test_stats_and_health(api):
    base, _ = api

    _, _, stats_body = get(base, "/api/stats?hours=24")
    stats = json.loads(stats_body)

    assert stats["total"] == 2
    assert stats["by_severity"]["Critical"] == 1
    assert stats["engine"]["alive"] is True

    _, _, health_body = get(base, "/api/health")
    health = json.loads(health_body)

    assert health["ok"] is True
    assert health["engine_alive"] is True


def test_events_and_heatmap(api):
    base, _ = api

    _, _, events_body = get(base, "/api/events-per-minute?minutes=5")
    events = json.loads(events_body)

    assert len(events["buckets"]) == 5
    assert sum(bucket["total"] for bucket in events["buckets"]) == 2

    _, _, heatmap_body = get(base, "/api/process-heatmap?hours=12")
    heatmap = json.loads(heatmap_body)

    assert heatmap["processes"][0]["name"] == "explorer.exe"
    assert len(heatmap["hours"]) == 12


def test_export_csv_and_jsonl(api):
    base, _ = api

    status, headers, body = get(base, "/api/export?format=csv")

    assert status == 200
    assert "text/csv" in headers["Content-Type"]
    assert "attachment" in headers["Content-Disposition"]
    assert body.startswith(b"\xef\xbb\xbf\"id\"")
    assert b"Canary file detected" in body

    _, headers, jsonl = get(base, "/api/export?format=jsonl")

    assert "x-ndjson" in headers["Content-Type"]
    lines = [line for line in jsonl.decode("utf-8").splitlines() if line]
    assert len(lines) == 2
    assert json.loads(lines[0])["severity"] in {"Critical", "High"}


def test_legacy_findings_shape(api):
    base, _ = api

    _, _, body = get(base, "/findings.json")
    rows = json.loads(body)

    assert len(rows) == 2
    assert set(rows[0]) == {"time", "summary", "severity"}


def test_index_and_vendor_are_served(api):
    base, _ = api

    status, headers, body = get(base, "/index.html")

    assert status == 200
    assert "text/html" in headers["Content-Type"]
    assert b"Repo-Canary" in body

    status, headers, _ = get(base, "/vendor/chart.umd.min.js")

    assert status == 200
    assert "javascript" in headers["Content-Type"]


def test_source_files_are_not_served(api):
    base, _ = api

    with pytest.raises(urllib.error.HTTPError) as error:
        get(base, "/scripts/database.py")

    assert error.value.code == 404

    with pytest.raises(urllib.error.HTTPError) as error:
        get(base, "/vendor/../scripts/database.py")

    assert error.value.code == 404
