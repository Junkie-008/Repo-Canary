#!/usr/bin/env python3
"""End-to-end check of the packaged demo.

Run by the container CI job after ``docker compose up -d --build`` and after
``simulate_ransomware.py`` has been executed inside the engine container. It
talks to the published dashboard over HTTP and inspects the running containers
with ``docker compose exec``, so it verifies the artifact the image actually
ships rather than the source tree.

This is not a pytest module: unit tests cannot see the image, its non-root user
or the shared volume. Run it by hand with the stack up and the drill done:

    python tests/ci_container_smoke.py
"""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE_URL = os.environ.get("REPO_CANARY_URL", "http://127.0.0.1:8000")
COMPOSE = os.environ.get("REPO_CANARY_COMPOSE", "docker compose").split()
LAB = "/data/lab"
WAIT_SECONDS = float(os.environ.get("REPO_CANARY_WAIT", "120"))

problems: list[str] = []
checks = 0


def check(condition: object, message: str) -> bool:
    global checks
    checks += 1

    if not condition:
        problems.append(message)
        print(f"[FAIL] {message}")

    return bool(condition)


def fetch(path: str) -> tuple[int, bytes, dict[str, str]]:
    with urllib.request.urlopen(BASE_URL + path, timeout=5) as response:
        return response.status, response.read(), dict(response.headers)


def in_engine(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*COMPOSE, "exec", "-T", "engine", *args],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=timeout,
    )


def findings_payload() -> dict:
    status, body, _ = fetch("/api/findings?limit=200")
    check(status == 200, f"/api/findings returned {status}")
    return json.loads(body)


def wait_for_findings(total: int = 4) -> dict:
    deadline = time.time() + WAIT_SECONDS
    payload: dict = {}
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            payload = findings_payload()

            if payload.get("total", 0) >= total:
                return payload
        except (OSError, ValueError, urllib.error.URLError) as error:
            last_error = error

        time.sleep(2)

    check(False, f"the drill produced fewer than {total} findings: {payload or last_error}")
    return payload


def wait_for_reports(items: list[dict]) -> list[dict]:
    """Reports are written asynchronously, so wait for every row to link one."""

    deadline = time.time() + WAIT_SECONDS

    while time.time() < deadline:
        if all(item.get("report_path") for item in items):
            return items

        time.sleep(2)
        items = findings_payload().get("items", [])

    return items


def main() -> int:
    payload = wait_for_findings()
    items = wait_for_reports(payload.get("items", []))

    # -- the engine and the dashboard share one volume and one heartbeat -----
    status, body, _ = fetch("/api/health")
    health = json.loads(body)
    check(status == 200 and health.get("ok") is True, "the health endpoint is not ok")
    check(health.get("engine_alive") is True, "the engine heartbeat is not alive")

    running = subprocess.run(
        [*COMPOSE, "ps", "--status", "running", "--services"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=30,
    ).stdout.split()
    check({"engine", "dashboard"} <= set(running), f"services not running: {running}")

    # -- the drill is detected, classified and attributed honestly -----------
    by_rule: dict[str, int] = {}

    for item in items:
        by_rule[item.get("rule", "")] = by_rule.get(item.get("rule", ""), 0) + 1

        check(
            str(item.get("path", "")).startswith(LAB),
            f"finding {item.get('id')} is outside the lab: {item.get('path')}",
        )
        check(
            item.get("attribution_method") != "sysmon",
            "Sysmon attribution is impossible in a container, yet a finding claims it",
        )

    check(by_rule.get("canary", 0) >= 3, f"expected 3 canary findings, saw {by_rule}")
    check(by_rule.get("mass_change", 0) >= 1, f"expected a mass-change finding, saw {by_rule}")

    # -- every finding has a real PDF inside the shared volume ---------------
    for item in items:
        path = item.get("report_path")

        if not check(bool(path), f"finding {item.get('id')} has no report"):
            continue

        written = in_engine("test", "-s", path)
        check(written.returncode == 0, f"report missing or empty: {path}")

        header = in_engine("head", "-c", "4", path)
        check(header.stdout == "%PDF", f"report is not a PDF: {path}")

    reports = in_engine("sh", "-c", f"ls -1 {LAB}/reports/*.pdf | wc -l")
    check(
        reports.returncode == 0 and int(reports.stdout.strip() or 0) >= len(items),
        f"expected at least {len(items)} report files, saw {reports.stdout.strip()!r}",
    )

    # -- the exports and the dashboard work from the published port ----------
    status, body, headers = fetch("/api/export?format=csv")
    check(status == 200, f"CSV export returned {status}")
    check(headers.get("Content-Type", "").startswith("text/csv"), "CSV export has the wrong type")
    check(body.startswith(b"\xef\xbb\xbf"), "CSV export lost its BOM")
    rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
    check(len(rows) >= len(items) + 1, f"CSV export has {len(rows) - 1} rows for {len(items)} findings")
    check("report_path" in rows[0], "CSV header is missing report_path")

    status, body, _ = fetch("/api/export?format=jsonl")
    lines = [json.loads(line) for line in body.decode("utf-8").splitlines() if line.strip()]
    check(status == 200 and len(lines) >= len(items), f"JSONL export has {len(lines)} rows")

    status, body, _ = fetch("/")
    check(status == 200 and b"chart.umd.min.js" in body, "the dashboard page is not served")
    check(b"Repo-Canary" in body or b"Repo Canary" in body or b"Ransomware" in body,
          "the dashboard page does not look like the real UI")

    try:
        fetch("/scripts/database.py")
        check(False, "the server exposes its own source files")
    except urllib.error.HTTPError as error:
        check(error.code == 404, f"/scripts/database.py returned {error.code}")

    status, body, _ = fetch("/findings.json")
    check(status == 200 and len(json.loads(body)) >= len(items), "the legacy JSON alias is stale")

    # -- storage and packaging invariants ------------------------------------
    journal = in_engine(
        "python",
        "-c",
        "import sqlite3; c = sqlite3.connect('/data/lab/canary.db'); "
        "print(c.execute('PRAGMA journal_mode').fetchone()[0])",
    )
    check(journal.stdout.strip() == "wal", f"SQLite is not in WAL mode: {journal.stdout.strip()!r}")

    user = in_engine("id", "-u")
    check(user.stdout.strip() == "10001", f"the engine does not run as the canary user: {user.stdout.strip()}")

    for stray in ("tests", "docs", ".git", ".venv"):
        absent = in_engine("test", "!", "-e", f"/app/{stray}")
        check(absent.returncode == 0, f"{stray} leaked into the runtime image")

    logs = subprocess.run(
        [*COMPOSE, "logs", "--no-color"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=60,
    ).stdout
    check("Traceback (most recent call last)" not in logs, "a container logged a traceback")

    print()
    print(f"{checks - len(problems)}/{checks} container checks passed")

    if problems:
        for problem in problems:
            print(f"- {problem}")
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as error:
        print(f"[FAIL] the demo is not reachable at {BASE_URL}: {error}")
        sys.exit(1)
