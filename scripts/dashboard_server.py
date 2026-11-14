"""Serve the Repo-Canary dashboard and its read-only JSON API.

Only ``index.html`` and files under ``vendor/`` are exposed. The old server
served the whole repository root, which leaked scripts and ``.git/``.

Endpoints
---------
GET /api/findings            ?severity=&rule=&q=&since=&until=&limit=&offset=
GET /api/stats               ?hours=
GET /api/events-per-minute   ?minutes=
GET /api/top-processes       ?hours=&limit=
GET /api/process-heatmap     ?hours=&top=
GET /api/export              ?format=csv|jsonl + findings filters
GET /api/health
GET /findings.json           legacy 50-row shape for old consumers
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import mimetypes
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import lab_config
from database import FindingsDB
from logging_config import configure_logging

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_FILE = REPO_ROOT / "index.html"
VENDOR_DIR = REPO_ROOT / "vendor"

VERSION = "2.0.0"
HEARTBEAT_ALIVE_SECONDS = 20

logger = logging.getLogger("repo_canary.dashboard")

INDEX_HTML = b"<h1>Repo-Canary</h1><p>index.html is missing.</p>"


def _first(params: dict, name: str, default=None):
    values = params.get(name)
    return values[0] if values else default


def _integer(params: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(_first(params, name, default))
    except (TypeError, ValueError):
        return default

    return max(minimum, min(value, maximum))


def _severity_param(params: dict):
    raw = _first(params, "severity")

    if not raw:
        return None

    return [part.strip() for part in raw.split(",") if part.strip()]


def _filters(params: dict) -> dict:
    return {
        "severity": _severity_param(params),
        "rule": _first(params, "rule") or None,
        "query": _first(params, "q") or None,
        "since": _first(params, "since") or None,
        "until": _first(params, "until") or None,
    }


def _safe_value(value):
    """Neutralise spreadsheet formulas while keeping numbers/None intact."""

    if value is None or isinstance(value, (int, float)):
        return value

    text = str(value)

    if text[:1] in ("=", "+", "-", "@"):
        return "'" + text

    return text


class DashboardApp:
    """Data access for the HTTP layer."""

    def __init__(self, db: FindingsDB):
        self.db = db

    def findings(self, params: dict) -> dict:
        limit = _integer(params, "limit", 50, 1, 500)
        offset = _integer(params, "offset", 0, 0, 10_000_000)
        filters = _filters(params)

        items = self.db.list_findings(limit=limit, offset=offset, **filters)
        total = self.db.count_findings(**filters)

        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(items) < total,
        }

    def stats(self, params: dict) -> dict:
        hours = _integer(params, "hours", 24, 1, 24 * 30)
        payload = self.db.stats(hours=hours)
        payload["engine"] = self._engine_payload()
        return payload

    def events_per_minute(self, params: dict) -> dict:
        minutes = _integer(params, "minutes", 60, 1, 1440)
        return {"minutes": minutes, "buckets": self.db.events_per_minute(minutes)}

    def top_processes(self, params: dict) -> dict:
        hours = _integer(params, "hours", 24, 1, 24 * 30)
        limit = _integer(params, "limit", 10, 1, 50)
        return {"items": self.db.top_processes(hours=hours, limit=limit)}

    def process_heatmap(self, params: dict) -> dict:
        hours = _integer(params, "hours", 12, 1, 72)
        top = _integer(params, "top", 8, 1, 20)
        return self.db.process_heatmap(hours=hours, top=top)

    def export(self, params: dict) -> tuple[bytes, str, str]:
        fmt = (_first(params, "format") or "csv").lower()
        filters = _filters(params)

        rows = self.db.export_findings(limit=10000, **filters)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        if fmt == "jsonl":
            body = "\n".join(
                json.dumps(row, ensure_ascii=False, default=str) for row in rows
            ).encode("utf-8")

            return (
                body + (b"\n" if body else b""),
                "application/x-ndjson; charset=utf-8",
                f"repo-canary-findings-{stamp}.jsonl",
            )

        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)

        writer.writerow(
            [
                "id",
                "occurred_at",
                "severity",
                "rule",
                "summary",
                "path",
                "event_type",
                "pid",
                "attribution_method",
                "process_name",
                "process_exe",
                "process_user",
                "file_sha256",
                "intel_label",
                "report_path",
            ]
        )

        for row in rows:
            process = row.get("process") or {}
            writer.writerow(
                [_safe_value(value) for value in [
                    row.get("id"),
                    row.get("occurred_at"),
                    row.get("severity"),
                    row.get("rule"),
                    row.get("summary"),
                    row.get("path"),
                    row.get("event_type"),
                    row.get("pid"),
                    row.get("attribution_method"),
                    process.get("name"),
                    process.get("exe_path"),
                    process.get("username"),
                    row.get("file_sha256"),
                    row.get("intel_label"),
                    row.get("report_path"),
                ]]
            )

        # The BOM keeps Excel happy on Windows.
        body = ("\ufeff" + buffer.getvalue()).encode("utf-8")

        return (
            body,
            "text/csv; charset=utf-8",
            f"repo-canary-findings-{stamp}.csv",
        )

    def health(self) -> dict:
        engine = self._engine_payload()
        return {
            "ok": True,
            "version": VERSION,
            "database": str(self.db.path),
            "engine": engine,
            "engine_alive": bool(engine and engine.get("alive")),
        }

    def legacy_findings(self) -> list[dict]:
        rows = self.db.list_findings(limit=50, offset=0)

        return [
            {
                "time": row.get("occurred_at"),
                "summary": row.get("summary"),
                "severity": row.get("severity"),
            }
            for row in rows
        ]

    def _engine_payload(self) -> dict | None:
        state = self.db.engine_state()

        if not state:
            return None

        age = state.get("heartbeat_age_seconds")
        state["alive"] = age is not None and age < HEARTBEAT_ALIVE_SECONDS
        return state


class DashboardHandler(BaseHTTPRequestHandler):
    app: DashboardApp

    protocol_version = "HTTP/1.1"
    server_version = "RepoCanaryDashboard/" + VERSION

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        route = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=False)

        try:
            if route in ("/", "/index.html"):
                self._send_index()
                return

            if route.startswith("/vendor/"):
                self._send_vendor(route.removeprefix("/vendor/"))
                return

            if route == "/findings.json":
                self._send_json(self.app.legacy_findings())
                return

            if route == "/api/health":
                self._send_json(self.app.health())
                return

            if route == "/api/findings":
                self._send_json(self.app.findings(params))
                return

            if route == "/api/stats":
                self._send_json(self.app.stats(params))
                return

            if route == "/api/events-per-minute":
                self._send_json(self.app.events_per_minute(params))
                return

            if route == "/api/top-processes":
                self._send_json(self.app.top_processes(params))
                return

            if route == "/api/process-heatmap":
                self._send_json(self.app.process_heatmap(params))
                return

            if route == "/api/export":
                body, content_type, filename = self.app.export(params)
                self._send_bytes(
                    body,
                    content_type,
                    extra_headers={
                        "Content-Disposition": f'attachment; filename="{filename}"'
                    },
                )
                return

            self._send_json({"error": "not found"}, status=404)

        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            logger.exception("Dashboard request failed: %s", self.path)
            try:
                self._send_json({"error": "internal server error"}, status=500)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Responses
    # ------------------------------------------------------------------

    def _send_index(self) -> None:
        try:
            body = INDEX_FILE.read_bytes()
        except OSError:
            body = INDEX_HTML

        self._send_bytes(body, "text/html; charset=utf-8")

    def _send_vendor(self, relative: str) -> None:
        relative = relative.split("?", 1)[0]
        candidate = (VENDOR_DIR / relative).resolve()

        if VENDOR_DIR.resolve() not in candidate.parents:
            self._send_json({"error": "not found"}, status=404)
            return

        if candidate.suffix.lower() not in {".js", ".css", ".map", ".woff2"}:
            self._send_json({"error": "not found"}, status=404)
            return

        try:
            body = candidate.read_bytes()
        except OSError:
            self._send_json({"error": "not found"}, status=404)
            return

        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self._send_bytes(body, content_type)

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status=status)

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        *,
        status: int = 200,
        extra_headers: dict | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - base class signature
        logger.debug("%s - %s", self.address_string(), format % args)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Serve the Repo-Canary dashboard",
    )

    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")

    parser.add_argument(
        "--db-path",
        default=None,
        help=f"SQLite database (default: {lab_config.DB_FILE})",
    )

    parser.add_argument(
        "--findings",
        default=None,
        help="deprecated: legacy findings.json; the DB is expected beside it",
    )

    parser.add_argument(
        "--log-file",
        default=str(lab_config.ERROR_LOG),
        help=f"error log path (default: {lab_config.ERROR_LOG})",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"Repo-Canary {VERSION}",
    )

    return parser.parse_args(argv)


def resolve_db_path(args) -> Path:
    if args.db_path:
        return Path(args.db_path)

    if args.findings:
        return Path(args.findings).with_suffix(".db")

    return Path(lab_config.DB_FILE)


def main(argv=None) -> int:

    args = parse_args(argv)
    configure_logging(args.log_file)

    db_path = resolve_db_path(args)
    db = FindingsDB(db_path)

    try:
        db.initialize()
    except Exception:  # noqa: BLE001
        logger.exception("Could not open the database at %s", db_path)
        return 1

    app = DashboardApp(db)

    handler = type("Handler", (DashboardHandler,), {"app": app})

    server = ThreadingHTTPServer((args.host, args.port), handler)
    server.daemon_threads = True

    print("=" * 65)
    print("        RANSOMWARE 207 - DASHBOARD SERVER")
    print("=" * 65)
    print(f"Dashboard: http://{args.host}:{args.port}/index.html")
    print(f"Database:  {db_path}")
    print("Press CTRL+C to stop.")
    print("=" * 65, flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopping dashboard server...")
    finally:
        # serve_forever() has already returned; calling shutdown() here would
        # block forever (it waits for the serve loop to stop).
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
