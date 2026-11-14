"""PDF incident reports.

Reports are generated on a background thread so neither the watchdog callback
nor the enrichment worker waits for PDF rendering. A throttle prevents a PDF
storm during a mass-change burst.

``fpdf2`` is imported lazily: if it is not installed the detector still runs,
it just logs that reporting is disabled.
"""

from __future__ import annotations

import logging
import os
import queue
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

FONT_CANDIDATES = (
    Path(__file__).resolve().parent.parent / "vendor" / "DejaVuSans.ttf",
)


class ReportThrottle:
    """Allow at most ``max_per_minute`` reports, and one per rule+path per window."""

    def __init__(self, max_per_minute: int = 12, dedupe_seconds: float = 60.0):
        self.max_per_minute = max(1, max_per_minute)
        self.dedupe_seconds = dedupe_seconds
        self._recent_calls: deque[float] = deque()
        self._keys: dict[tuple[str, Optional[str]], float] = {}

    def allow(self, rule: str, path: Optional[str], now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now

        while self._recent_calls and now - self._recent_calls[0] >= 60:
            self._recent_calls.popleft()

        if len(self._recent_calls) >= self.max_per_minute:
            return False

        key = (rule, os.path.normcase(path or ""))
        last = self._keys.get(key)

        if last is not None and now - last < self.dedupe_seconds:
            return False

        self._keys[key] = now
        self._recent_calls.append(now)

        if len(self._keys) > 2048:
            cutoff = now - self.dedupe_seconds
            self._keys = {
                stored_key: seen
                for stored_key, seen in self._keys.items()
                if seen >= cutoff
            }

        return True


class IncidentReporter:
    """Render one PDF per qualifying finding, asynchronously."""

    def __init__(
        self,
        db,
        report_dir: Path | str,
        *,
        enabled: bool = True,
        throttle: Optional[ReportThrottle] = None,
        engine_version: str = "2.0.0",
    ):
        self.db = db
        self.report_dir = Path(report_dir)
        self.enabled = enabled
        self.throttle = throttle or ReportThrottle()
        self.engine_version = engine_version
        self.hostname = socket.gethostname()

        self._queue: queue.Queue[Optional[int]] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return

        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(
            target=self._run,
            name="incident-reporter",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping.set()

        if self._thread is None:
            return

        self._queue.put(None)
        self._thread.join(timeout=timeout)
        self._thread = None

    def enqueue(self, finding_id: int) -> None:
        if self.enabled and not self._stopping.is_set():
            self._queue.put(finding_id)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while True:
            try:
                finding_id = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                continue

            if finding_id is None:
                return

            try:
                self._generate(finding_id)
            except Exception:  # noqa: BLE001 - reporting must never kill the worker
                logger.exception("Incident report failed for finding %s", finding_id)

    def _generate(self, finding_id: int) -> None:
        finding = self.db.get_finding(finding_id)

        if not finding or finding.get("report_path"):
            return

        if not self.throttle.allow(finding.get("rule", ""), finding.get("path")):
            logger.debug("Report throttled for finding %s", finding_id)
            return

        path = self._write_pdf(finding)

        if path is None:
            return

        self.db.attach_report(finding_id, str(path))
        logger.info("Incident report written: %s", path)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _write_pdf(self, finding: dict) -> Optional[Path]:
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("fpdf2 is not installed; PDF reporting disabled")
            self.enabled = False
            return None

        self.report_dir.mkdir(parents=True, exist_ok=True)

        stamp = (
            str(finding.get("occurred_at") or datetime.utcnow().isoformat())
            .replace(":", "-")
            .replace(".", "-")
        )
        target = self.report_dir / f"INC-{int(finding['id']):06d}-{stamp}.pdf"

        font_path = next((path for path in FONT_CANDIDATES if path.exists()), None)
        unicode_font = font_path is not None

        pdf = FPDF(format="A4", unit="mm")
        pdf.set_auto_page_break(auto=True, margin=18)

        if unicode_font:
            try:
                pdf.add_font("DejaVu", "", str(font_path))
                pdf.add_font("DejaVu", "B", str(font_path))
            except Exception:  # noqa: BLE001 - fall back to core fonts
                logger.exception("Could not load DejaVu font; using Helvetica")
                unicode_font = False

        def text(value) -> str:
            value = "-" if value is None or value == "" else str(value)
            return value if unicode_font else value.encode("latin-1", "replace").decode("latin-1")

        family = "DejaVu" if unicode_font else "Helvetica"

        pdf.add_page()
        pdf.set_font(family, "B", 18)
        pdf.cell(0, 10, text("Repo-Canary Incident Report"))
        pdf.ln(14)

        pdf.set_font(family, "", 10)
        pdf.cell(0, 5, text(f"Report ID: INC-{int(finding['id']):06d}"))
        pdf.ln(5)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 5, text(f"Generated: {generated} UTC"))
        pdf.ln(5)
        pdf.cell(0, 5, text(f"Host: {self.hostname}"))
        pdf.ln(10)

        self._section(pdf, family, text, "Detection")
        self._field(pdf, family, text, "Occurred (UTC)", finding.get("occurred_at"))
        self._field(pdf, family, text, "Severity", finding.get("severity"))
        self._field(pdf, family, text, "Rule", finding.get("rule"))
        self._field(pdf, family, text, "Trigger rule", finding.get("trigger_rule"))
        self._field(pdf, family, text, "Summary", finding.get("summary"))
        self._field(pdf, family, text, "Event type", finding.get("event_type"))
        pdf.ln(4)

        self._section(pdf, family, text, "File evidence")
        self._field(pdf, family, text, "Path", finding.get("path"))
        self._field(pdf, family, text, "SHA-256", finding.get("file_sha256"))
        self._field(pdf, family, text, "Intel label", finding.get("intel_label"))
        self._field(pdf, family, text, "Matched hash", finding.get("matched_hash"))
        pdf.ln(4)

        process = finding.get("process") or {}

        self._section(pdf, family, text, "Process attribution")
        self._field(pdf, family, text, "Method", finding.get("attribution_method"))
        self._field(pdf, family, text, "PID", finding.get("pid"))
        self._field(pdf, family, text, "Process", process.get("name"))
        self._field(pdf, family, text, "Executable", process.get("exe_path"))
        self._field(pdf, family, text, "User", process.get("username"))

        cmdline = process.get("cmdline") or []
        self._field(pdf, family, text, "Command line", " ".join(str(part) for part in cmdline))
        pdf.ln(4)

        self._section(pdf, family, text, "Engine")
        self._field(pdf, family, text, "Version", self.engine_version)
        self._field(pdf, family, text, "Finding source", finding.get("source"))

        pdf.output(str(target))

        return target

    @staticmethod
    def _section(pdf, family: str, text, title: str) -> None:
        pdf.set_font(family, "B", 12)
        pdf.cell(0, 8, text(title))
        pdf.ln(8)
        pdf.set_font(family, "", 10)

    @staticmethod
    def _field(pdf, family: str, text, label: str, value) -> None:
        pdf.set_font(family, "B", 10)
        pdf.cell(38, 6, text(f"{label}:"))
        pdf.set_font(family, "", 10)
        pdf.multi_cell(0, 6, text(value), new_x="LMARGIN", new_y="NEXT")
