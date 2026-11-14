"""Repo-Canary detection engine.

Watches the lab folder with watchdog, applies the canary and mass-change
rules, persists findings into SQLite, enriches them asynchronously (Sysmon
attribution, SHA-256 threat intel), and queues PDF incident reports.

Usage
-----
    python scripts/detection_engine.py
    python scripts/detection_engine.py --test-dir <folder> --db-path <file>

The default folder is ``C:\\RansomwareLab\\testdata``. Override it with the
arguments above or the environment variables documented in lab_config.py.
"""

from __future__ import annotations

import argparse
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import signal
import sys

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import lab_config
from attribution import build_attributor
from database import FindingsDB, utc_minute, utc_now
from detection_rules import (
    CANARY_FILES,
    DEBOUNCE_SECONDS,
    RATE_THRESHOLD,
    RATE_WINDOW_SECONDS,
    Alert,
    DetectionRules,
)
from logging_config import configure_logging
from models import FindingRecord, IntelResult
from reporting import IncidentReporter, ReportThrottle
from threat_intel import ThreatIntel

VERSION = "2.0.0"
COUNTER_FLUSH_SECONDS = 2.0
HEARTBEAT_SECONDS = 5.0

EVENT_TYPE_MAP = {
    "CREATED": "created",
    "MODIFIED": "modified",
    "DELETED": "deleted",
    "MOVED": "moved",
    "MOVED_TO": "moved",
}

logger = logging.getLogger("repo_canary.engine")


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def configure_output() -> None:
    """Make alert output safe when stdout is redirected or not UTF-8."""

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
            )
        except (AttributeError, ValueError, OSError):
            pass


# ============================================================
# BUFFERED EVENT COUNTERS
# ============================================================


class EventCounters:
    """Buffer per-minute event counts and flush them in batches."""

    def __init__(self, db: FindingsDB, flush_seconds: float = COUNTER_FLUSH_SECONDS):
        self.db = db
        self.flush_seconds = flush_seconds
        self._counts: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def increment(self, event_type: str, moment: datetime | None = None) -> None:
        key = (utc_minute(moment), EVENT_TYPE_MAP.get(event_type, event_type.lower()))

        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1

    def flush(self) -> None:
        with self._lock:
            batch = self._counts
            self._counts = {}

        if not batch:
            return

        try:
            self.db.bump_event_counters(batch)
        except Exception:  # noqa: BLE001 - counters must not kill the engine
            logger.exception("Could not flush event counters")

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name="event-counters",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

        self.flush()

    def _run(self) -> None:
        while not self._stop.wait(self.flush_seconds):
            self.flush()


# ============================================================
# ENRICHMENT
# ============================================================


class EnrichmentWorker:
    """Add process attribution, hashes and intel labels after persistence."""

    def __init__(
        self,
        db: FindingsDB,
        attributor,
        intel: ThreatIntel,
        reporter: IncidentReporter,
        max_queue: int = 1000,
    ):
        self.db = db
        self.attributor = attributor
        self.intel = intel
        self.reporter = reporter
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dropped = 0

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name="finding-enricher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=10.0)
            self._thread = None

        if self._dropped:
            logger.warning("Dropped %d enrichment jobs under load", self._dropped)

    def submit(
        self,
        finding_id: int,
        path: str | None,
        occurred_epoch: float,
        trigger_rule: str,
    ) -> None:
        try:
            self._queue.put_nowait((finding_id, path, occurred_epoch, trigger_rule))
        except queue.Full:
            self._dropped += 1
            logger.error("Enrichment queue full; dropped finding %s", finding_id)

    def _run(self) -> None:
        while True:
            try:
                job = self._queue.get(timeout=0.2)
            except queue.Empty:
                # Drain anything already queued before exiting.
                if self._stop.is_set():
                    return
                continue

            try:
                self._process(*job)
            except Exception:  # noqa: BLE001 - enrichment must never kill the worker
                logger.exception("Enrichment failed for finding %s", job[0])

    def _process(
        self,
        finding_id: int,
        path: str | None,
        occurred_epoch: float,
        trigger_rule: str,
    ) -> None:
        occurred = (
            datetime.fromtimestamp(occurred_epoch, tz=timezone.utc)
            if occurred_epoch
            else datetime.now(timezone.utc)
        )

        process, method = self.attributor.lookup(path or "", occurred)
        intel = IntelResult()

        if path:
            intel = self.intel.check(path)

            if intel.error:
                logger.debug("Threat-intel check for %s: %s", path, intel.error)

        if process is not None:
            logger.info(
                "Attributed %s to %s (pid %s, method %s)",
                Path(path).name if path else "?",
                process.name,
                process.pid,
                method,
            )

        updates = {
            "process": process,
            "attribution_method": method,
            "file_sha256": intel.sha256,
        }

        if intel.matched:
            updates.update(
                {
                    "severity": "Confirmed Ransomware",
                    "rule": "hash_match",
                    "trigger_rule": trigger_rule,
                    "intel_label": intel.label,
                    "matched_hash": intel.sha256,
                }
            )

            logger.warning(
                "Hash match on %s: %s", path, intel.label
            )

        self.db.enrich_finding(finding_id, **updates)
        self.reporter.enqueue(finding_id)


# ============================================================
# DETECTOR
# ============================================================


class RansomwareDetector(FileSystemEventHandler):

    def __init__(
        self,
        db: FindingsDB,
        enricher: EnrichmentWorker,
        counters: EventCounters,
    ):
        super().__init__()
        self.rules = DetectionRules()
        self.db = db
        self.enricher = enricher
        self.counters = counters

    # --------------------------------------------------------
    # Alerts
    # --------------------------------------------------------

    def print_alert(self, alert: Alert) -> None:
        print()
        print("=" * 65)

        if alert.severity == "Critical":
            print("🚨 CANARY ALERT")
        else:
            print("🚨 MASS-CHANGE ALERT")

        print("=" * 65)
        print(f"Time:  {alert.time}")
        print(f"Event: {alert.event_type}")
        print(f"File:  {alert.path}")

        if alert.rule == "mass_change":
            print(f"Window:    {RATE_WINDOW_SECONDS} seconds")
            print(f"Threshold: {RATE_THRESHOLD} events")

        print("=" * 65)

    def persist_alert(self, alert: Alert) -> None:
        record = FindingRecord(
            occurred_at=alert.time,
            summary=alert.summary,
            severity=alert.severity,
            rule=alert.rule,
            trigger_rule=alert.rule,
            path=alert.path,
            event_type=alert.event_type,
        )

        finding_id, inserted = self.db.insert_finding(record)

        if inserted:
            self.enricher.submit(
                finding_id,
                alert.path,
                alert.occurred_epoch,
                alert.rule,
            )
        else:
            logger.debug("Duplicate finding ignored: %s", alert.summary)

    # --------------------------------------------------------
    # Event entry point
    # --------------------------------------------------------

    def process_event(
        self,
        event_type: str,
        path: str,
        is_directory: bool = False,
        count_event: bool = True,
    ) -> None:
        try:
            if is_directory:
                return

            normalized = str(Path(path))

            result = self.rules.process_event(
                event_type,
                normalized,
                is_directory=False,
                count_event=count_event,
            )

            if not result.accepted:
                return

            # MOVED_TO is only a canary check; the rename was already counted
            # once on the source event.
            if count_event:
                self.counters.increment(event_type)

            logger.debug(
                "%s %s (window=%d)",
                event_type,
                Path(normalized).name,
                result.event_count,
            )

            for alert in result.alerts:
                self.print_alert(alert)
                self.persist_alert(alert)

        except Exception:  # noqa: BLE001 - a handler exception kills the observer
            logger.exception("Unhandled error while processing %s %s", event_type, path)

    # --------------------------------------------------------
    # Watchdog handlers
    # --------------------------------------------------------

    def on_created(self, event):
        self.process_event("CREATED", event.src_path, event.is_directory)

    def on_modified(self, event):
        self.process_event("MODIFIED", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self.process_event("DELETED", event.src_path, event.is_directory)

    def on_moved(self, event):
        self.process_event("MOVED", event.src_path, event.is_directory)

        if not event.is_directory:
            # Count the rename once, but still canary-check the destination.
            self.process_event(
                "MOVED_TO",
                event.dest_path,
                False,
                count_event=False,
            )


# ============================================================
# CLI / MAIN
# ============================================================


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Repo-Canary detection engine",
    )

    parser.add_argument(
        "--test-dir",
        default=str(lab_config.TEST_DIR),
        help=f"folder to watch (default: {lab_config.TEST_DIR})",
    )

    parser.add_argument(
        "--db-path",
        default=None,
        help=f"SQLite database (default: {lab_config.DB_FILE})",
    )

    parser.add_argument(
        "--findings",
        default=None,
        help="deprecated: legacy findings.json; the DB is placed beside it",
    )

    parser.add_argument(
        "--attribution",
        choices=("auto", "sysmon", "none"),
        default="auto",
        help="process attribution source (default: auto)",
    )

    parser.add_argument(
        "--hash-file",
        default=str(lab_config.KNOWN_HASHES_FILE),
        help=f"SHA-256 threat-intel feed (default: {lab_config.KNOWN_HASHES_FILE})",
    )

    parser.add_argument(
        "--max-hash-bytes",
        type=int,
        default=256 * 1024 * 1024,
        help="skip hashing files larger than this (default: 256 MiB)",
    )

    parser.add_argument(
        "--report-dir",
        default=str(lab_config.REPORTS_DIR),
        help=f"PDF report folder (default: {lab_config.REPORTS_DIR})",
    )

    parser.add_argument(
        "--reports-per-minute",
        type=int,
        default=12,
        help="PDF report throttle (default: 12 per minute)",
    )

    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="disable PDF incident reports",
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


def resolve_paths(args) -> tuple[Path, Path]:
    """Return ``(db_path, legacy_json_path)`` with the deprecated alias."""

    if args.db_path:
        db_path = Path(args.db_path)
    elif args.findings:
        db_path = Path(args.findings).with_suffix(".db")
        print(
            "[!] --findings is deprecated; using database "
            f"{db_path} (pass --db-path to choose explicitly)",
            file=sys.stderr,
        )
    else:
        db_path = Path(lab_config.DB_FILE)

    legacy_json = (
        Path(args.findings) if args.findings else Path(lab_config.FINDINGS_FILE)
    )

    return db_path, legacy_json


def main(argv=None) -> int:

    configure_output()

    args = parse_args(argv)

    configure_logging(args.log_file)

    monitored_dir = Path(args.test_dir)
    db_path, legacy_json = resolve_paths(args)
    report_dir = Path(args.report_dir)

    if not monitored_dir.is_dir():
        logger.error("Directory does not exist: %s", monitored_dir)
        return 1

    db = FindingsDB(db_path)

    try:
        db.initialize()
        migrated = db.migrate_legacy_json(legacy_json)
    except Exception:  # noqa: BLE001 - configuration errors should be readable
        logger.exception("Could not initialise the database at %s", db_path)
        return 1

    intel = ThreatIntel(args.hash_file, max_bytes=args.max_hash_bytes)
    hash_count = intel.load()

    try:
        db.replace_known_hashes(intel.entries())
    except Exception:  # noqa: BLE001
        logger.exception("Could not mirror the threat-intel feed into SQLite")

    attributor = build_attributor(args.attribution)

    reporter = IncidentReporter(
        db,
        report_dir,
        enabled=not args.no_reports,
        throttle=ReportThrottle(max_per_minute=args.reports_per_minute),
        engine_version=VERSION,
    )

    enricher = EnrichmentWorker(db, attributor, intel, reporter)
    counters = EventCounters(db)
    detector = RansomwareDetector(db, enricher, counters)

    reporter.start()
    enricher.start()
    counters.start()

    started_at = utc_now()

    try:
        db.heartbeat(
            watch_dir=str(monitored_dir),
            version=VERSION,
            started_at=started_at,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Could not write the initial heartbeat")

    stop = threading.Event()

    def request_stop(signum, frame):
        logger.info("Signal %s received; shutting down", signum)
        stop.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            try:
                signal.signal(getattr(signal, signal_name), request_stop)
            except (OSError, ValueError):
                pass

    observer = Observer()
    observer.schedule(detector, str(monitored_dir), recursive=True)
    observer.start()

    print("=" * 65)
    print("        RANSOMWARE 207 - DETECTION ENGINE")
    print("=" * 65)
    print(f"Watching:    {monitored_dir}")
    print(f"Database:    {db_path}")
    print(f"Reports:     {'disabled' if args.no_reports else report_dir}")
    print(f"Threat feed: {args.hash_file} ({hash_count} hashes)")
    print(f"Attribution: {getattr(attributor, 'method', 'none')}")
    print(
        f"Threshold:   {RATE_THRESHOLD} events / {RATE_WINDOW_SECONDS} s "
        f"(debounce {DEBOUNCE_SECONDS} s)"
    )
    print(f"Canaries:    {', '.join(sorted(CANARY_FILES))}")
    if migrated:
        print(f"Migrated:    {migrated} legacy findings")
    print("Status: WATCHING")
    print("=" * 65, flush=True)

    def heartbeat_loop() -> None:
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                db.heartbeat(watch_dir=str(monitored_dir), version=VERSION)
            except Exception:  # noqa: BLE001
                logger.exception("Heartbeat write failed")

    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        name="heartbeat",
        daemon=True,
    )
    heartbeat_thread.start()

    exit_code = 0

    try:
        while not stop.wait(1.0):
            if not observer.is_alive():
                logger.critical(
                    "The filesystem observer stopped unexpectedly; exiting so a "
                    "supervisor can restart the service"
                )
                exit_code = 1
                break
    finally:
        observer.stop()
        observer.join(timeout=10.0)

        stop.set()
        counters.stop()
        enricher.stop()
        reporter.stop()
        heartbeat_thread.join(timeout=5.0)

        print("\n[+] Detector stopped.")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
