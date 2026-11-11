"""Ransomware 207 - detection engine.

Watches the lab test folder with watchdog, applies the canary and
mass-change rules (detection_rules.py) and appends every alert to
findings.json (findings_store.py).

Usage
-----
    py -3.12 detection_engine.py
    py -3.12 detection_engine.py --test-dir <folder> --findings <file>

The default folder is C:\\RansomwareLab\\testdata. Override it with the
arguments above or with the environment variables documented in
lab_config.py.
"""

import argparse
from datetime import datetime
from pathlib import Path
import sys
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import lab_config
from detection_rules import (
    CANARY_FILES,
    DEBOUNCE_SECONDS,
    RATE_THRESHOLD,
    RATE_WINDOW_SECONDS,
    Alert,
    DetectionRules,
)
from findings_store import save_finding


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def configure_output() -> None:
    """Make alert output safe when stdout is redirected or not UTF-8.

    The alert banners use emoji. A redirected Windows stream defaults to
    cp1252, which cannot encode them, and a print() failure inside the
    watchdog thread would stop the detector. Degrade instead of crashing.
    """

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
# DETECTOR
# ============================================================

class RansomwareDetector(FileSystemEventHandler):

    def __init__(self, findings_file):
        super().__init__()
        self.rules = DetectionRules()
        self.findings_file = Path(findings_file)

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

        if alert.severity != "Critical":
            print(f"Window:    {RATE_WINDOW_SECONDS} seconds")
            print(f"Threshold: {RATE_THRESHOLD} events")

        print("=" * 65)

    def raise_alert(self, alert: Alert) -> None:
        self.print_alert(alert)

        save_finding(
            alert.summary,
            alert.severity,
            findings_file=self.findings_file,
            timestamp=alert.time,
        )

    # --------------------------------------------------------
    # Event entry point
    # --------------------------------------------------------

    def process_event(self, event_type, path, is_directory=False):

        if is_directory:
            return

        path = str(Path(path))

        result = self.rules.process_event(
            event_type,
            path,
            is_directory=False,
        )

        # Duplicate event for the same file within the debounce period.
        if not result.accepted:
            return

        print(
            f"[{timestamp()}] "
            f"{event_type:<8} "
            f"{Path(path).name:<35} "
            f"WindowEvents={result.event_count}"
        )

        for alert in result.alerts:
            self.raise_alert(alert)

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
        self.process_event("MOVED_TO", event.dest_path, event.is_directory)


# ============================================================
# MAIN
# ============================================================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Ransomware 207 detection engine",
    )

    parser.add_argument(
        "--test-dir",
        default=str(lab_config.TEST_DIR),
        help=f"folder to watch (default: {lab_config.TEST_DIR})",
    )

    parser.add_argument(
        "--findings",
        default=str(lab_config.FINDINGS_FILE),
        help=f"findings JSON file (default: {lab_config.FINDINGS_FILE})",
    )

    return parser.parse_args(argv)


def main(argv=None) -> int:

    configure_output()

    args = parse_args(argv)

    monitored_dir = Path(args.test_dir)
    findings_file = Path(args.findings)

    if not monitored_dir.exists():
        print(f"[ERROR] Directory does not exist: {monitored_dir}")
        return 1

    print("=" * 65)
    print("        RANSOMWARE 207 - DETECTION ENGINE")
    print("=" * 65)
    print(f"Watching: {monitored_dir}")
    print(f"Findings: {findings_file}")
    print(
        f"Rate threshold: "
        f"{RATE_THRESHOLD} events / "
        f"{RATE_WINDOW_SECONDS} seconds"
    )
    print(f"Debounce: {DEBOUNCE_SECONDS} seconds")
    print(f"Canaries: {', '.join(sorted(CANARY_FILES))}")
    print("Press CTRL+C to stop.")
    print("=" * 65)

    detector = RansomwareDetector(findings_file)

    observer = Observer()
    observer.schedule(
        detector,
        str(monitored_dir),
        recursive=True,
    )

    observer.start()

    print("Status: WATCHING", flush=True)

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopping detector...")

        observer.stop()

    observer.join()

    print("[+] Detector stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
