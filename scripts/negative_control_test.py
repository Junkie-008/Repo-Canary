"""FR-1.4 negative control: ordinary file activity must produce no alert.

The SRS requires evidence that normal work in the monitored folder stays
silent. This script creates a throw-away lab folder, starts the real detection
engine against it with its own SQLite database, performs ordinary file
operations (below the 10-events-in-10-seconds threshold and never touching a
canary), and then checks that no finding was stored.

Exit code 0 = PASS (no alert), 1 = FAIL (an alert was raised).

Usage
-----
    python scripts/negative_control_test.py
"""

import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import FindingsDB  # noqa: E402

ENGINE = Path(__file__).with_name("detection_engine.py")

# Ordinary activity, well under RATE_THRESHOLD events in RATE_WINDOW_SECONDS.
PAUSE_SECONDS = 0.7


def read_stream(stream, sink):
    for line in stream:
        sink.append(line.rstrip())


def wait_for_engine(process, lines, timeout=15.0):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if any("Status: WATCHING" in line for line in lines):
            return True

        if process.poll() is not None:
            return False

        time.sleep(0.1)

    return False


def run_normal_activity(folder: Path) -> None:
    """Seven normalised events: 3 creates, 1 append, 1 rename, 1 delete."""

    for name in ("normal_a.txt", "normal_b.txt", "normal_c.txt"):
        (folder / name).write_text(
            "Ordinary user document.\n",
            encoding="utf-8",
        )
        time.sleep(PAUSE_SECONDS)

    with (folder / "normal_a.txt").open("a", encoding="utf-8") as file:
        file.write("Saved by the user.\n")

    time.sleep(PAUSE_SECONDS)

    (folder / "normal_b.txt").rename(folder / "normal_b_renamed.txt")

    time.sleep(PAUSE_SECONDS)

    # Reading files is not a modification and must not produce an alert.
    for path in folder.iterdir():
        if path.is_file():
            path.read_bytes()

    time.sleep(PAUSE_SECONDS)

    (folder / "normal_c.txt").unlink()

    time.sleep(PAUSE_SECONDS)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="repo-canary-negative-") as temp:
        folder = Path(temp) / "testdata"
        folder.mkdir()

        database = Path(temp) / "canary.db"
        log_file = Path(temp) / "error_log.txt"

        command = [
            sys.executable,
            "-u",
            str(ENGINE),
            "--test-dir",
            str(folder),
            "--db-path",
            str(database),
            "--hash-file",
            str(Path(temp) / "known_hashes.txt"),
            "--log-file",
            str(log_file),
            "--no-reports",
        ]

        print("[+] Starting detection engine on a disposable folder...")
        print(f"    {folder}")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        lines = []
        reader = threading.Thread(
            target=read_stream,
            args=(process.stdout, lines),
            daemon=True,
        )
        reader.start()

        if not wait_for_engine(process, lines):
            process.kill()

            print("[FAIL] The detection engine did not start.")
            print("\n".join(lines))

            return 1

        print("[+] Engine running. Performing ordinary file activity...")

        run_normal_activity(folder)

        # Give the engine time to flush any (unexpected) alert.
        time.sleep(2.0)

        process.terminate()

        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()

        alerts = []

        if database.exists():
            db = FindingsDB(database)
            db.initialize()
            alerts = db.list_findings(limit=100)

        print()
        print("=" * 65)
        print("NEGATIVE CONTROL RESULT (FR-1.4)")
        print("=" * 65)
        print("Activity:   3 creates, 1 append, 1 rename, 1 delete")
        print("Expectation: no alert")
        print(f"Alerts:     {len(alerts)}")

        if alerts:
            print("-" * 65)

            for alert in alerts:
                print(
                    f"  [{alert.get('severity', '?')}] "
                    f"{alert.get('summary', '?')}"
                )

            print("=" * 65)
            print("[FAIL] Normal activity raised an alert (false positive).")

            return 1

        print("=" * 65)
        print("[PASS] Normal activity produced no alert (no false positive).")

        return 0


if __name__ == "__main__":
    raise SystemExit(main())
