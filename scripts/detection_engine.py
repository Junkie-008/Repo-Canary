from pathlib import Path
from collections import deque
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


# ============================================================
# CONFIGURATION
# ============================================================

MONITORED_DIR = Path(r"C:\RansomwareLab\monitored")

CANARY_FILES = {
    "canary_001.txt",
    "canary_002.txt",
}

RATE_WINDOW_SECONDS = 10
RATE_THRESHOLD = 10

# Ignore repeated events for the same file inside this period.
DEBOUNCE_SECONDS = 0.5

# Prevent repeated mass-change alerts during the same burst.
ALERT_COOLDOWN_SECONDS = 10


# ============================================================
# DETECTOR
# ============================================================

class RansomwareDetector(FileSystemEventHandler):

    def __init__(self):
        super().__init__()

        # Stores timestamps of normalized file events.
        self.event_times = deque()

        # Tracks the most recent event for each file.
        self.last_file_event = {}

        # Prevents repeated alerts.
        self.last_rate_alert = 0

    # --------------------------------------------------------
    # Utility functions
    # --------------------------------------------------------

    def timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def is_canary(self, path):
        filename = Path(path).name.lower()
        return filename in CANARY_FILES

    # --------------------------------------------------------
    # Process filesystem event
    # --------------------------------------------------------

    def process_event(self, event_type, path):

        path = str(Path(path))

        if Path(path).is_dir():
            return

        now = time.time()

        # ----------------------------------------------------
        # Canary detection
        # ----------------------------------------------------

        if self.is_canary(path):

            print()
            print("=" * 65)
            print("🚨 CANARY ALERT")
            print("=" * 65)
            print(f"Time:  {self.timestamp()}")
            print(f"Event: {event_type}")
            print(f"File:  {path}")
            print("=" * 65)

        # ----------------------------------------------------
        # Debounce duplicate events
        # ----------------------------------------------------

        previous_event = self.last_file_event.get(path)

        if (
            previous_event is not None
            and now - previous_event < DEBOUNCE_SECONDS
        ):
            return

        self.last_file_event[path] = now

        # ----------------------------------------------------
        # Add normalized event to rolling window
        # ----------------------------------------------------

        self.event_times.append(now)

        while (
            self.event_times
            and now - self.event_times[0] > RATE_WINDOW_SECONDS
        ):
            self.event_times.popleft()

        event_count = len(self.event_times)

        # ----------------------------------------------------
        # Display event
        # ----------------------------------------------------

        print(
            f"[{self.timestamp()}] "
            f"{event_type:<8} "
            f"{Path(path).name:<35} "
            f"WindowEvents={event_count}"
        )

        # ----------------------------------------------------
        # Mass-change detection
        # ----------------------------------------------------

        if (
            event_count >= RATE_THRESHOLD
            and now - self.last_rate_alert
            >= ALERT_COOLDOWN_SECONDS
        ):

            print()
            print("=" * 65)
            print("🚨 MASS-CHANGE ALERT")
            print("=" * 65)
            print(f"Time:      {self.timestamp()}")
            print(f"Events:    {event_count}")
            print(
                f"Window:    {RATE_WINDOW_SECONDS} seconds"
            )
            print(
                f"Threshold: {RATE_THRESHOLD} events"
            )
            print("=" * 65)

            self.last_rate_alert = now

    # --------------------------------------------------------
    # Watchdog handlers
    # --------------------------------------------------------

    def on_created(self, event):
        self.process_event(
            "CREATED",
            event.src_path
        )

    def on_modified(self, event):
        self.process_event(
            "MODIFIED",
            event.src_path
        )

    def on_deleted(self, event):
        self.process_event(
            "DELETED",
            event.src_path
        )

    def on_moved(self, event):

        self.process_event(
            "MOVED",
            event.src_path
        )

        self.process_event(
            "MOVED_TO",
            event.dest_path
        )


# ============================================================
# MAIN
# ============================================================

def main():

    if not MONITORED_DIR.exists():

        print(
            f"[ERROR] Directory does not exist: "
            f"{MONITORED_DIR}"
        )

        return

    print("=" * 65)
    print("        RANSOMWARE 207 - DETECTION ENGINE")
    print("=" * 65)

    print(f"Watching: {MONITORED_DIR}")

    print(
        f"Rate threshold: "
        f"{RATE_THRESHOLD} events / "
        f"{RATE_WINDOW_SECONDS} seconds"
    )

    print(
        f"Debounce: {DEBOUNCE_SECONDS} seconds"
    )

    print(
        f"Canaries: "
        f"{', '.join(sorted(CANARY_FILES))}"
    )

    print("Status: WATCHING")
    print("Press CTRL+C to stop.")

    print("=" * 65)

    detector = RansomwareDetector()

    observer = Observer()

    observer.schedule(
        detector,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[+] Stopping detector...")

        observer.stop()

    observer.join()

    print("[+] Detector stopped.")


if __name__ == "__main__":
    main()