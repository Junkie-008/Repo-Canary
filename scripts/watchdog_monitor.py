from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from datetime import datetime
import time


MONITORED_DIR = Path(r"C:\RansomwareLab\monitored")


class RansomwareMonitor(FileSystemEventHandler):

    def log_event(self, event_type, path):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(
            f"[{timestamp}] "
            f"EVENT={event_type} | "
            f"FILE={path}"
        )

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.log_event(
                "MOVED",
                f"{event.src_path} -> {event.dest_path}"
            )


def main():

    if not MONITORED_DIR.exists():
        print(f"[ERROR] Directory does not exist: {MONITORED_DIR}")
        return

    event_handler = RansomwareMonitor()

    observer = Observer()
    observer.schedule(
        event_handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    print("=" * 60)
    print("RANSOMWARE 207 - FILE SYSTEM MONITOR")
    print("=" * 60)
    print(f"Monitoring: {MONITORED_DIR}")
    print("Status: ACTIVE")
    print("Press CTRL+C to stop.")
    print("=" * 60)

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopping monitor...")
        observer.stop()

    observer.join()

    print("[+] Monitor stopped.")


if __name__ == "__main__":
    main()