from pathlib import Path
import time

import lab_config

folder = Path(lab_config.MONITORED_DIR)
test_file = folder / "psutil_correlation_test.txt"

print(f"PID: {__import__('os').getpid()}")

test_file.write_text(
    "Harmless psutil correlation test.\n",
    encoding="utf-8"
)

print("File created.")
print("Process will remain alive for 30 seconds...")

time.sleep(30)

print("Test finished.")