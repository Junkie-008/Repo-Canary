# ===== simulate_ransomware.py - hits a canary early on purpose =====
"""Controlled, harmless stand-in for ransomware.

Reads each disposable file in the lab test folder, reverses its text,
writes it back and renames it to <name>.locked. Only the test folder is
touched; this is not real ransomware and never encrypts anything.

The test folder defaults to C:\\RansomwareLab\\testdata and can be changed
with REPO_CANARY_TEST_DIR (see scripts/lab_config.py).
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

from lab_config import TEST_DIR  # noqa: E402


def main() -> int:
    target = Path(TEST_DIR)

    if not target.exists():
        print(f"[ERROR] Test folder does not exist: {target}")
        return 1

    print("Attacking ONLY:", target)

    names = sorted(os.listdir(target))        # _canary_ files sort first

    for name in names:
        if name.endswith(".locked"):
            continue

        path = target / name

        if path.is_dir():
            continue

        with path.open("r", errors="ignore") as file:
            text = file.read()

        with path.open("w") as file:
            file.write(text[::-1])            # "encryption" = write the text back reversed

        path.rename(target / (name + ".locked"))

        print("touched", name)
        time.sleep(0.3)                       # slow enough to read the order

    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
