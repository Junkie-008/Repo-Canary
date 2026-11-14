"""Controlled, harmless stand-in for ransomware.

Reads each disposable .txt file in the lab test folder, reverses its text,
writes it back and renames it to ``<name>.locked``. Only the marked lab
folder is touched; this is not real ransomware and never encrypts anything.

Safety
------
- The target folder must contain the ``.repo-canary-lab`` marker created by
  ``reset_lab.py``; otherwise the script refuses to run. This prevents a
  mis-set ``REPO_CANARY_TEST_DIR`` from mangling real documents.
- Only regular ``.txt`` files are touched; symlinks, binaries and large files
  are skipped.
- ``--dry-run`` lists the changes without writing.

Usage
-----
    python simulate_ransomware.py --dry-run
    python simulate_ransomware.py
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

from lab_config import LAB_MARKER, TEST_DIR  # noqa: E402

MAX_FILE_BYTES = 10 * 1024 * 1024


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Harmless ransomware simulator for the Repo-Canary lab",
    )

    parser.add_argument(
        "--test-dir",
        default=str(TEST_DIR),
        help=f"lab test folder (default: {TEST_DIR})",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the planned operations without writing",
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the confirmation prompt",
    )

    return parser.parse_args(argv)


def is_lab_folder(target: Path) -> bool:
    return target.is_dir() and (target / LAB_MARKER).is_file()


def iter_targets(target: Path):
    for entry in sorted(os.scandir(target), key=lambda item: item.name):
        path = Path(entry.path)

        if entry.name.endswith(".locked"):
            continue

        if path.is_symlink() or not entry.is_file(follow_symlinks=False):
            continue

        if path.suffix.lower() != ".txt":
            continue

        try:
            if entry.stat(follow_symlinks=False).st_size > MAX_FILE_BYTES:
                print(f"skip (too large) {entry.name}")
                continue
        except OSError as error:
            print(f"skip (stat failed) {entry.name}: {error}")
            continue

        yield path


def main(argv=None) -> int:
    args = parse_args(argv)
    target = Path(args.test_dir).resolve()

    if not target.is_dir():
        print(f"[ERROR] Test folder does not exist: {target}")
        return 1

    if not is_lab_folder(target):
        print("[ERROR] Refusing to run: this folder is not a marked lab folder.")
        print(f"        Missing marker: {target / LAB_MARKER}")
        print("        Run scripts/reset_lab.py --yes to create a disposable lab.")
        return 2

    targets = list(iter_targets(target))

    if not targets:
        print("[!] No .txt files to touch.")
        return 0

    print("Attacking ONLY:", target)
    print(f"Files: {len(targets)}")

    if args.dry_run:
        for path in targets:
            print(f"[dry-run] would reverse and rename {path.name}")
        print("done (dry run)")
        return 0

    if not args.yes:
        answer = input("Reverse and rename these disposable files? [y/N] ").strip().lower()

        if answer not in {"y", "yes"}:
            print("[+] Cancelled.")
            return 0

    touched = 0

    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            path.write_text(text[::-1], encoding="utf-8")
            path.rename(target / (path.name + ".locked"))
        except OSError as error:
            print(f"skip (error) {path.name}: {error}")
            continue

        touched += 1
        print("touched", path.name)
        time.sleep(0.3)  # slow enough to read the order

    print(f"done ({touched} file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
