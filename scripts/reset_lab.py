"""Restore the disposable lab data before a Repo-Canary demo.

Actions
-------
- creates the lab marker (``.repo-canary-lab``) that the simulator requires
- deletes every ``*.locked`` file in the test folder
- recreates the three canary files (``_canary_01.txt`` .. ``_canary_03.txt``)
- stores their SHA-256/size/mtime baseline for the integrity scans
- recreates ``file1.txt`` .. ``file20.txt`` with harmless content
- optionally clears the SQLite findings (``--clear-findings``)

Only the test folder and the database are touched.

Usage
-----
    python scripts/reset_lab.py
    python scripts/reset_lab.py --yes --clear-findings
"""

import argparse
from pathlib import Path

import lab_config
from canary_integrity import lab_baseline_entries
from database import FindingsDB
from detection_rules import CANARY_FILES

TEST_FILES = [f"file{number}.txt" for number in range(1, 21)]

CANARY_TEXT = lab_config.CANARY_TEXT

TEST_TEXT = "Disposable test document. Safe to modify and delete.\n"


def reset(
    test_dir: Path,
    db_path: Path,
    findings_file: Path,
    clear_findings: bool = False,
) -> tuple:
    """Reset the lab folder and return (removed_locked, written_files)."""

    test_dir.mkdir(parents=True, exist_ok=True)

    # The simulator refuses to run without this marker.
    (test_dir / lab_config.LAB_MARKER).write_text(
        "Repo-Canary disposable lab folder. Safe to modify.\n",
        encoding="utf-8",
    )

    removed = []

    for path in sorted(test_dir.glob("*.locked")):
        path.unlink()
        removed.append(path)

    written = []

    for name in sorted(CANARY_FILES):
        path = test_dir / name
        # Write bytes so the canary is LF on every platform; text mode would
        # turn \n into \r\n on Windows and diverge from the canonical baseline.
        path.write_bytes(CANARY_TEXT.encode("utf-8"))
        written.append(path)

    for name in TEST_FILES:
        path = test_dir / name
        path.write_text(TEST_TEXT, encoding="utf-8")
        written.append(path)

    # The baseline must describe exactly what was just written, including the
    # mtime, so a later edit or timestamp change during downtime is visible.
    db = FindingsDB(db_path)
    db.initialize()
    db.replace_canary_baseline(lab_baseline_entries(test_dir))

    if clear_findings:
        db.clear_findings()

        if findings_file.exists():
            findings_file.unlink()

    return removed, written


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Restore the Repo-Canary disposable lab data",
    )

    parser.add_argument(
        "--test-dir",
        default=str(lab_config.TEST_DIR),
        help=f"test folder (default: {lab_config.TEST_DIR})",
    )

    parser.add_argument(
        "--db-path",
        default=str(lab_config.DB_FILE),
        help=f"SQLite database (default: {lab_config.DB_FILE})",
    )

    parser.add_argument(
        "--findings",
        default=str(lab_config.FINDINGS_FILE),
        help=f"legacy findings.json (default: {lab_config.FINDINGS_FILE})",
    )

    parser.add_argument(
        "--clear-findings",
        action="store_true",
        help="clear findings from the database as well",
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="do not ask for confirmation",
    )

    return parser.parse_args(argv)


def main(argv=None) -> int:

    args = parse_args(argv)

    test_dir = Path(args.test_dir)
    db_path = Path(args.db_path)
    findings_file = Path(args.findings)

    if not args.yes:
        print("This will overwrite the disposable files in:")
        print(f"  {test_dir}")

        if args.clear_findings:
            print(f"and clear findings in: {db_path}")

        answer = input("Continue? [y/N] ").strip().lower()

        if answer not in {"y", "yes"}:
            print("[+] Cancelled.")
            return 0

    removed, written = reset(
        test_dir,
        db_path,
        findings_file,
        clear_findings=args.clear_findings,
    )

    print(f"[+] Test folder: {test_dir}")
    print(f"[+] Removed {len(removed)} .locked file(s)")
    print(f"[+] Wrote {len(written)} disposable file(s)")

    if args.clear_findings:
        print(f"[+] Cleared findings in {db_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
