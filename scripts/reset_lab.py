"""Restore the disposable lab data before a Ransomware 207 demo.

Actions
-------
- deletes every *.locked file in the test folder
- recreates the three canary files (_canary_01.txt .. _canary_03.txt)
- recreates file1.txt .. file20.txt with harmless content
- optionally clears findings.json (--clear-findings)

Only the test folder and the findings file are touched.

Usage
-----
    py -3.12 reset_lab.py
    py -3.12 reset_lab.py --yes --clear-findings
"""

import argparse
from pathlib import Path

import lab_config
from detection_rules import CANARY_FILES

TEST_FILES = [f"file{number}.txt" for number in range(1, 21)]

CANARY_TEXT = (
    "This is a canary file. Ordinary work must never touch it.\n"
)

TEST_TEXT = "Disposable test document. Safe to modify and delete.\n"


def reset(
    test_dir: Path,
    findings_file: Path,
    clear_findings: bool = False,
) -> tuple:
    """Reset the lab folder and return (removed_locked, written_files)."""

    test_dir.mkdir(parents=True, exist_ok=True)

    removed = []

    for path in sorted(test_dir.glob("*.locked")):
        path.unlink()
        removed.append(path)

    written = []

    for name in sorted(CANARY_FILES):
        path = test_dir / name
        path.write_text(CANARY_TEXT, encoding="utf-8")
        written.append(path)

    for name in TEST_FILES:
        path = test_dir / name
        path.write_text(TEST_TEXT, encoding="utf-8")
        written.append(path)

    if clear_findings and findings_file.exists():
        findings_file.unlink()

    return removed, written


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Restore the Ransomware 207 disposable lab data",
    )

    parser.add_argument(
        "--test-dir",
        default=str(lab_config.TEST_DIR),
        help=f"test folder (default: {lab_config.TEST_DIR})",
    )

    parser.add_argument(
        "--findings",
        default=str(lab_config.FINDINGS_FILE),
        help=f"findings JSON file (default: {lab_config.FINDINGS_FILE})",
    )

    parser.add_argument(
        "--clear-findings",
        action="store_true",
        help="delete findings.json as well",
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
    findings_file = Path(args.findings)

    if not args.yes:
        print("This will overwrite the disposable files in:")
        print(f"  {test_dir}")

        if args.clear_findings:
            print(f"and delete findings: {findings_file}")

        answer = input("Continue? [y/N] ").strip().lower()

        if answer not in {"y", "yes"}:
            print("[+] Cancelled.")
            return 0

    removed, written = reset(
        test_dir,
        findings_file,
        clear_findings=args.clear_findings,
    )

    print(f"[+] Test folder: {test_dir}")
    print(f"[+] Removed {len(removed)} .locked file(s)")
    print(f"[+] Wrote {len(written)} disposable file(s)")

    if args.clear_findings:
        print(f"[+] Cleared {findings_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
