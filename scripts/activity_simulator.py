from pathlib import Path
import time

MONITORED_DIR = Path(r"C:\RansomwareLab\monitored")

TEST_FILES = [
    "simulated_document_01.txt",
    "simulated_document_02.txt",
    "simulated_document_03.txt",
    "simulated_document_04.txt",
    "simulated_document_05.txt",
]


def create_test_files():
    print("[+] Creating test files...")

    for filename in TEST_FILES:
        path = MONITORED_DIR / filename

        path.write_text(
            "This is a harmless ransomware detection test file.\n",
            encoding="utf-8"
        )

        print(f"[CREATE] {path.name}")
        time.sleep(1)


def modify_test_files():
    print("\n[+] Modifying test files...")

    for filename in TEST_FILES:
        path = MONITORED_DIR / filename

        with path.open("a", encoding="utf-8") as file:
            file.write("Simulated suspicious modification.\n")

        print(f"[MODIFY] {path.name}")
        time.sleep(1)


def main():
    if not MONITORED_DIR.exists():
        print(f"[ERROR] Directory does not exist: {MONITORED_DIR}")
        return

    print("=== Ransomware Detection Activity Simulator ===")
    print("This simulator performs harmless file activity only.")
    print(f"Target: {MONITORED_DIR}\n")

    create_test_files()
    modify_test_files()

    print("\n[+] Simulation completed.")


if __name__ == "__main__":
    main()