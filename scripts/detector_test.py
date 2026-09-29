from pathlib import Path
import time

MONITORED_DIR = Path(r"C:\RansomwareLab\monitored")

TEST_FILES = [
    "burst_test_01.txt",
    "burst_test_02.txt",
    "burst_test_03.txt",
    "burst_test_04.txt",
    "burst_test_05.txt",
    "burst_test_06.txt",
]


def main():

    print("[+] Starting harmless ransomware activity simulation")

    # --------------------------------------------------------
    # Phase 1: Touch the canary
    # --------------------------------------------------------

    canary = MONITORED_DIR / "CANARY_001.txt"

    print("[+] Triggering canary...")
    
    with canary.open("a", encoding="utf-8") as file:
        file.write("Harmless detector test.\n")

    time.sleep(2)

    # --------------------------------------------------------
    # Phase 2: Generate rapid file activity
    # --------------------------------------------------------

    print("[+] Generating rapid file activity...")

    for filename in TEST_FILES:

        path = MONITORED_DIR / filename

        path.write_text(
            "Harmless ransomware detection test.\n",
            encoding="utf-8"
        )

        with path.open("a", encoding="utf-8") as file:
            file.write("Simulated modification.\n")

    print("[+] Simulation complete.")


if __name__ == "__main__":
    main()