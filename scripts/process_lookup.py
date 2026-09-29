import psutil
import sys


def get_process_info(pid):
    try:
        process = psutil.Process(pid)

        print(f"PID:     {process.pid}")
        print(f"Name:    {process.name()}")
        print(f"Exe:     {process.exe()}")
        print(f"Cmdline: {process.cmdline()}")

    except psutil.NoSuchProcess:
        print(f"[ERROR] Process {pid} no longer exists.")

    except psutil.AccessDenied:
        print(f"[ERROR] Access denied while inspecting PID {pid}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: py -3.12 process_lookup.py <PID>")
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("[ERROR] PID must be a number.")
        sys.exit(1)

    get_process_info(pid)