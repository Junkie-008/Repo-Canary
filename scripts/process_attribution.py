import psutil


def get_process_info(pid):
    """
    Return useful process information for a given PID.
    """

    try:
        process = psutil.Process(pid)

        return {
            "pid": process.pid,
            "name": process.name(),
            "exe": process.exe(),
            "cmdline": " ".join(process.cmdline()),
            "username": process.username(),
            "status": process.status(),
        }

    except psutil.NoSuchProcess:
        return {
            "pid": pid,
            "name": "UNKNOWN",
            "exe": "UNKNOWN",
            "cmdline": "UNKNOWN",
            "username": "UNKNOWN",
            "status": "PROCESS_EXITED",
        }

    except psutil.AccessDenied:
        return {
            "pid": pid,
            "name": "ACCESS_DENIED",
            "exe": "ACCESS_DENIED",
            "cmdline": "ACCESS_DENIED",
            "username": "ACCESS_DENIED",
            "status": "ACCESS_DENIED",
        }


def print_process_info(info):
    print("=" * 60)
    print("PROCESS ATTRIBUTION")
    print("=" * 60)

    print(f"PID:       {info['pid']}")
    print(f"Name:      {info['name']}")
    print(f"Executable:{info['exe']}")
    print(f"Command:   {info['cmdline']}")
    print(f"Username:  {info['username']}")
    print(f"Status:    {info['status']}")

    print("=" * 60)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("py -3.12 process_attribution.py <PID>")
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("[ERROR] PID must be a number.")
        sys.exit(1)

    info = get_process_info(pid)
    print_process_info(info)