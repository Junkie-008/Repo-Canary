from process_attribution import get_process_info


def correlate_process(pid):
    """
    Retrieve process information associated with a Sysmon PID.
    """

    info = get_process_info(pid)

    print("=" * 60)
    print("FILE EVENT → PROCESS CORRELATION")
    print("=" * 60)

    print(f"PID:        {info['pid']}")
    print(f"Process:    {info['name']}")
    print(f"Executable: {info['exe']}")
    print(f"Command:    {info['cmdline']}")
    print(f"User:       {info['username']}")
    print(f"Status:     {info['status']}")

    print("=" * 60)

    return info


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("py -3.12 correlation.py <PID>")
        sys.exit(1)

    pid = int(sys.argv[1])
    correlate_process(pid)