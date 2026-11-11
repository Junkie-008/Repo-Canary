"""Serve the Ransomware 207 dashboard and findings.json from one origin.

The dashboard is a static page that fetches findings.json. Rather than
copying index.html into C:\\RansomwareLab and starting a generic HTTP
server there, this script serves the repository's index.html and exposes
the configured findings file at /findings.json.

Usage
-----
    py -3.12 dashboard_server.py
    py -3.12 dashboard_server.py --port 8000 --findings <file>

Then open http://localhost:8000/index.html
"""

import argparse
import functools
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import lab_config

REPO_ROOT = Path(__file__).resolve().parent.parent


class DashboardHandler(SimpleHTTPRequestHandler):
    """Static files from the repository, /findings.json from the lab."""

    findings_file: Path = lab_config.FINDINGS_FILE

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/findings.json":
            self.send_findings()
            return

        super().do_GET()

    def send_findings(self):
        payload = []

        try:
            with Path(self.findings_file).open("r", encoding="utf-8") as file:
                data = json.load(file)

            if isinstance(data, list):
                payload = data

        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            # Missing or partially written file: serve an empty list.
            payload = []

        body = json.dumps(payload, indent=2).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        if not self.path.startswith("/findings.json"):
            self.send_header("Cache-Control", "no-store")

        super().end_headers()

    def log_message(self, format, *args):
        # Keep the console quiet: only errors are useful during a demo.
        if str(args[1]).startswith("4") or str(args[1]).startswith("5"):
            super().log_message(format, *args)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Serve the Ransomware 207 dashboard",
    )

    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--findings",
        default=str(lab_config.FINDINGS_FILE),
        help=f"findings JSON file (default: {lab_config.FINDINGS_FILE})",
    )

    return parser.parse_args(argv)


def main(argv=None) -> int:

    args = parse_args(argv)

    handler = functools.partial(
        type(
            "Handler",
            (DashboardHandler,),
            {"findings_file": Path(args.findings)},
        ),
        directory=str(REPO_ROOT),
    )

    server = ThreadingHTTPServer((args.host, args.port), handler)

    print("=" * 65)
    print("        RANSOMWARE 207 - DASHBOARD SERVER")
    print("=" * 65)
    print(f"Dashboard: http://{args.host}:{args.port}/index.html")
    print(f"Findings:  {args.findings}")
    print("Press CTRL+C to stop.")
    print("=" * 65)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopping dashboard server...")
        server.shutdown()

    server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
