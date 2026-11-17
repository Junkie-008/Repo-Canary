"""Build the eight Repo-Canary PDF deliverables into ``docs/``.

Usage:
    python docs_src/build_docs.py
    python docs_src/build_docs.py --out docs

Content lives in ``docs_content.py``; this script only renders it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from docs_builder import render, render_deck_slides, require_fonts
from docs_content import DOCUMENTS


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Repo-Canary PDF documentation set")
    parser.add_argument("--out", default="docs", help="output directory (default: docs)")
    args = parser.parse_args()

    require_fonts()

    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)

    for doc in DOCUMENTS:
        if doc.key == "deck":
            path = render_deck_slides(doc, output_dir)
        else:
            path = render(doc, output_dir)

        print(f"pdf  {path.name:38s} {path.stat().st_size / 1024:8.1f} KiB")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
