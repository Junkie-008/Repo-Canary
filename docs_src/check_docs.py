"""Validate the eight-PDF documentation set.

Usage:
    python docs_src/check_docs.py docs

The gate checks that the folder contains exactly the expected PDFs, that every
document has enough pages and extractable text, that the current project facts
are present, and that the diagram assets exist.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pypdf import PdfReader

EXPECTED_PDFS = [
    "01_System_Architecture.pdf",
    "02_Diagrams.pdf",
    "03_Database_Design.pdf",
    "04_Testing_Report.pdf",
    "05_User_Manual.pdf",
    "06_Future_Scope.pdf",
    "07_Synopsis.pdf",
    "08_Project_Presentation.pdf",
]

REQUIRED_TERMS = {
    "01_System_Architecture.pdf": ("canary_baseline", "SQLite", "integrity"),
    "02_Diagrams.pdf": ("DFD", "canary_baseline", "sequence"),
    "03_Database_Design.pdf": ("canary_baseline", "schema_version", "WAL"),
    "04_Testing_Report.pdf": ("67", "test_canary_integrity", "negative control"),
    "05_User_Manual.pdf": ("reset_lab", "integrity", "dashboard"),
    "06_Future_Scope.pdf": ("retention", "authentication"),
    "07_Synopsis.pdf": ("67", "SQLite", "canary"),
    "08_Project_Presentation.pdf": ("67", "canary_baseline", "SQLite"),
}

EXPECTED_IMAGES = [
    "architecture.png",
    "diagram_context.png",
    "diagram_dfd1.png",
    "diagram_usecase.png",
    "diagram_sequence.png",
    "diagram_er.png",
    "diagram_deployment.png",
]

MIN_PAGES = 3
MIN_PAGE_CHARS = 120
MIN_IMAGE_BYTES = 10_000
IMAGE_DIR = Path(__file__).resolve().parent / "images"


def check_pdf(path: Path, problems: list[str]) -> tuple[int, str] | None:
    try:
        reader = PdfReader(str(path))
    except Exception as error:  # noqa: BLE001 - report any unreadable output
        problems.append(f"{path.name}: unreadable ({error})")
        return None

    pages = len(reader.pages)
    text_parts = []

    if pages < MIN_PAGES:
        problems.append(f"{path.name}: only {pages} page(s)")

    for number, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").strip()
        text_parts.append(text)

        # A full-page diagram is legitimate content even though it carries only
        # a caption; the near-blank-page guard is for pages with neither text
        # nor an image.
        try:
            has_image = len(page.images) > 0
        except Exception:  # noqa: BLE001 - tolerate parser differences
            has_image = False

        if len(text) < MIN_PAGE_CHARS and not has_image:
            problems.append(f"{path.name} page {number}: {len(text)} chars of text")

    return pages, "\n".join(text_parts)


def main(argv: list[str]) -> int:
    target = Path(argv[1] if len(argv) > 1 else "docs")
    problems: list[str] = []
    page_counts: dict[str, int] = {}
    texts: dict[str, str] = {}

    if not target.is_dir():
        print(f"docs directory not found: {target}", file=sys.stderr)
        return 1

    extras = sorted(
        path.name
        for path in target.iterdir()
        if path.is_file() and path.name not in EXPECTED_PDFS
    )

    if extras:
        problems.append(f"unexpected file(s) in {target}: {', '.join(extras)}")

    for name in EXPECTED_PDFS:
        path = target / name

        if not path.is_file():
            problems.append(f"{name}: missing")
            continue

        result = check_pdf(path, problems)

        if result is None:
            continue

        pages, text = result
        page_counts[name] = pages
        texts[name] = text

        for term in REQUIRED_TERMS.get(name, ()):
            if term.lower() not in text.lower():
                problems.append(f"{name}: missing current term '{term}'")

    for name in EXPECTED_IMAGES:
        path = IMAGE_DIR / name

        if not path.is_file():
            problems.append(f"image missing: {path}")
        elif path.stat().st_size < MIN_IMAGE_BYTES:
            problems.append(f"image too small: {path}")

    for name in EXPECTED_PDFS:
        if name in page_counts:
            print(f"{page_counts[name]:3d} pages  {name}")

    print(f"checked {len(page_counts)}/{len(EXPECTED_PDFS)} PDFs in {target}")
    print(f"checked {len(EXPECTED_IMAGES)} diagram assets in {IMAGE_DIR}")

    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)

        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)

        return 1

    print("documentation set OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
