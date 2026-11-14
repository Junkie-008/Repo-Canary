"""Validate a built documentation set.

Runs after ``build_docs.py`` (locally or in CI) and fails loudly when a
document is missing, unreadable, suspiciously short or has lost its text.

Usage:
    python docs/check_docs.py docs          # the committed set
    python docs/check_docs.py build/docs    # a fresh CI build
"""

from __future__ import annotations

import sys
from pathlib import Path

from pypdf import PdfReader

EXPECTED_PDFS = [
    "01_Project_Report.pdf",
    "02_SRS_Document.pdf",
    "03_System_Architecture.pdf",
    "04_Database_Design.pdf",
    "05_API_Documentation.pdf",
    "06_Testing_Report.pdf",
    "07_User_Manual.pdf",
    "08_Installation_Guide.pdf",
    "09_README.pdf",
    "10_Future_Scope.pdf",
    "11_Project_Presentation.pdf",
    "12_Synopsis.pdf",
]

EXPECTED_MARKDOWN = [
    "README.md",
    "INSTALLATION_GUIDE.md",
    "DATABASE_SCHEMA.md",
    "API_DOCUMENTATION.md",
]

DECK = "11_Project_Presentation.pdf"
DECK_PPTX = "11_Project_Presentation.pptx"

MIN_PAGES = 3
MIN_PAGE_CHARS = 120
MIN_MARKDOWN_CHARS = 400
DECK_SIZE = (960, 540)  # points, 16:9


def check_pdf(path: Path, problems: list[str]) -> int | None:
    try:
        reader = PdfReader(str(path))
    except Exception as error:  # noqa: BLE001 - report any unreadable output
        problems.append(f"{path.name}: unreadable ({error})")
        return None

    pages = len(reader.pages)

    if pages < MIN_PAGES:
        problems.append(f"{path.name}: only {pages} page(s)")

    for number, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").strip()

        if len(text) < MIN_PAGE_CHARS:
            problems.append(f"{path.name} page {number}: {len(text)} chars of text")

    return pages


def check_deck_size(path: Path, problems: list[str]) -> None:
    page = PdfReader(str(path)).pages[0]
    width = round(float(page.mediabox.width))
    height = round(float(page.mediabox.height))

    if (width, height) != DECK_SIZE:
        problems.append(f"{path.name}: {width}x{height} pt, expected {DECK_SIZE[0]}x{DECK_SIZE[1]}")


def check_pptx(path: Path, deck_pages: int | None, problems: list[str]) -> int | None:
    try:
        from pptx import Presentation
    except ImportError:
        problems.append("python-pptx is not installed; cannot check the deck .pptx")
        return None

    slides = len(Presentation(str(path)).slides)

    if deck_pages is not None and slides != deck_pages:
        problems.append(f"{path.name}: {slides} slides but the PDF has {deck_pages} pages")

    return slides


def main(argv: list[str]) -> int:
    target = Path(argv[1] if len(argv) > 1 else Path(__file__).parent)
    problems: list[str] = []
    page_counts: dict[str, int] = {}

    for name in EXPECTED_PDFS:
        path = target / name

        if not path.is_file():
            problems.append(f"{name}: missing")
            continue

        pages = check_pdf(path, problems)

        if pages is not None:
            page_counts[name] = pages

    deck_path = target / DECK

    if deck_path.is_file():
        check_deck_size(deck_path, problems)

    slides = None
    pptx_path = target / DECK_PPTX

    if not pptx_path.is_file():
        problems.append(f"{DECK_PPTX}: missing")
    else:
        slides = check_pptx(pptx_path, page_counts.get(DECK), problems)

    for name in EXPECTED_MARKDOWN:
        path = target / name
        text = path.read_text(encoding="utf-8") if path.is_file() else ""

        if len(text) < MIN_MARKDOWN_CHARS:
            problems.append(f"{name}: missing or too short")

    for name in EXPECTED_PDFS:
        if name in page_counts:
            print(f"{page_counts[name]:3d} pages  {name}")

    print(f"{slides if slides is not None else '?':3} slides {DECK_PPTX}")
    print(f"checked {len(page_counts)}/{len(EXPECTED_PDFS)} PDFs in {target}")

    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)

        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)

        return 1

    print("documentation set OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
