"""Build the Ransomware 207 documentation set.

Usage:
    python build_docs.py            # PDFs + markdown + deck (.pptx)
    python build_docs.py --pdf-only # PDFs only

Every PDF is produced from ``docs_content.py`` through one template, so the
documents are internally consistent and can be regenerated after a code change.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from docs_builder import (
    Document,
    render,
    render_deck_slides,
    require_fonts,
    to_markdown,
)
from docs_content import DOCUMENTS, MARKDOWN_FILES


def build_pptx(doc: Document, output: Path) -> Path:
    """Mirror the deck PDF into an editable PowerPoint file."""

    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.util import Inches, Pt

    navy = RGBColor(0x1F, 0x2A, 0x44)
    accent = RGBColor(0xB0, 0x3A, 0x2E)
    grey = RGBColor(0x6E, 0x74, 0x80)

    deck = Presentation()
    deck.slide_width = Inches(13.333)
    deck.slide_height = Inches(7.5)

    slides = [(block[1], block[2]) for block in doc.blocks if block[0] == "slide"]
    blank = deck.slide_layouts[6]
    total = len(slides)

    for index, (title, bullets) in enumerate(slides, start=1):
        slide = deck.slides.add_slide(blank)

        band = slide.shapes.add_shape(1, 0, 0, deck.slide_width, Inches(1.35))
        band.fill.solid()
        band.fill.fore_color.rgb = navy
        band.line.fill.background()

        stripe = slide.shapes.add_shape(1, 0, Inches(1.35), deck.slide_width, Inches(0.07))
        stripe.fill.solid()
        stripe.fill.fore_color.rgb = accent
        stripe.line.fill.background()

        kicker = slide.shapes.add_textbox(Inches(0.7), Inches(0.35), Inches(11.5), Inches(0.4))
        run = kicker.text_frame.paragraphs[0].add_run()
        run.text = "RANSOMWARE 207 | Incident Detection for a Ransomware Attack"
        run.font.size = Pt(12)
        run.font.color.rgb = RGBColor(0xEE, 0xF0, 0xF4)

        heading = slide.shapes.add_textbox(Inches(0.7), Inches(0.7), Inches(11.9), Inches(0.6))
        paragraph = heading.text_frame.paragraphs[0]
        run = paragraph.add_run()
        run.text = title
        run.font.size = Pt(28 if len(title) < 46 else 22)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

        body = slide.shapes.add_textbox(Inches(0.9), Inches(1.8), Inches(11.5), Inches(4.9))
        frame = body.text_frame
        frame.word_wrap = True

        for position, bullet in enumerate(bullets):
            paragraph = frame.paragraphs[0] if position == 0 else frame.add_paragraph()
            paragraph.text = f"-  {bullet}"
            paragraph.space_after = Pt(12)
            for run in paragraph.runs:
                run.font.size = Pt(20 if len(bullets) <= 4 else 17)
                run.font.color.rgb = RGBColor(0x21, 0x25, 0x29)

        counter = slide.shapes.add_textbox(Inches(11.9), Inches(7.0), Inches(1.0), Inches(0.35))
        run = counter.text_frame.paragraphs[0].add_run()
        run.text = f"{index} / {total}"
        run.font.size = Pt(11)
        run.font.color.rgb = grey

    deck.save(str(output))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the project documentation PDFs")
    parser.add_argument("--pdf-only", action="store_true", help="skip markdown and PowerPoint output")
    parser.add_argument("--out", default=str(Path(__file__).parent), help="output directory")
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

        if args.pdf_only:
            continue

        if doc.key in MARKDOWN_FILES:
            md_path = output_dir / MARKDOWN_FILES[doc.key]
            md_path.write_text(to_markdown(doc), encoding="utf-8")
            print(f"md   {md_path.name}")

        if doc.key == "deck":
            pptx_path = output_dir / "11_Project_Presentation.pptx"
            build_pptx(doc, pptx_path)
            print(f"pptx {pptx_path.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
