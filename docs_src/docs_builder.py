"""Render the eight project PDFs with one consistent fpdf2 template.

Content lives in ``docs_content.py`` as a list of blocks, so every document
shares the same cover, headings, tables and page furniture. Wide diagrams are
placed on landscape pages so their labels stay readable in print.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from fpdf import FPDF
from fpdf.fonts import FontFace

# The documents are set in the Windows faces because that is what the source
# documents used. RC_DOC_FONT_DIR lets another machine (or a Windows CI runner
# with a relocated font cache) point at the same files.
FONT_DIR = Path(os.environ.get("RC_DOC_FONT_DIR") or r"C:\Windows\Fonts")
BODY_FONT = FONT_DIR / "segoeui.ttf"
BOLD_FONT = FONT_DIR / "segoeuib.ttf"
CODE_FONT = FONT_DIR / "consola.ttf"


def require_fonts() -> None:
    """Fail with an actionable message instead of an fpdf2 traceback."""

    missing = [path for path in (BODY_FONT, BOLD_FONT, CODE_FONT) if not path.is_file()]

    if missing:
        names = ", ".join(path.name for path in missing)
        raise SystemExit(
            f"Missing font files in {FONT_DIR}: {names}\n"
            "Set RC_DOC_FONT_DIR to a folder holding segoeui.ttf, segoeuib.ttf and consola.ttf."
        )

NAVY = (31, 42, 68)
ACCENT = (176, 58, 46)
GREY = (110, 116, 128)
LIGHT = (238, 240, 244)
WHITE = (255, 255, 255)
TEXT = (33, 37, 41)

COVER_META = [
    ("Institution", "ABES Engineering College, Ghaziabad"),
    ("Department", "Computer Science & Engineering"),
    ("University", "Dr. A.P.J. Abdul Kalam Technical University, Lucknow"),
    ("Programme", "B.Tech, Computer Science & Engineering"),
    ("Submitted by", "Abhishek (Roll 2400320100046)"),
    ("Project ID / Group", "RANSOMWARE 207 | Group G3"),
    ("Internal faculty guide", "SarathG"),
    ("Session", "2026 - 2027 (3rd Year, 5th Semester)"),
    ("Repository", "github.com/Junkie-008/repo-canary (branch main)"),
    ("Document version", "3.1 - 17 November 2026"),
]


@dataclass
class Document:
    key: str
    filename: str
    title: str
    subtitle: str
    blocks: list[tuple] = field(default_factory=list)
    landscape: bool = False
    markdown_name: str | None = None


class DocPDF(FPDF):
    def __init__(self, doc: Document):
        if doc.landscape:
            super().__init__(orientation="L", unit="mm", format=(190.5, 338.7))
        else:
            super().__init__(orientation="P", unit="mm", format="A4")

        self.doc = doc
        self.toc_pages = 1
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(20, 18, 20)
        self.set_title(doc.title)
        self.set_author("Abhishek - RANSOMWARE 207")
        self.set_subject(doc.subtitle)
        self.set_creator("Repo-Canary documentation builder")
        self.set_keywords("ransomware, detection, Sysmon, SQLite, Docker, dashboard")

        self.add_font("Body", "", str(BODY_FONT))
        self.add_font("Body", "B", str(BOLD_FONT))
        self.add_font("Code", "", str(CODE_FONT))
        self.set_font("Body", "", 10)
        self.alias_nb_pages()

    # -- page furniture ---------------------------------------------------
    def header(self) -> None:
        if self.page_no() == 1:
            return

        self.set_font("Body", "", 8)
        self.set_text_color(*GREY)
        self.cell(0, 5, "Ransomware 207", align="L")
        self.cell(0, 5, self.doc.title, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LIGHT)
        self.set_line_width(0.4)
        self.line(self.l_margin, self.get_y() + 1, self.w - self.r_margin, self.get_y() + 1)
        self.ln(6)

    def footer(self) -> None:
        if self.page_no() == 1:
            return

        self.set_y(-15)
        self.set_font("Body", "", 8)
        self.set_text_color(*GREY)
        self.cell(0, 6, "ABES Engineering College | RANSOMWARE 207", align="L")
        self.set_y(-15)
        self.cell(0, 6, f"Page {self.page_no()} of {{nb}}", align="R")

    # -- cover ------------------------------------------------------------
    def cover(self) -> None:
        self.add_page()
        self.set_auto_page_break(auto=False)
        self.set_fill_color(*NAVY)
        self.rect(0, 0, self.w, 62, style="F")
        self.set_fill_color(*ACCENT)
        self.rect(0, 62, self.w, 3, style="F")

        self.set_text_color(*WHITE)
        self.set_font("Body", "", 11)
        self.set_xy(20, 14)
        self.cell(0, 6, "ABES ENGINEERING COLLEGE, GHAZIABAD", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Body", "", 9)
        self.cell(0, 5, "Department of Computer Science & Engineering", new_x="LMARGIN", new_y="NEXT")
        self.cell(
            0,
            5,
            "Dr. A.P.J. Abdul Kalam Technical University, Lucknow",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        self.set_xy(20, 80)
        self.set_text_color(*TEXT)
        self.set_font("Body", "B", 23)
        self.multi_cell(
            0,
            10.5,
            "Incident Detection for a Ransomware Attack on a Windows Server",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        self.ln(3)
        self.set_text_color(*ACCENT)
        self.set_font("Body", "B", 15)
        self.multi_cell(0, 8.5, self.doc.title, new_x="LMARGIN", new_y="NEXT")

        self.set_text_color(*GREY)
        self.set_font("Body", "", 10.5)
        self.multi_cell(0, 5.6, self.doc.subtitle, new_x="LMARGIN", new_y="NEXT")

        self.ln(5)
        y = self.get_y()
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.8)
        self.line(20, y, 60, y)
        self.ln(6)

        self.set_font("Body", "", 9)
        for label, value in COVER_META:
            self.set_text_color(*GREY)
            self.cell(46, 5.8, label, new_x="RIGHT", new_y="TOP")
            self.set_text_color(*TEXT)
            self.multi_cell(0, 5.8, value, new_x="LMARGIN", new_y="NEXT")

        self.set_y(-22)
        self.set_font("Body", "", 8)
        self.set_text_color(*GREY)
        self.cell(0, 5, "Generated from the Repo-Canary source tree, 17 November 2026", align="C")
        self.set_auto_page_break(auto=True, margin=20)

    # -- blocks -----------------------------------------------------------
    def heading1(self, text: str) -> None:
        if self.get_y() > self.h - 60:
            self.add_page()

        self.ln(3)
        self.set_font("Body", "B", 15)
        self.set_text_color(*NAVY)
        self.multi_cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.6)
        y = self.get_y() + 1
        self.line(self.l_margin, y, self.l_margin + 28, y)
        self.ln(5)

    def heading2(self, text: str) -> None:
        if self.get_y() > self.h - 45:
            self.add_page()

        self.ln(2)
        self.set_font("Body", "B", 11.5)
        self.set_text_color(*ACCENT)
        self.multi_cell(0, 6.5, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def heading3(self, text: str) -> None:
        self.set_font("Body", "B", 10)
        self.set_text_color(*NAVY)
        self.multi_cell(0, 6, text, new_x="LMARGIN", new_y="NEXT")

    def para(self, text: str) -> None:
        # Do not start a paragraph with only a line or two left above the footer.
        if self.get_y() > self.h - 40:
            self.add_page()

        self.set_font("Body", "", 10)
        self.set_text_color(*TEXT)
        self.multi_cell(0, 5.6, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def bullets(self, items: Iterable[str], numbered: bool = False) -> None:
        self.set_font("Body", "", 10)
        self.set_text_color(*TEXT)
        width = self.w - self.l_margin - self.r_margin

        for index, item in enumerate(items, start=1):
            if self.get_y() > self.h - 26:
                self.add_page()

            marker = f"{index}." if numbered else "-"
            self.set_x(self.l_margin + 3)
            self.set_font("Body", "B", 10)
            self.cell(6, 5.6, marker)
            self.set_font("Body", "", 10)
            self.multi_cell(width - 9, 5.6, item, new_x="LMARGIN", new_y="NEXT")
            self.ln(1)

        self.ln(1)

    def code(self, text: str) -> None:
        self.set_font("Code", "", 8.0)
        line_height = 4.5
        lines = text.strip("\n").splitlines()
        width = self.w - self.l_margin - self.r_margin
        height = line_height * len(lines) + 5

        if self.get_y() + height > self.h - 25:
            self.add_page()

        top = self.get_y()
        self.set_fill_color(*LIGHT)
        self.rect(self.l_margin, top, width, height, style="F")
        self.set_text_color(*NAVY)
        self.set_xy(self.l_margin + 3, top + 2.5)

        for line in lines:
            self.cell(width - 6, line_height, line, new_x="LMARGIN", new_y="NEXT")
            self.set_x(self.l_margin + 3)

        self.set_y(top + height + 3)

    def figure(self, path: str, caption: str = "", width_mm: float | None = None) -> None:
        """Embed a diagram, scaled to the text width, with a caption."""

        from PIL import Image

        image_path = Path(path)

        if not image_path.is_file():
            raise FileNotFoundError(f"diagram not found: {image_path}")

        usable = self.w - self.l_margin - self.r_margin
        width = min(float(width_mm or usable), usable)

        with Image.open(image_path) as image:
            height = width * (image.height / image.width)

        if self.get_y() + height > self.h - self.b_margin - 8:
            self.add_page()

        x = self.l_margin + (usable - width) / 2
        top = self.get_y()
        self.image(str(image_path), x=x, y=top, w=width)
        self.set_y(top + height + 3)

        if caption:
            self.set_font("Body", "", 8.5)
            self.set_text_color(*GREY)
            self.multi_cell(0, 4.6, caption, new_x="LMARGIN", new_y="NEXT")

        self.ln(2)

    def figure_page(self, path: str, caption: str = "") -> None:
        """Place one wide diagram on its own landscape page, then resume portrait."""

        from PIL import Image

        image_path = Path(path)

        if not image_path.is_file():
            raise FileNotFoundError(f"diagram not found: {image_path}")

        default_margins = (self.l_margin, self.t_margin, self.r_margin)
        self.set_margins(12, 12, 12)
        self.add_page(orientation="L")
        usable_w = self.w - self.l_margin - self.r_margin
        # Leave room for the running header above the image and the caption below it.
        top = self.t_margin + 14
        usable_h = self.h - top - self.b_margin - 20

        with Image.open(image_path) as image:
            aspect = image.height / image.width

        width = usable_w
        height = width * aspect

        if height > usable_h:
            height = usable_h
            width = height / aspect

        x = self.l_margin + (usable_w - width) / 2
        self.image(str(image_path), x=x, y=top, w=width)

        if caption:
            self.set_xy(self.l_margin, top + height + 5)
            self.set_font("Body", "", 9)
            self.set_text_color(*GREY)
            self.multi_cell(usable_w, 4.8, caption, new_x="LMARGIN", new_y="NEXT")

        self.set_margins(*default_margins)
        self.add_page(orientation="P")

    def data_table(self, header: Sequence[str], rows: Sequence[Sequence[str]], widths: Sequence[float] | None = None) -> None:
        if widths:
            total = sum(widths)
            relative = [round(100 * w / total) for w in widths]
        else:
            relative = None

        headings_style = FontFace(emphasis="BOLD", color=WHITE, fill_color=NAVY)

        self.set_font("Body", "", 8.5)
        self.set_draw_color(*LIGHT)
        self.set_text_color(*TEXT)
        self.set_fill_color(*WHITE)

        with super().table(
            col_widths=relative,
            headings_style=headings_style,
            text_align="LEFT",
            line_height=4.6,
            padding=1.6,
            borders_layout="HORIZONTAL_LINES",
            cell_fill_mode="ROWS",
            cell_fill_color=(246, 247, 249),
        ) as table:
            head = table.row()
            for cell in header:
                head.cell(cell)

            for index, row in enumerate(rows):
                table_row = table.row()
                for cell in row:
                    table_row.cell(str(cell))

        self.ln(3)

    # -- contents ---------------------------------------------------------
    def contents(self, entries: Sequence[tuple[str, int]], pages: int) -> None:
        self.add_page()
        self.set_font("Body", "B", 16)
        self.set_text_color(*NAVY)
        self.cell(0, 10, "Contents", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

        width = self.w - self.l_margin - self.r_margin
        title_width = width - 18

        for title, page in entries:
            if self.get_y() > self.h - 28:
                self.add_page()

            self.set_font("Body", "", 10)
            self.set_text_color(*TEXT)

            label = title
            if self.get_string_width(label) > title_width:
                while label and self.get_string_width(label + "...") > title_width:
                    label = label[:-1]
                label = label.rstrip() + "..."

            self.cell(title_width, 6.2, label)
            self.set_font("Body", "B", 10)
            self.cell(18, 6.2, str(page), align="R", new_x="LMARGIN", new_y="NEXT")

        for _ in range(pages - 1):
            self.add_page()


def _draw_blocks(pdf: DocPDF, blocks: Sequence[tuple]) -> dict[str, int]:
    numbers: dict[str, int] = {}

    for block in blocks:
        kind = block[0]

        if kind == "h1":
            pdf.heading1(block[1])
            numbers[block[1]] = pdf.page_no()
        elif kind == "h2":
            pdf.heading2(block[1])
        elif kind == "h3":
            pdf.heading3(block[1])
        elif kind == "p":
            pdf.para(block[1])
        elif kind == "bullets":
            pdf.bullets(block[1])
        elif kind == "num":
            pdf.bullets(block[1], numbered=True)
        elif kind == "code":
            pdf.code(block[1])
        elif kind == "table":
            widths = block[3] if len(block) > 3 else None
            pdf.data_table(block[1], block[2], widths)
        elif kind == "image":
            caption = block[2] if len(block) > 2 else ""
            width_mm = block[3] if len(block) > 3 else None
            pdf.figure(block[1], caption, width_mm)
        elif kind == "figure_wide":
            pdf.figure_page(block[1], block[2] if len(block) > 2 else "")
        elif kind == "pagebreak":
            pdf.add_page()
        else:  # pragma: no cover - guards a typo in the content module
            raise ValueError(f"unknown block type: {kind}")

    return numbers


def render(doc: Document, output_dir: Path) -> Path:
    headings = [block[1] for block in doc.blocks if block[0] == "h1"]
    toc_pages = 1 if len(headings) <= 24 else 2

    # Pass 1: page numbers with placeholder contents pages of the same length.
    probe = DocPDF(doc)
    probe.cover()
    probe.contents([(title, 0) for title in headings], toc_pages)
    numbers = _draw_blocks(probe, doc.blocks)

    # Pass 2: the real thing.
    pdf = DocPDF(doc)
    pdf.cover()
    pdf.contents([(title, numbers.get(title, "")) for title in headings], toc_pages)
    _draw_blocks(pdf, doc.blocks)

    target = output_dir / doc.filename
    pdf.output(str(target))
    return target


def to_markdown(doc: Document) -> str:
    lines = [f"# {doc.title}", "", f"*{doc.subtitle}*", ""]

    for block in doc.blocks:
        kind = block[0]

        if kind == "h1":
            lines += [f"## {block[1]}", ""]
        elif kind == "h2":
            lines += [f"### {block[1]}", ""]
        elif kind == "h3":
            lines += [f"#### {block[1]}", ""]
        elif kind == "p":
            lines += [block[1], ""]
        elif kind in {"bullets", "num"}:
            for index, item in enumerate(block[1], start=1):
                marker = f"{index}." if kind == "num" else "-"
                lines.append(f"{marker} {item}")
            lines.append("")
        elif kind == "code":
            lines += ["```", block[1].strip("\n"), "```", ""]
        elif kind == "table":
            header, rows = block[1], block[2]
            lines.append("| " + " | ".join(header) + " |")
            lines.append("| " + " | ".join("---" for _ in header) + " |")
            for row in rows:
                lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
            lines.append("")
        elif kind in {"image", "figure_wide"}:
            caption = block[2] if len(block) > 2 else ""
            lines += [f"![{caption}]({block[1]})", ""]
        elif kind == "pagebreak":
            lines += ["---", ""]

    return "\n".join(lines).rstrip() + "\n"


def to_docx(doc: Document, output: Path) -> Path:
    """Render the same block model to an editable Word document."""

    from docx import Document as WordDocument
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    word = WordDocument()
    word.core_properties.title = doc.title
    word.core_properties.author = "Abhishek - RANSOMWARE 207"
    word.core_properties.subject = doc.subtitle
    word.core_properties.comments = "Generated from docs_content.py"

    for section in word.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.9)
        section.right_margin = Inches(0.9)

    normal = word.styles["Normal"]
    normal.font.name = "Segoe UI"
    normal.font.size = Pt(10)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), "Segoe UI")

    for level, size in ((1, 15), (2, 12), (3, 10.5)):
        style = word.styles[f"Heading {level}"]
        style.font.name = "Segoe UI"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor(0x1F, 0x2A, 0x44)
        style.element.rPr.rFonts.set(qn("w:eastAsia"), "Segoe UI")

    title = word.add_heading(doc.title, level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT

    subtitle = word.add_paragraph()
    run = subtitle.add_run(doc.subtitle)
    run.italic = True
    run.font.color.rgb = RGBColor(0x6E, 0x74, 0x80)

    meta = word.add_paragraph()
    meta.add_run("RANSOMWARE 207 | Group G3 | Document version 3.1 - 17 November 2026").bold = True
    meta.add_run("\nABES Engineering College, Ghaziabad | Dr. A.P.J. Abdul Kalam Technical University, Lucknow")

    def add_code(text: str) -> None:
        paragraph = word.add_paragraph()
        paragraph.paragraph_format.space_after = Pt(4)
        paragraph.paragraph_format.left_indent = Inches(0.15)
        shading = OxmlElement("w:shd")
        shading.set(qn("w:fill"), "F2F4F7")
        paragraph._p.get_or_add_pPr().append(shading)
        lines = text.strip("\n").splitlines() or [""]

        for index, line in enumerate(lines):
            run = paragraph.add_run(line)
            run.font.name = "Consolas"
            run.font.size = Pt(8.5)
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
            if index < len(lines) - 1:
                run.add_break()

    for block in doc.blocks:
        kind = block[0]

        if kind in {"h1", "h2", "h3"}:
            word.add_heading(block[1], level=int(kind[1]))
        elif kind == "p":
            word.add_paragraph(block[1])
        elif kind == "bullets":
            for item in block[1]:
                word.add_paragraph(item, style="List Bullet")
        elif kind == "num":
            for item in block[1]:
                word.add_paragraph(item, style="List Number")
        elif kind == "code":
            add_code(block[1])
        elif kind == "table":
            header, rows = block[1], block[2]
            table = word.add_table(rows=1, cols=len(header))
            table.style = "Light Grid Accent 1"
            table.autofit = True

            for index, label in enumerate(header):
                cell = table.rows[0].cells[index]
                cell.text = str(label)
                for run in cell.paragraphs[0].runs:
                    run.bold = True

            for row in rows:
                cells = table.add_row().cells
                for index, value in enumerate(row):
                    cells[index].text = str(value)

            word.add_paragraph()
        elif kind == "pagebreak":
            word.add_page_break()

    output.parent.mkdir(parents=True, exist_ok=True)
    word.save(str(output))
    return output


def render_deck_slides(doc: Document, output_dir: Path) -> Path:
    """Render a 16:9 slide deck (one slide per page)."""

    pdf = DocPDF(doc)
    pdf.set_auto_page_break(False)
    pdf.set_margins(0, 0, 0)

    slides = [(block[1], block[2]) for block in doc.blocks if block[0] == "slide"]
    total = len(slides)

    for index, (title, bullets) in enumerate(slides, start=1):
        pdf.add_page()
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 0, pdf.w, 34, style="F")
        pdf.set_fill_color(*ACCENT)
        pdf.rect(0, 34, pdf.w, 1.6, style="F")

        pdf.set_text_color(*WHITE)
        pdf.set_font("Body", "", 10)
        pdf.set_xy(18, 9)
        pdf.cell(0, 5, "RANSOMWARE 207 | Incident Detection for a Ransomware Attack")

        pdf.set_text_color(*WHITE)
        pdf.set_font("Body", "B", 22)
        pdf.set_xy(18, 17)
        pdf.multi_cell(pdf.w - 36, 10, title, new_x="LMARGIN", new_y="NEXT")

        pdf.set_text_color(*TEXT)
        pdf.set_font("Body", "", 13)
        pdf.set_xy(22, 48)

        for bullet in bullets:
            pdf.set_x(22)
            pdf.set_font("Body", "B", 13)
            pdf.cell(6, 8, "-")
            pdf.set_font("Body", "", 12.5)
            pdf.multi_cell(pdf.w - 52, 7.4, bullet, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1.5)

        pdf.set_text_color(*GREY)
        pdf.set_font("Body", "", 9)
        pdf.set_xy(pdf.w - 40, pdf.h - 12)
        pdf.cell(30, 5, f"{index} / {total}", align="R")

    target = output_dir / doc.filename
    pdf.output(str(target))
    return target
