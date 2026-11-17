"""Generate the diagrams embedded in docs/02_Diagrams.pdf.

Run from the repository root:
    python docs_src/make_diagrams.py

The images are deterministic Pillow drawings, so the diagram set can be
regenerated on any Windows machine with the same fonts.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "images"
OUT.mkdir(parents=True, exist_ok=True)

NAVY = (31, 42, 68)
ACCENT = (176, 58, 46)
GREY = (105, 112, 124)
TEXT = (33, 37, 41)
WHITE = (255, 255, 255)
BLUE = (232, 240, 250)
GREEN = (232, 246, 239)
AMBER = (255, 246, 230)
RED = (253, 236, 235)

FONT = r"C:\Windows\Fonts\segoeui.ttf"
FONT_BOLD = r"C:\Windows\Fonts\segoeuib.ttf"

TITLE = ImageFont.truetype(FONT_BOLD, 38)
SUBTITLE = ImageFont.truetype(FONT, 20)
HEAD = ImageFont.truetype(FONT_BOLD, 22)
BODY = ImageFont.truetype(FONT, 16)
SMALL = ImageFont.truetype(FONT, 14)
TINY = ImageFont.truetype(FONT, 12)


def new_canvas(width: int, height: int, title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)
    draw.text((width / 2, 24), title, font=TITLE, fill=NAVY, anchor="ma")
    draw.text((width / 2, 74), subtitle, font=SUBTITLE, fill=GREY, anchor="ma")
    draw.line([60, 112, width - 60, 112], fill=(220, 224, 230), width=2)
    return image, draw


def box(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    w: float,
    h: float,
    title: str,
    lines: list[str] | tuple[str, ...] = (),
    fill: tuple[int, int, int] = WHITE,
    outline: tuple[int, int, int] = NAVY,
    title_font: ImageFont.FreeTypeFont = HEAD,
    body_font: ImageFont.FreeTypeFont = BODY,
) -> None:
    draw.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=fill, outline=outline, width=3)
    draw.text((x + w / 2, y + 14), title, font=title_font, fill=NAVY, anchor="ma")
    yy = y + 47

    for line in lines:
        draw.text((x + w / 2, yy), line, font=body_font, fill=TEXT, anchor="ma")
        yy += 23


def store(draw: ImageDraw.ImageDraw, x: float, y: float, w: float, h: float, title: str, sub: str = "") -> None:
    """Classic DFD open-ended data store."""

    draw.line([x, y, x, y + h], fill=NAVY, width=3)
    draw.line([x + 30, y, x + 30, y + h], fill=NAVY, width=3)
    draw.line([x, y, x + w, y], fill=NAVY, width=3)
    draw.line([x, y + h, x + w, y + h], fill=NAVY, width=3)
    draw.line([x + w, y, x + w, y + h], fill=NAVY, width=3)
    draw.text((x + w / 2, y + 12), title, font=BODY, fill=NAVY, anchor="ma")

    if sub:
        draw.text((x + w / 2, y + 38), sub, font=SMALL, fill=TEXT, anchor="ma")


def arrow(
    draw: ImageDraw.ImageDraw,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    color: tuple[int, int, int] = GREY,
    width: int = 3,
) -> None:
    draw.line([x1, y1, x2, y2], fill=color, width=width)
    dx, dy = x2 - x1, y2 - y1
    length = max((dx * dx + dy * dy) ** 0.5, 1)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    base = (x2 - 16 * ux, y2 - 16 * uy)
    draw.polygon(
        [(x2, y2), (base[0] + 8 * px, base[1] + 8 * py), (base[0] - 8 * px, base[1] - 8 * py)],
        fill=color,
    )


def elbow(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[float, float]],
    color: tuple[int, int, int] = GREY,
    width: int = 3,
) -> None:
    for (x1, y1), (x2, y2) in zip(points, points[1:-1]):
        draw.line([x1, y1, x2, y2], fill=color, width=width)

    arrow(draw, *points[-2], *points[-1], color=color, width=width)


def tag(draw: ImageDraw.ImageDraw, x: float, y: float, text: str, anchor: str = "la") -> None:
    bbox = draw.textbbox((0, 0), text, font=TINY)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]

    if anchor == "ma":
        x -= w / 2
    elif anchor == "ra":
        x -= w

    draw.rectangle([x - 3, y - 1, x + w + 3, y + h + 1], fill=WHITE)
    draw.text((x, y), text, font=TINY, fill=GREY, anchor=anchor)


def ellipse(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    w: float,
    h: float,
    text: str,
    fill: tuple[int, int, int] = BLUE,
) -> None:
    draw.ellipse([x, y, x + w, y + h], fill=fill, outline=NAVY, width=2)
    draw.multiline_text((x + w / 2, y + h / 2), text, font=SMALL, fill=TEXT, anchor="mm", align="center")


def context() -> None:
    image, d = new_canvas(
        1800,
        1000,
        "Figure 1 — System context (DFD level 0)",
        "Who uses Repo-Canary, what enters it, and what evidence leaves it.",
    )

    box(d, 640, 380, 520, 210, "Repo-Canary", [
        "watch · decide · persist · enrich · report",
        "engine + dashboard + SQLite evidence store",
    ], fill=BLUE, outline=NAVY)

    box(d, 80, 380, 420, 150, "Lab operator / simulator", ["runs reset and drill", "file activity in testdata"], fill=GREEN)
    box(d, 640, 160, 520, 120, "Sysmon 15", ["Event ID 11 FileCreate", "PID + image + timestamp"], fill=AMBER, outline=ACCENT)
    box(d, 1240, 160, 420, 120, "Threat-intel feed", ["known SHA-256 hashes", "local text file"], fill=AMBER, outline=ACCENT)
    box(d, 1240, 380, 420, 150, "Security analyst", ["browser dashboard", "filters and exports"], fill=GREEN)
    box(d, 640, 820, 520, 110, "Incident report consumer", ["opens INC-*.pdf", "reads evidence"], fill=GREEN)

    store(d, 640, 660, 520, 90, "D1  canary.db", "findings · baseline · counters")
    store(d, 1240, 660, 420, 90, "D2  reports/", "PDF incident reports")

    arrow(d, 500, 430, 638, 430)
    tag(d, 520, 400, "file events")
    arrow(d, 900, 280, 820, 378)
    tag(d, 700, 330, "Event ID 11")
    arrow(d, 1450, 280, 1160, 378)
    tag(d, 1340, 330, "hash match")
    arrow(d, 1160, 430, 1238, 430)
    arrow(d, 900, 590, 900, 658)
    tag(d, 910, 615, "INSERT / SELECT")
    arrow(d, 1160, 705, 1238, 705)
    tag(d, 1166, 675, "write PDF")
    arrow(d, 900, 750, 900, 818)
    tag(d, 910, 775, "evidence")

    d.text((60, 930), "Dashed trust boundary: the lab VM. The dashboard never writes; the engine owns the database and reports.",
           font=SMALL, fill=GREY)
    image.save(OUT / "diagram_context.png")


def dfd1() -> None:
    image, d = new_canvas(
        1900,
        1250,
        "Figure 2 — Data-flow diagram (DFD level 1)",
        "Processes, stores and external feeds that turn one file write into one finding.",
    )

    box(d, 70, 150, 300, 110, "Simulator", ["harmless .txt drill", "marked lab only"], fill=GREEN)
    box(d, 470, 150, 350, 120, "P1 watchdog", ["Observer events", "create/modify/move/delete"], fill=BLUE)
    box(d, 900, 150, 350, 120, "P2 Detection rules", ["canary + mass change", "debounce + cooldown"], fill=BLUE)
    box(d, 70, 390, 300, 120, "D1 testdata", ["3 canaries + 20 files", "watched recursively"], fill=GREEN)
    box(d, 470, 390, 350, 130, "P3 Integrity monitor", ["startup + periodic", "SHA-256/size/mtime"], fill=AMBER, outline=ACCENT)
    box(d, 900, 390, 400, 130, "P4 Enrichment", ["Sysmon correlation + psutil", "SHA-256 + intel match"], fill=BLUE)
    box(d, 1380, 560, 380, 110, "P5 Incident reporter", ["fpdf2 PDF", "async throttle"], fill=BLUE)
    box(d, 1380, 940, 380, 100, "P6 Dashboard API", ["read-only JSON", "static index.html"], fill=GREEN)
    box(d, 1540, 150, 300, 110, "Sysmon 15", ["Event ID 11", "PID + path + time"], fill=AMBER, outline=ACCENT)
    box(d, 1540, 300, 300, 110, "Hash feed", ["known_hashes.txt", "hot reload"], fill=AMBER, outline=ACCENT)
    box(d, 1380, 1110, 380, 90, "Analyst browser", ["2 s polling", "filters / export"], fill=GREEN)

    store(d, 900, 760, 400, 100, "D2 canary.db", "findings · baseline · counters")
    store(d, 1380, 760, 380, 90, "D3 reports/", "INC-*.pdf")

    arrow(d, 370, 205, 468, 205)
    tag(d, 380, 175, "writes")

    elbow(d, [(370, 435), (430, 435), (430, 205), (468, 205)])
    tag(d, 390, 300, "file events")

    arrow(d, 820, 205, 898, 205)
    tag(d, 830, 175, "normalised events")

    arrow(d, 370, 455, 468, 455)
    tag(d, 380, 425, "read canaries")

    elbow(d, [(1000, 270), (850, 270), (850, 810), (898, 810)])
    tag(d, 860, 620, "INSERT finding")

    arrow(d, 1150, 270, 1150, 388)
    tag(d, 1160, 310, "queue")

    elbow(d, [(640, 520), (640, 810), (898, 810)])
    tag(d, 650, 650, "baseline scan finding")

    arrow(d, 1075, 520, 1075, 758)
    tag(d, 1085, 650, "UPDATE row")

    arrow(d, 1540, 205, 1300, 425)
    tag(d, 1540, 270, "Event 11")
    arrow(d, 1540, 355, 1300, 470)
    tag(d, 1540, 400, "hashes")

    arrow(d, 1300, 450, 1378, 610)
    tag(d, 1305, 540, "report queue")

    arrow(d, 1570, 670, 1570, 758)
    tag(d, 1580, 700, "PDF")

    arrow(d, 1300, 810, 1378, 990)
    tag(d, 1305, 850, "SELECT")

    arrow(d, 1570, 1040, 1570, 1108)
    tag(d, 1580, 1060, "JSON")

    d.text((70, 650), "P1/P2 run on the watchdog thread and persist first. P3 shares the same findings\n"
                      "table, so a startup or periodic scan is indistinguishable to the dashboard.\n"
                      "P4/P5 are asynchronous workers; a slow Sysmon, hash or PDF never loses the alert.",
           font=SMALL, fill=GREY, spacing=8)
    image.save(OUT / "diagram_dfd1.png")


def usecase() -> None:
    image, d = new_canvas(
        1800,
        1220,
        "Figure 3 — Use-case diagram",
        "Actors outside the system and the capabilities the project demonstrates.",
    )

    d.rounded_rectangle([470, 140, 1710, 1080], radius=18, fill=(250, 251, 253), outline=NAVY, width=3)
    d.text((1090, 155), "Repo-Canary", font=HEAD, fill=NAVY, anchor="ma")

    cases = [
        (650, 210, 330, 90, "Reset / start lab", BLUE),
        (1050, 210, 300, 90, "Run harmless drill", BLUE),
        (650, 450, 330, 90, "Detect canary", RED),
        (1050, 450, 300, 90, "Detect mass change", RED),
        (1420, 450, 250, 90, "Hash + match intel", BLUE),
        (650, 690, 330, 90, "Attribute process", BLUE),
        (1050, 690, 300, 90, "Verify baseline", AMBER),
        (1420, 690, 250, 90, "Generate PDF", BLUE),
        (650, 930, 330, 90, "View dashboard", GREEN),
        (1050, 930, 300, 90, "Filter / export findings", GREEN),
        (1420, 930, 250, 90, "Review incident evidence", GREEN),
    ]

    # Connectors are drawn first so the ellipses stay readable on top of them.
    connectors = [
        [(175, 305), (650, 255)],
        [(175, 305), (600, 315), (1050, 315), (1050, 300)],
        [(175, 785), (650, 735)],
        [(175, 1025), (650, 975)],
        [(175, 1025), (1050, 975)],
        [(175, 1025), (1420, 975)],
    ]

    for points in connectors:
        for (x1, y1), (x2, y2) in zip(points, points[1:]):
            d.line([x1, y1, x2, y2], fill=(186, 191, 201), width=2)

    for label, y in (("Lab operator / simulator", 255), ("Sysmon", 735), ("Security analyst", 975)):
        d.ellipse([100, y - 30, 160, y + 30], outline=NAVY, width=3, fill=WHITE)
        d.line([130, y + 30, 130, y + 80], fill=NAVY, width=3)
        d.line([90, y + 50, 170, y + 50], fill=NAVY, width=3)
        d.line([130, y + 80, 95, y + 125], fill=NAVY, width=3)
        d.line([130, y + 80, 165, y + 125], fill=NAVY, width=3)
        d.text((130, y + 145), label, font=BODY, fill=NAVY, anchor="ma")

    for x, y, w, h, text, fill in cases:
        ellipse(d, x, y, w, h, text, fill=fill)

    d.text((60, 1170), "The lab operator runs the simulator. Hash + match intel and Generate PDF are automatic capabilities.",
           font=SMALL, fill=GREY)
    image.save(OUT / "diagram_usecase.png")


def sequence() -> None:
    image, d = new_canvas(
        1900,
        1250,
        "Figure 4 — Detection sequence",
        "One file write, from the simulator to the dashboard, including the asynchronous workers.",
    )

    lanes = [
        (150, "Simulator"),
        (420, "watchdog"),
        (690, "Rules"),
        (960, "SQLite"),
        (1230, "Enrichment"),
        (1500, "Reporter"),
        (1770, "Dashboard"),
    ]

    for x, name in lanes:
        d.rounded_rectangle([x - 115, 145, x + 115, 195], radius=10, fill=NAVY)
        d.text((x, 170), name, font=BODY, fill=WHITE, anchor="mm")
        d.line([x, 195, x, 1160], fill=(200, 205, 214), width=2)

    steps = [
        (250, 150, 420, "1. writes _canary_01.txt"),
        (330, 420, 690, "2. MODIFIED event"),
        (410, 690, 960, "3. canary rule fires"),
        (490, 960, 1230, "4. INSERT finding + queue"),
        (570, 1230, 960, "5. read finding"),
        (650, 1230, 960, "6. UPDATE hash/process"),
        (730, 1230, 1500, "7. queue report"),
        (810, 1500, 960, "8. attach report path"),
        (890, 1770, 960, "9. SELECT (2 s poll)"),
        (970, 960, 1770, "10. JSON rows"),
    ]

    for y, x1, x2, label in steps:
        arrow(d, x1, y, x2, y, color=ACCENT if x1 < x2 else NAVY)
        mid = (x1 + x2) / 2
        d.rectangle([mid - 120, y - 20, mid + 120, y - 4], fill=WHITE)
        d.text((mid, y - 12), label, font=SMALL, fill=TEXT, anchor="mm")

    d.rectangle([50, 825, 900, 900], fill=WHITE)
    d.text((60, 835), "Steps 1–4 are synchronous on the watchdog thread; 5–8 happen on the enrichment and reporting\n"
                      "workers; 9–10 are the dashboard's read-only polling loop. Enrichment also queries Sysmon Event ID 11\n"
                      "and the local hash feed; those feeds are external and are not drawn as lanes.",
           font=SMALL, fill=GREY, spacing=8)
    d.rectangle([50, 915, 900, 990], fill=WHITE)
    d.text((60, 925), "The finding is persisted before enrichment on purpose: a slow Sysmon channel, hash or PDF never\n"
                       "loses the alert. Every worker is bounded and its failures are logged, not fatal.",
           font=SMALL, fill=GREY, spacing=8)
    image.save(OUT / "diagram_sequence.png")


def er() -> None:
    image, d = new_canvas(
        1900,
        1300,
        "Figure 5 — Entity-relationship diagram",
        "The seven SQLite tables, their keys and the relationships used by the API.",
    )

    box(d, 700, 330, 600, 390, "findings", [
        "PK id",
        "occurred_at · severity · severity_rank",
        "rule · trigger_rule · summary · path",
        "FK process_id · pid · attribution_method",
        "file_sha256 · intel_label · matched_hash",
        "report_path · report_created_at",
        "source · UNIQUE dedupe_key · created_at",
    ], fill=RED, title_font=HEAD, body_font=SMALL)

    box(d, 80, 330, 470, 270, "processes", [
        "PK id",
        "name · exe_path · cmdline",
        "username",
        "first_seen · last_seen",
    ], fill=BLUE, title_font=HEAD, body_font=SMALL)

    box(d, 1360, 140, 460, 220, "known_hashes", [
        "PK sha256 (64 hex)",
        "label",
        "source · added_at",
    ], fill=AMBER, title_font=HEAD, body_font=SMALL)

    box(d, 1360, 410, 460, 230, "canary_baseline", [
        "PK name",
        "sha256 (64 hex) · size",
        "mtime_ns · captured_at",
    ], fill=AMBER, title_font=HEAD, body_font=SMALL)

    box(d, 80, 760, 470, 220, "event_counters", [
        "PK (minute, event_type)",
        "count",
    ], fill=GREEN, title_font=HEAD, body_font=SMALL)

    box(d, 700, 830, 600, 220, "engine_state", [
        "PK id (always 1)",
        "started_at · last_heartbeat",
        "watch_dir · version",
    ], fill=GREEN, title_font=HEAD, body_font=SMALL)

    # Relationships
    arrow(d, 550, 470, 698, 470, color=NAVY, width=3)
    tag(d, 565, 440, "1 process -> N findings")
    d.line([1360, 250, 1300, 250], fill=GREY, width=2)
    d.line([1300, 250, 1300, 380], fill=GREY, width=2)
    arrow(d, 1300, 380, 1300, 430, color=GREY, width=2)
    tag(d, 1120, 260, "hash lookup (logical, no FK)")
    d.line([1360, 525, 1300, 525], fill=GREY, width=2)

    d.text((80, 1080), "Indexes: occurred_at, severity, rule, process_id, file_sha256 and severity_rank.\n"
                       "canary_baseline is the only table written by reset_lab.py; the engine reads it during scans.",
           font=SMALL, fill=GREY, spacing=8)
    image.save(OUT / "diagram_er.png")


def deployment() -> None:
    image, d = new_canvas(
        1900,
        1120,
        "Figure 6 — Deployment topology",
        "The native Windows lab and the two-container compose stack use the same SQLite contract.",
    )

    d.rounded_rectangle([60, 140, 900, 1030], radius=18, fill=(250, 251, 253), outline=NAVY, width=3)
    d.text((480, 155), "Native Windows lab", font=HEAD, fill=NAVY, anchor="ma")
    box(d, 130, 230, 300, 130, "Detection engine", ["python scripts/detection_engine.py", "observer + workers"], fill=BLUE)
    box(d, 530, 230, 300, 130, "Dashboard server", ["python scripts/dashboard_server.py", "127.0.0.1:8000"], fill=GREEN)
    box(d, 130, 470, 300, 150, "C:\\RansomwareLab", ["testdata/ · canary.db", "reports/ · logs"], fill=WHITE)
    box(d, 530, 470, 300, 110, "Sysmon 15", ["Event ID 11", "readable channel"], fill=AMBER, outline=ACCENT)
    box(d, 130, 720, 300, 110, "Browser", ["http://127.0.0.1:8000", "2 s polling"], fill=GREEN)

    arrow(d, 280, 360, 280, 468)
    tag(d, 290, 400, "writes findings")
    elbow(d, [(680, 360), (680, 430), (430, 430), (430, 468)])
    tag(d, 610, 398, "reads SQLite")
    arrow(d, 680, 470, 430, 360)
    tag(d, 450, 410, "Event 11")
    elbow(d, [(430, 775), (880, 775), (880, 295), (830, 295)])
    tag(d, 700, 750, "HTTP :8000")

    d.rounded_rectangle([1000, 140, 1840, 1030], radius=18, fill=(250, 251, 253), outline=NAVY, width=3)
    d.text((1420, 155), "Docker Compose stack", font=HEAD, fill=NAVY, anchor="ma")
    box(d, 1080, 240, 300, 140, "engine container", ["repo-canary:latest", "uid 10001 · no published port"], fill=BLUE)
    box(d, 1460, 240, 300, 140, "dashboard container", ["same image", "127.0.0.1:8000"], fill=GREEN)
    box(d, 1080, 500, 680, 140, "canary-data named volume", ["/data/lab/testdata", "canary.db · reports/ · logs"], fill=WHITE)
    box(d, 1080, 740, 680, 90, "Host browser", ["http://127.0.0.1:8000", "healthcheck /api/health"], fill=GREEN)

    arrow(d, 1230, 380, 1230, 498)
    tag(d, 1240, 420, "shared volume")
    arrow(d, 1610, 380, 1610, 498)
    tag(d, 1620, 420, "read-only")
    elbow(d, [(1760, 310), (1810, 310), (1810, 785), (1760, 785)])
    tag(d, 1700, 700, "HTTP :8000")

    d.text((60, 1070), "Windows note: the compose file uses a named volume because inotify from a Windows bind mount may not propagate.\n"
                       "Containers have no Sysmon, so attribution there is 'none' by design; run natively for process evidence.",
           font=SMALL, fill=GREY, spacing=7)
    image.save(OUT / "diagram_deployment.png")


if __name__ == "__main__":
    context()
    dfd1()
    usecase()
    sequence()
    er()
    deployment()
    print("wrote 6 diagrams to", OUT)
