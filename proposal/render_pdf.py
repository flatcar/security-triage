#!/usr/bin/env python3
"""Render pipeline-proposal.md (with mermaid code fences) to PDF.

Steps:
1. Extract each ```mermaid fenced block from the source markdown.
2. Render each block to a PNG using @mermaid-js/mermaid-cli (npx mmdc).
3. Write a PDF-build markdown copy with mermaid fences replaced by image refs.
4. Convert that copy to PDF with pandoc + tectonic.
"""
from __future__ import annotations
import re
import subprocess
import sys
from pathlib import Path

DOCS_DIR = Path(__file__).parent
SRC_MD = DOCS_DIR / "pipeline-proposal.md"
DIAGRAMS_DIR = DOCS_DIR / "diagrams"
BUILD_MD = DOCS_DIR / "_build" / "pipeline-proposal.pdf-source.md"
OUT_PDF = DOCS_DIR / "pipeline-proposal.pdf"

MERMAID_FENCE = re.compile(r"```mermaid\n(.*?)\n```\n", re.DOTALL)

# Page geometry assumptions (margin=1in on US Letter -> 6.5in x 9in text area).
TEXT_WIDTH_IN = 6.5
MAX_WIDTH_PCT = 68  # default/ceiling width as a percent of text width
MAX_HEIGHT_IN = 5.0  # cap so a diagram always leaves room for a heading/caption
FULL_PAGE_HEIGHT_IN = 8.3  # just under textheight, leaves room for a caption
MIN_WIDTH_PCT = 30


def _pdf_points_size(path: Path) -> tuple[float, float]:
    """Read (width, height) in points from a single-page PDF's MediaBox."""
    out = subprocess.run(
        ["pdfinfo", str(path)], check=True, capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        if line.startswith("Page size:"):
            # "Page size:      400.5 x 1200.75 pts"
            nums = re.findall(r"[\d.]+", line.split(":", 1)[1])
            return float(nums[0]), float(nums[1])
    raise ValueError(f"Could not find page size in pdfinfo output for {path}")


def _width_pct_for(diagram_path: Path) -> int:
    """Pick a width percent that keeps tall/narrow diagrams under MAX_HEIGHT_IN.

    A fixed width percent for every diagram makes very tall flowcharts render
    almost a full page tall, which leaves no room to share a page with any
    heading/intro text and forces a near-blank page before it. Scaling width
    down for tall diagrams keeps them legible while letting them actually
    pack next to surrounding prose. Diagrams are vector PDFs, so shrinking
    never costs raster sharpness -- only layout/packing is being optimized.

    If a diagram is so extreme in aspect ratio that it hits the width floor
    even under the packing-friendly cap, it was never going to share a page
    with text anyway -- so re-size it against the full page height instead,
    to avoid needlessly shrinking it for no packing benefit.
    """
    pts_w, pts_h = _pdf_points_size(diagram_path)
    aspect = pts_h / pts_w
    width_in_by_width_cap = TEXT_WIDTH_IN * (MAX_WIDTH_PCT / 100)
    width_in_by_height_cap = MAX_HEIGHT_IN / aspect
    width_in = min(width_in_by_width_cap, width_in_by_height_cap)
    pct = round(width_in / TEXT_WIDTH_IN * 100)
    if pct <= MIN_WIDTH_PCT:
        width_in_full_page = FULL_PAGE_HEIGHT_IN / aspect
        width_in = min(width_in_by_width_cap, width_in_full_page)
        pct = round(width_in / TEXT_WIDTH_IN * 100)
    return max(MIN_WIDTH_PCT, pct)


def main() -> int:
    DIAGRAMS_DIR.mkdir(exist_ok=True)
    BUILD_MD.parent.mkdir(exist_ok=True)

    text = SRC_MD.read_text()
    matches = list(MERMAID_FENCE.finditer(text))
    print(f"Found {len(matches)} mermaid diagrams")

    out_parts = []
    last_end = 0
    for i, m in enumerate(matches, start=1):
        out_parts.append(text[last_end:m.start()])
        mmd_path = DIAGRAMS_DIR / f"diagram-{i:02d}.mmd"
        pdf_path = DIAGRAMS_DIR / f"diagram-{i:02d}.pdf"
        new_content = m.group(1) + "\n"
        needs_render = (
            "--force" in sys.argv
            or not pdf_path.exists()
            or not mmd_path.exists()
            or mmd_path.read_text() != new_content
        )
        mmd_path.write_text(new_content)

        if needs_render:
            print(f"Rendering diagram {i}...")
            # Render as a vector PDF (not PNG) so diagrams stay crisp no
            # matter how much they get shrunk to fit a page.
            subprocess.run(
                [
                    "npx", "-y", "@mermaid-js/mermaid-cli",
                    "-i", str(mmd_path),
                    "-o", str(pdf_path),
                    "-e", "pdf",
                    "--pdfFit",
                    "-b", "white",
                ],
                check=True,
                cwd=DOCS_DIR,
            )
        else:
            print(f"Skipping diagram {i} (unchanged, cached pdf)")
        width_pct = _width_pct_for(pdf_path)
        out_parts.append(
            "```{=latex}\n\\begin{center}\n```\n\n"
            f"![]({pdf_path.relative_to(DOCS_DIR)}){{width={width_pct}%}}\n\n"
            "```{=latex}\n\\end{center}\n```\n\n"
        )
        last_end = m.end()
    out_parts.append(text[last_end:])

    BUILD_MD.write_text("".join(out_parts))
    print(f"Wrote build markdown to {BUILD_MD}")

    # Confine floats (diagrams) to the heading section they appear under, so a
    # tall diagram can never drift past a later heading and leave two headings
    # stacked with nothing in between. This keeps the tight packing from
    # relaxed float placement without breaking document structure.
    built = BUILD_MD.read_text()
    # The title comes from pandoc metadata; drop the duplicate H1.
    built = re.sub(r"\A# .+\n", "", built)
    heading_re = re.compile(r"(?m)^(#{2,3} .+)$")
    built = heading_re.sub(
        r"\n```{=latex}\n\\FloatBarrier\n\\Needspace{8\\baselineskip}\n```\n\n\1", built
    )
    BUILD_MD.write_text(built)

    header_tex = DOCS_DIR / "_build_header.tex"
    subprocess.run(
        [
            "pandoc",
            str(BUILD_MD),
            "-o", str(OUT_PDF),
            "--pdf-engine=tectonic",
            "-V", "geometry:margin=1in",
            "-V", "colorlinks=true",
            "-V", "fontsize=10pt",
            "-V", "linkcolor=blue",
            "-H", str(header_tex),
            "--metadata", "title=Proposal: ETL-Based Security Pipeline with LLM-Assisted CVE Triage",
        ],
        check=True,
        cwd=DOCS_DIR,
    )
    print(f"Wrote PDF to {OUT_PDF}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
