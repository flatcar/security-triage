#!/usr/bin/env python3
"""Render workflow-architecture.md (with mermaid code fences) to PDF.

Steps:
1. Extract each ```mermaid fenced block from the source markdown.
2. Render each block to an SVG using @mermaid-js/mermaid-cli (npx mmdc).
3. Write a PDF-build markdown copy with mermaid fences replaced by image refs.
4. Convert that copy to PDF with pandoc + tectonic.
"""
from __future__ import annotations
import re
import subprocess
import sys
from pathlib import Path

DOCS_DIR = Path(__file__).parent
SRC_MD = DOCS_DIR / "workflow-architecture.md"
DIAGRAMS_DIR = DOCS_DIR / "diagrams"
BUILD_MD = DOCS_DIR / "_build" / "workflow-architecture.pdf-source.md"
OUT_PDF = DOCS_DIR / "workflow-architecture.pdf"

MERMAID_FENCE = re.compile(r"```mermaid\n(.*?)\n```\n", re.DOTALL)


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
        svg_path = DIAGRAMS_DIR / f"diagram-{i:02d}.svg"
        png_path = DIAGRAMS_DIR / f"diagram-{i:02d}.png"
        new_content = m.group(1) + "\n"
        needs_render = (
            "--force" in sys.argv
            or not png_path.exists()
            or not mmd_path.exists()
            or mmd_path.read_text() != new_content
        )
        mmd_path.write_text(new_content)

        if needs_render:
            print(f"Rendering diagram {i}...")
            subprocess.run(
                [
                    "npx", "-y", "@mermaid-js/mermaid-cli",
                    "-i", str(mmd_path),
                    "-o", str(png_path),
                    "-b", "white",
                    "-s", "2",
                    "-w", "1400",
                ],
                check=True,
                cwd=DOCS_DIR,
            )
        else:
            print(f"Skipping diagram {i} (unchanged, cached png)")
        out_parts.append(f"![Diagram {i}]({png_path.relative_to(DOCS_DIR)})\n\n")
        last_end = m.end()
    out_parts.append(text[last_end:])

    BUILD_MD.write_text("".join(out_parts))
    print(f"Wrote build markdown to {BUILD_MD}")

    # Insert an explicit page break before every level-2 "## N. Title" section
    # (except the very first one, which follows the title page/TOC already).
    # Combined with forced-"here" figure placement, this avoids the awkward
    # near-blank pages that otherwise result when a tall diagram doesn't fit
    # in the remaining space under its heading.
    built = BUILD_MD.read_text()
    section_re = re.compile(r"(?m)^(## \d+\. .+)$")
    parts = section_re.split(built)
    rebuilt = [parts[0]]
    for i in range(1, len(parts), 2):
        heading = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        if i == 1:
            rebuilt.append(heading + body)
        else:
            rebuilt.append("\n```{=latex}\n\\newpage\n```\n\n" + heading + body)
    BUILD_MD.write_text("".join(rebuilt))

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
            "--toc",
            "--toc-depth=2",
            "-V", "linkcolor=blue",
            "-H", str(header_tex),
            "--metadata", "title=Flatcar Security Triage: Workflow and Architecture",
        ],
        check=True,
        cwd=DOCS_DIR,
    )
    print(f"Wrote PDF to {OUT_PDF}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
