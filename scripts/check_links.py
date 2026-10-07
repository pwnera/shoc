#!/usr/bin/env python3
"""Check that every relative Markdown link, and every link to a file in this repo on
GitHub, points at a file that exists."""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SKIP_PREFIX = ("http://", "https://", "mailto:", "#")
# docs/ links to files outside it this way, since the docs site only serves docs/ (D68).
REPO = re.compile(r"https://github\.com/pwnera/shoc/(?:blob|tree)/main/(.+)")
ROOTS = [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "CODE_OF_CONDUCT.md",
    "CLAUDE.md",
]


def main() -> int:
    files = [Path(p) for p in ROOTS if Path(p).exists()]
    files += sorted(Path("docs").rglob("*.md")) + sorted(Path("rfcs").rglob("*.md"))
    files += sorted(Path("console").glob("*.md"))
    broken: list[str] = []
    for path in files:
        for target in LINK.findall(path.read_text()):
            if m := REPO.match(target):
                resolved = Path(m[1].split("#", 1)[0]).resolve()
            elif target.startswith(SKIP_PREFIX):
                continue
            else:
                resolved = (path.parent / target.split("#", 1)[0]).resolve()
            if not resolved.exists():
                broken.append(f"{path}: {target}")
    for b in broken:
        print(f"FAIL broken link — {b}")
    if not broken:
        print(f"OK {len(files)} document(s), no broken relative links")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
