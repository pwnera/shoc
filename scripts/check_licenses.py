#!/usr/bin/env python3
"""Fail the build unless every runtime dependency has a permissive licence.

Runtime means the core dependencies and everything they pull in, the set the
wheel and the image ship. A licence passes when its SPDX expression is built
from PERMISSIVE alone. Anything else, copyleft or unrecognised, fails until it
is reviewed and recorded in REVIEWED with the exact licence string accepted.
Run from the repo root: python -m scripts.check_licenses
"""

from __future__ import annotations

import sys
import tomllib
from importlib.metadata import distribution
from pathlib import Path

from scripts.check_dependency_budget import closure

# MIT-0 is MIT without the attribution clause (cffi 2.0 moved to it).
PERMISSIVE = {"MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "PSF-2.0"}
# Reviewed exceptions, pinned to the licence string that was accepted: a
# change of licence fails again.
REVIEWED = {
    "psycopg": "LGPL-3.0-only",  # used unmodified as a library (NOTICE)
    "psycopg-binary": "LGPL-3.0-only",  # the same library, prebuilt
    "certifi": "MPL-2.0",  # file-level copyleft; the CA bundle is shipped unmodified
}


def licence_of(name: str) -> str:
    meta = distribution(name).metadata
    return (meta.get("License-Expression") or meta.get("License") or "").strip()


def permitted(name: str, licence: str) -> bool:
    if name in REVIEWED:
        return licence == REVIEWED[name]
    # ponytail: a nested expression passes only if every licence in it is permissive
    if "(" in licence:
        ids = licence.replace("(", " ").replace(")", " ").replace(" OR ", " ").replace(" AND ", " ")
        return set(ids.split()) <= PERMISSIVE
    # Without parentheses AND binds tighter than OR (SPDX), so split on OR first.
    return any(set(a.split(" AND ")) <= PERMISSIVE for a in licence.split(" OR "))


def main() -> int:
    deps = tomllib.loads(Path("pyproject.toml").read_text())["project"]["dependencies"]
    bad = [(n, licence_of(n)) for n in sorted(closure(deps))]
    bad = [(n, lic) for n, lic in bad if not permitted(n, lic)]
    for name, lic in bad:
        print(
            f"FAIL {name}: {lic[:80] or 'no licence metadata'}; not on the permissive list, "
            "review it and record it in REVIEWED"
        )
    if not bad:
        print("OK every runtime dependency has a permissive or reviewed licence")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
