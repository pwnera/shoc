"""Rules and hunt packs adapt only what an Apache 2.0 repository may carry."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.support import ROOT

ADAPTABLE = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "DRL-1.1"}
CONTENT = sorted(p for d in ("rules", "hunts") for p in (ROOT / "content" / d).glob("*.yaml"))


@pytest.mark.parametrize("path", CONTENT, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_adapted_sources_carry_a_compatible_licence(path: Path):
    for source in yaml.safe_load(path.read_text()).get("sources") or []:
        url = source["url"]
        assert source.get("relation") in ("adapted", "inspired"), url
        if source["relation"] == "adapted":
            assert source.get("license") in ADAPTABLE, f"{url}: not adaptable, mark it inspired"
        if source.get("license") == "DRL-1.1":
            assert source.get("author"), f"{url}: DRL-1.1 requires the author"
