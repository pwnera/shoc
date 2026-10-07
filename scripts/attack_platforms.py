"""Write content/attack_platforms.json: the platforms of each ATT&CK Enterprise technique.

The Detection Engineer's nightly sweep leaves a technique a report named off
its backlog when none of the technique's platforms is one a connected source
sees (DET-2): a credential-dumping technique is Windows, Linux and macOS, and a
tenant that sends only SaaS audit logs cannot look for it. Run this when MITRE
publishes a new ATT&CK version:

    python scripts/attack_platforms.py
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).resolve().parent.parent / "content" / "attack_platforms.json"
# MITRE's terms of use ask every copy to carry its copyright designation and licence.
NOTICE = (
    "© {year} The MITRE Corporation. This work is reproduced and distributed with the "
    "permission of The MITRE Corporation. MITRE hereby grants you a non-exclusive, "
    "royalty-free license to use ATT&CK® for research, development, and commercial "
    "purposes. Any copy you make for such purposes is authorized provided that you "
    "reproduce MITRE's copyright designation and this license in any such copy. "
    "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
)


def main() -> None:
    with urllib.request.urlopen(URL, timeout=300) as resp:
        bundle = json.load(resp)
    version, year, platforms = "", "", {}
    for obj in bundle["objects"]:
        if obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version", ""))
            year = str(obj.get("modified", ""))[:4]
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        if obj.get("x_mitre_deprecated"):
            continue
        tid = next(
            (
                r["external_id"]
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            "",
        )
        if tid:
            platforms[tid] = sorted(obj.get("x_mitre_platforms", []))
    lines = [f"  {json.dumps(k)}: {json.dumps(v)}" for k, v in sorted(platforms.items())]
    OUT.write_text(
        "{\n"
        f'  "notice": {json.dumps(NOTICE.format(year=year), ensure_ascii=False)},\n'
        f'  "attack_version": {json.dumps(version)},\n'
        '  "platforms": {\n  ' + ",\n  ".join(lines) + "\n  }\n}\n",
        encoding="utf-8",
    )
    print(f"{len(platforms)} techniques, ATT&CK {version} -> {OUT}")


if __name__ == "__main__":
    main()
