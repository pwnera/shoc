"""Stored ids: a prefix and the sha256 of the parts joined with `|`.

The ids are keys in the database, so a caller keeps its parts, their order and
their string forms (`isoformat()`, `case_uid or ''`) exactly as they were.
"""

from __future__ import annotations

import hashlib


def make_id(prefix: str, *parts: str, length: int = 20) -> str:
    return prefix + hashlib.sha256("|".join(parts).encode()).hexdigest()[:length]
