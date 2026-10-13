"""The Surveyor's host link matches a host by name, not by pattern (D80)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from shoc.agents import surveyor


class _Store:
    """Answers only the host lookup; records every statement it is sent."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def query(self, sql: str, params: dict[str, Any], limit: int) -> Any:
        self.sent.append((sql, params))
        rows = [{"device_hostname": self.host}] if "DISTINCT device_hostname" in sql else []
        return SimpleNamespace(rows=rows, truncated=False)


def test_a_hostnames_underscore_and_backslash_are_escaped():
    store = _Store("LAP_TOP\\21.example.org")
    surveyor.logins(store, "t1", "user:alice@example.com")
    [(sql, params)] = [(s, p) for s, p in store.sent if "LIKE :h0" in s]
    assert "LIKE :h0 ESCAPE '!'" in sql
    assert params["h0"] == "lap!_top\\21%", "an `_` would match any one character"
