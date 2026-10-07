"""Pull connectors (ING-1). One module per source, cursor kept in Postgres."""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

from shoc.errors import NotFound
from shoc.ingest.connectors.base import Connector, connector_of


def get(source: str) -> Connector:
    source = connector_of(source)
    if source in push_sources():
        raise NotFound(
            f"'{source}' is a push source: POST its records to /ingest/{source} "
            "instead of polling it"
        )
    if source not in available():
        raise NotFound(f"unknown connector '{source}' (have: {', '.join(available())})")
    return _module(source).CONNECTOR


def _module(name: str) -> ModuleType:
    return importlib.import_module(f"{__name__}.{name}")


def available() -> list[str]:
    """Every module in this package that defines a CONNECTOR, so a new source is
    one module and one mapping (ING-4). The auth helpers define none."""
    return sorted(
        m.name for m in pkgutil.iter_modules(__path__) if hasattr(_module(m.name), "CONNECTOR")
    )


def push_sources() -> list[str]:
    """Sources that can only be pushed to: a mapping with no pull connector
    (ING-2). None today: every vendor shoc supports has an API to poll."""
    from shoc.ingest import ocsf

    return sorted(set(ocsf.available_sources()) - set(available()))


def also_push() -> list[str]:
    """Pull connectors whose vendor also pushes, in the vendor's own form: a
    module that parses the push defines `from_webhook` (GitHub's organisation
    webhook, for plans without the audit-log API)."""
    return [name for name in available() if hasattr(_module(name), "from_webhook")]


def accepts_push(source: str) -> bool:
    name = connector_of(source)
    return name in push_sources() or name in also_push()


def pushed(source: str, secret: dict) -> bool:
    """A push key alone is no pull credential: the vendor sends, there is no page to ask for (ING-2)."""
    return accepts_push(source) and not set(secret) - {"push_key"}


__all__ = [
    "Connector",
    "accepts_push",
    "also_push",
    "available",
    "connector_of",
    "get",
    "push_sources",
    "pushed",
]
