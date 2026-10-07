"""Response actions (RSP-4) and platform lookups (RFC 0014).

An action changes something and goes through the policy. A lookup only reads,
with the same credentials, and is what the crew calls while it investigates.
"""

from __future__ import annotations

import importlib
import pkgutil

import httpx

from shoc.actions.base import Action, ActionResult, BaseLookup, Credentials

_REGISTRY: dict[str, Action] = {}
_LOOKUPS: dict[str, BaseLookup] = {}
_loaded = False


def _load() -> None:
    global _loaded
    if not _loaded:
        import shoc.actions as pkg

        for mod in pkgutil.iter_modules(pkg.__path__):
            if not mod.name.startswith("_") and mod.name != "base":
                module = importlib.import_module(f"{pkg.__name__}.{mod.name}")
                for action in getattr(module, "ACTIONS", []):
                    _REGISTRY[action.type] = action
                for lookup in getattr(module, "LOOKUPS", []):
                    _LOOKUPS[lookup.type] = lookup
        _loaded = True


def load() -> dict[str, Action]:
    _load()
    return _REGISTRY


def lookups() -> dict[str, BaseLookup]:
    _load()
    return _LOOKUPS


def get(action_type: str) -> Action:
    from shoc.errors import NotFound

    actions = load()
    if action_type not in actions:
        raise NotFound(f"unknown action '{action_type}' (have: {', '.join(sorted(actions))})")
    return actions[action_type]


def get_lookup(name: str) -> BaseLookup:
    from shoc.errors import NotFound

    found = lookups()
    if name not in found:
        raise NotFound(f"unknown lookup '{name}' (have: {', '.join(sorted(found))})")
    return found[name]


def available() -> list[str]:
    return sorted(load())


def probe(creds: Credentials, http: httpx.Client | None = None) -> str | None:
    """One read that proves a response credential works, in a few words, or None
    when its provider has none to try: a PagerDuty routing key is only proven by
    a page. A refusal raises, as the vendor worded it."""
    from shoc.actions.base import NEEDS
    from shoc.cases.credentials import provider_of

    provider = provider_of(creds.provider)
    if provider not in NEEDS:
        return None
    check = getattr(importlib.import_module(f"{__name__}.{provider}"), "probe", None)
    return check(creds, http) if check else None


__all__ = [
    "Action",
    "ActionResult",
    "BaseLookup",
    "Credentials",
    "available",
    "get",
    "get_lookup",
    "load",
    "lookups",
    "probe",
]
