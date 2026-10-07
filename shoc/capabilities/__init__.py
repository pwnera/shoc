"""Capabilities: the product surface. Add an operation here, never in a surface."""

from shoc.capabilities.registry import (
    Caller,
    Capability,
    Context,
    Result,
    all_capabilities,
    call,
    capability,
    get,
    load,
)

__all__ = [
    "Caller",
    "Capability",
    "Context",
    "Result",
    "all_capabilities",
    "call",
    "capability",
    "get",
    "load",
]
