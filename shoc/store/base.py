"""The `EventStore` interface every backend implements (STO-1).

The core never uses a warehouse-specific feature: it writes canonical SQL over
the OCSF tables and hands it to the adapter, which translates it with SQLGlot.
`tests/conformance` runs the same fixtures and rules against every adapter and
requires the same findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@dataclass
class LoadStats:
    rows: int = 0
    bytes: int = 0
    duration_ms: int = 0
    table: str = "ocsf_events"


@dataclass
class StoreHealth:
    dialect: str = "postgres"
    ok: bool = True
    event_count: int = 0
    latest_event: datetime | None = None
    latency_ms: int = 0
    detail: str = ""


@dataclass
class RetentionPolicy:
    days: int = 90
    table: str = "ocsf_events"


@dataclass
class QueryResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    sql: str = ""
    duration_ms: int = 0
    truncated: bool = False


@runtime_checkable
class EventStore(Protocol):
    dialect: str
    tenant_id: str

    def create_tenant(self) -> None:
        """Create the tenant's namespace and OCSF tables. Idempotent."""
        ...

    def migrate(self, ocsf_version: str = "1.3.0") -> None:
        """Bring the tenant's tables up to the current OCSF layout."""
        ...

    def load_batch(self, path: str, table: str = "ocsf_events") -> LoadStats:
        """Load a gzipped NDJSON batch. Duplicate event_uids are ignored."""
        ...

    def query(
        self, canonical_sql: str, params: dict[str, Any] | None = None, limit: int = 1000
    ) -> QueryResult:
        """Run canonical SQL, translated to this backend's dialect."""
        ...

    def apply_retention(self, policy: RetentionPolicy) -> int:
        """Drop data older than the policy. Returns rows or partitions removed."""
        ...

    def reset(self) -> None:
        """Delete every event for this tenant.

        Used by the conformance suite between cases, and by an operator who is
        re-ingesting a source from scratch. It never touches another tenant.
        """
        ...

    def health(self) -> StoreHealth: ...

    def close(self) -> None: ...
