"""Connector contract and the run loop shared by every source (ING-1, ING-4).

A connector is one small object: it knows how to ask its API for events after a
cursor, and returns raw records plus the next cursor. Mapping, batching, dedup,
cursor persistence and health accounting all happen here, so a new source is one
module plus one mapping file.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx

from shoc.db.pool import execute, fetch_one
from shoc.ingest import batch as batchwriter
from shoc.ingest import ocsf, replay
from shoc.store.base import EventStore

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# How far before the newest event seen the next window starts. CloudTrail and
# Entra sign-ins, among others, deliver some events minutes after their
# timestamp, and a window that resumed exactly at the newest event would never
# read them. What the overlap reads again is dropped by the store, which keeps
# one row per event_uid and time.
OVERLAP = timedelta(minutes=15)


@dataclass
class FetchResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    cursor: dict[str, Any] = field(default_factory=dict)
    more: bool = False
    # Set when some streams of a source failed and the others were still read.
    error: str = ""


class Connector(Protocol):
    source: str

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult: ...


@dataclass
class Asset:
    """One thing a source's own API says exists, acting or not (D49).

    `entity` is typed the way the survey types events (`user:alice@example.com`),
    so a snapshot row and the events of the same thing land on one entity. A
    range the company declared to the vendor is `network:<cidr or a-b range>`.
    """

    entity: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)
    # The vendor's own last sign-in or check-in, when it keeps one.
    last_active: str | None = None


# A connector may also declare `snapshot(settings, secret) -> list[Asset]`: a
# pass over what exists, beside the log it ingests (D49). It runs with the
# source's pull, at most this often.
SNAPSHOT_EVERY = timedelta(hours=24)


def snapshot_due(conn: Any, tenant_id: str, source: str) -> bool:
    """True when the source's connector takes snapshots and none is recent."""
    from shoc.ingest.connectors import get

    try:
        if not hasattr(get(source), "snapshot"):
            return False
    except Exception:
        return False
    row = fetch_one(
        conn,
        "SELECT max(taken_at) AS at FROM shoc.snapshots WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    at = (row or {}).get("at")
    return at is None or datetime.now(UTC) - at >= SNAPSHOT_EVERY


def take_snapshot(
    conn: Any, tenant_id: str, source: str, settings: dict[str, Any], secret: dict[str, Any]
) -> int:
    """Replace what the source's API says exists. Something deleted at the vendor
    is gone after the next pass, so a snapshot never describes a user who left."""
    from shoc.ingest.connectors import get

    assets: list[Asset] = get(source).snapshot(settings, secret)  # type: ignore[attr-defined]
    execute(
        conn, "DELETE FROM shoc.snapshots WHERE tenant_id = %s AND source = %s", (tenant_id, source)
    )
    kept = {a.entity: a for a in assets}
    for asset in kept.values():
        execute(
            conn,
            """INSERT INTO shoc.snapshots
                   (tenant_id, source, entity, kind, attributes, last_active)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (
                tenant_id,
                source,
                asset.entity,
                asset.kind,
                json.dumps(asset.attributes, default=str),
                asset.last_active,
            ),
        )
    return len(kept)


@dataclass
class RunStats:
    source: str
    fetched: int = 0
    loaded: int = 0
    pages: int = 0
    cursor: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    detail: str | None = None


# What a rejected credential most likely lacks. The provider's own wording, and
# how to grant it, is in docs/connectors.md; this is the one line a person needs
# while reading an error. Every connector inherits it through `run`.
PERMISSION_HINTS = {
    "aws_cloudtrail": "cloudtrail:LookupEvents and ec2:DescribeRegions, or s3:ListBucket and s3:GetObject on the trail bucket",
    "aws_guardduty": "guardduty:ListDetectors, ListFindings and GetFindings, and ec2:DescribeRegions",
    "azure_activity": "Reader on the subscription",
    "gcp_audit": "roles/pubsub.subscriber on the sink's subscription (or roles/logging.viewer without one)",
    "okta": "an API token of a read-only administrator, which reads the System Log, users and network zones",
    "entra": "Graph AuditLog.Read.All and Directory.Read.All",
    "google_workspace": "domain-wide delegation for admin.reports.audit.readonly",
    "m365": "ActivityFeed.Read on the Management API",
    "defender": "Graph SecurityAlert.Read.All",
    "defender_hunting": "Storage Blob Data Reader on the Streaming API's storage account",
    "crowdstrike": "an API client with the Alerts: read scope",
    "crowdstrike_fdr": "the key pair of a Falcon Data Replicator feed, which CrowdStrike scopes to the feed's SQS queue and S3 bucket",
    "sentinelone": "a service-user token with viewer rights",
    "sentinelone_cloudfunnel": "s3:ListBucket and s3:GetObject on the Cloud Funnel bucket",
    "github": "a fine-grained token with organisation Administration: read",
    "gitlab": "a token with read_api (instance-wide events need an administrator)",
    "wazuh": "an indexer user with read on wazuh-alerts-*",
    "cloudflare": "an account API token with Account Settings: Read",
    "cloudflare_logs": "an R2 API token with Object Read on the Logpush bucket, or s3:ListBucket and s3:GetObject on it",
    "tailscale": "an OAuth client with the logs:configuration:read scope",
    "stripe": "a restricted key with Activity logs: read and Events: read",
    "openai": "an Admin key with audit logs read, which only an organization owner can create",
    "anthropic": "an Admin API key, which only an organization admin can create",
}


# Where to create that credential: the connect form shows it, and the
# Integrator (D50) hands it to the operator when a source waits on one.
WHERE = {
    "aws_cloudtrail": "IAM → Users → Create user, with a policy allowing cloudtrail:LookupEvents and ec2:DescribeRegions → Security credentials → Create access key",
    "aws_guardduty": "IAM → Users → Create user, with AmazonGuardDutyReadOnlyAccess and a policy allowing ec2:DescribeRegions → Security credentials → Create access key",
    "azure_activity": "Subscription → Access control (IAM) → Add role assignment → Reader, for the app registration used for Entra ID",
    "gcp_audit": 'Logging → Log router → Create sink: filter logName:"cloudaudit.googleapis.com", destination a new Pub/Sub topic → Pub/Sub → the topic → Create subscription, pull → service account with Pub/Sub Subscriber on it → Keys → Add key → JSON',
    "okta": "Admin Console → Security → API → Tokens → Create token, as a read-only administrator",
    "entra": "Entra admin center → App registrations → New registration → API permissions: Graph AuditLog.Read.All and Directory.Read.All (application) → Grant admin consent → Certificates & secrets → New client secret",
    "google_workspace": "console.cloud.google.com, any project → APIs & Services → Library → Admin SDK API → Enable → IAM & Admin → Service accounts → Create service account (no roles) → open it → Keys → Add key → Create new key → JSON: its client_email and private_key go here (if key creation is refused, an organization policy blocks it: IAM & Admin → Organization policies → Disable service account key creation → override) → Details → copy the Unique ID → admin.google.com → Security → Access and data control → API controls → Manage domain-wide delegation → Add new: that ID, scope https://www.googleapis.com/auth/admin.reports.audit.readonly → Authorize → Account → Admin roles → Create new role with only the Admin console privilege Reports, assigned to one user: that user's address is admin_email",
    "m365": "Entra admin center → App registrations → your app → API permissions → Office 365 Management APIs → ActivityFeed.Read (application) → Grant admin consent → New client secret",
    "defender": "Entra admin center → App registrations → your app → API permissions → Graph SecurityAlert.Read.All (application) → Grant admin consent → New client secret",
    "defender_hunting": "Defender portal → Settings → Microsoft Defender XDR → Streaming API → Add: Forward events to Azure Storage, pick the tables → Azure portal → the storage account → Access control (IAM) → Add role assignment → Storage Blob Data Reader, for an app registration → Certificates & secrets → New client secret",
    "crowdstrike": "Falcon console → Support and resources → API clients and keys → Create API client, Alerts: Read",
    "crowdstrike_fdr": "Falcon console → Support and resources → Falcon Data Replicator → Create feed (FDR is a paid add-on CrowdStrike support enables) → copy the SQS URL, the client ID (the AWS access key ID) and the secret (the secret access key)",
    "sentinelone": "Settings → Users → Service Users → Create service user, Viewer → copy the API token",
    "sentinelone_cloudfunnel": "SentinelOne console → Cloud Funnel settings: stream to your own S3 bucket → AWS IAM → Users → Create user, with a policy allowing s3:ListBucket and s3:GetObject on that bucket → Security credentials → Create access key",
    "github": "Your profile → Settings → Developer settings → Fine-grained tokens → Generate, owned by the organisation, Administration: Read. Enterprise Cloud only; other plans push a webhook",
    "gitlab": "Group or user Settings → Access tokens → Add new token, read_api",
    "cloudflare": "Manage account → Account API tokens → Create token → Custom, Account Settings: Read",
    "cloudflare_logs": "Cloudflare dashboard → R2 → Manage R2 API tokens → Create API token, Object Read only, scoped to the Logpush bucket → copy the Access Key ID and Secret Access Key. For an S3 destination: IAM → Users → Create user with s3:ListBucket and s3:GetObject on the bucket → Create access key",
    "tailscale": "Admin console → Settings → Trust credentials → + Credential → OAuth → Scopes: Logging → Audit Logs, Read",
    "stripe": "Dashboard → Developers → API keys → Create restricted key, Activity logs: Read and Events: Read",
    "openai": "As an owner: Settings → Data controls → turn audit logging on, then Admin keys → Create, Audit logs: Read",
    "anthropic": "Claude Console, as an admin → Settings → Security → turn on the Compliance API if it is offered (then set activity_feed), then Settings → Admin keys → Create admin key",
    "file": "A JSON or NDJSON file on the host shoc runs on, and the mapping to read it with",
    "wazuh": "Wazuh dashboard → Indexer management → Security → Roles: read on wazuh-alerts-* → Internal users → Create user with that role; the indexer answers on port 9200",
}


# Where a push source's vendor is set up to send. Only vendors that push in a
# form of their own are here (ING-2).
PUSH_WHERE = {
    "github": "Organisation → Settings → Webhooks → Add webhook: payload URL, content type application/json, secret = the push key; events organization, repository, public, member, team, team_add, membership, branch_protection_rule, branch_protection_configuration, repository_ruleset, release, deploy_key, org_block, meta, secret_scanning_alert, security_and_analysis, personal_access_token_request, dependabot_alert, push, create, delete, workflow_job, workflow_run",
}


# What `source.configure` needs for each connector: the settings, then the keys
# of the secret. Optional ones are left out; docs/connectors.md has them all.
FIELDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "aws_cloudtrail": ((), ("access_key_id", "secret_access_key")),
    "aws_guardduty": ((), ("access_key_id", "secret_access_key")),
    "azure_activity": (("subscription_id",), ("tenant_id", "client_id", "client_secret")),
    "gcp_audit": (("subscription",), ("client_email", "private_key")),
    "okta": (("org_url",), ("api_token",)),
    "entra": ((), ("tenant_id", "client_id", "client_secret")),
    "google_workspace": (("admin_email",), ("client_email", "private_key")),
    "m365": ((), ("tenant_id", "client_id", "client_secret")),
    "defender": ((), ("tenant_id", "client_id", "client_secret")),
    "defender_hunting": (("storage_account",), ("tenant_id", "client_id", "client_secret")),
    "crowdstrike": (("cloud",), ("client_id", "client_secret")),
    "crowdstrike_fdr": (("queue_url",), ("access_key_id", "secret_access_key")),
    "sentinelone": (("console_url",), ("api_token",)),
    "sentinelone_cloudfunnel": (("bucket",), ("access_key_id", "secret_access_key")),
    "github": (("org",), ("token",)),
    # Optional, yet the form's only way in: with no group it reads the instance's
    # audit log, which needs an administrator and, self-managed, a `base_url`.
    "gitlab": (("group",), ("token",)),
    "cloudflare": (("account_id",), ("api_token",)),
    "cloudflare_logs": (("bucket", "datasets"), ("access_key_id", "secret_access_key")),
    # Or an `api_key` access token, which expires within 90 days.
    "tailscale": ((), ("client_id", "client_secret")),
    "stripe": ((), ("api_key",)),
    "openai": ((), ("admin_key",)),
    "anthropic": ((), ("admin_key",)),
    "file": (("path", "mapping"), ()),
    "wazuh": (("indexer_url",), ("username", "password")),
}


def connector_of(source: str) -> str:
    """The connector a source runs. A second account of the same vendor is the
    connector's name and a label, `cloudflare:acme`, with its own settings,
    credential, cursor and schedule; both read through the one mapping."""
    return source.split(":", 1)[0]


def explain(source: str, exc: Exception) -> str:
    """A sentence someone can act on, instead of a library's repr.

    A 401 from a connector used to surface as an httpx traceback with a link to
    the MDN page for HTTP 401, which tells the reader nothing about which token
    to fix.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            need = PERMISSION_HINTS.get(connector_of(source))
            return (
                f"{source} rejected the credential ({code})"
                + (f"; it needs {need}" if need else "")
                + "."
            )
        if code == 429:
            return f"{source} is rate-limiting us ({code}); the next cycle will retry."
        if code >= 500:
            return f"{source} returned {code}; that is their side, the next cycle will retry."
        return f"{source} refused the request ({code})."
    if isinstance(exc, httpx.TimeoutException):
        return f"{source} did not answer in time."
    if isinstance(exc, httpx.TransportError):
        return f"{source} could not be reached: {exc}"
    return f"{type(exc).__name__}: {exc}"


def client(headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(timeout=DEFAULT_TIMEOUT, headers=headers or {}, follow_redirects=True)


def since_default(cursor: dict[str, Any], hours: int = 24) -> str:
    """Where to resume: the stored cursor, else a bounded backfill window."""
    if cursor.get("since"):
        return str(cursor["since"])
    return (datetime.now(UTC) - timedelta(hours=hours)).isoformat()


def resume(start: str, newest: str) -> str:
    """Where the next window starts once a walk is complete: OVERLAP before
    `newest`, and never before `start`, so a quiet source does not drift back."""
    try:
        back = (utc(newest) - OVERLAP).isoformat()
        return max(back, start, key=utc) if start else back
    except ValueError:
        return newest


def utc(iso: str) -> datetime:
    when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).astimezone(UTC)


class Streams:
    """One source read as several streams of the same tenant, each with its own
    cursor (ING-1).

    Workspace answers per Reports application, Entra per log, M365 per content
    type, AWS per region and Azure per subscription, and one setting names the
    stream. A single name reads that stream with a plain cursor, as before. A
    list, or no value where the connector has a default, reads every stream, so a
    source is not quietly missing the logs half its rules run on. A stream that
    fails does not hold the others back; its error comes back on the page.
    """

    def __init__(self, inner: Connector, setting: str, default: tuple[str, ...] = ()) -> None:
        self.inner, self.setting, self.default = inner, setting, default
        self.source = inner.source

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        names = settings.get(self.setting) or list(self.default)
        if isinstance(names, str) or not names:
            return self.inner.fetch(settings, secret, cursor, limit)
        state = dict(cursor.get("streams") or {})
        # Streams still paging go first; once none is, a new walk reads them all.
        todo = [n for n in names if (state.get(n) or {}).get("more")] or list(names)
        records: list[dict[str, Any]] = []
        failed: list[str] = []
        for name in todo:
            mine = state.get(name) or {}
            try:
                page = self.inner.fetch(
                    {**settings, self.setting: name}, secret, mine, max(1, limit // len(todo))
                )
            except Exception as exc:
                if len(failed) + 1 == len(names):
                    raise
                failed.append(f"{name}: {explain(self.source, exc)}")
                # Not pending any more, so it cannot starve the others next run.
                state[name] = {**mine, "more": False}
                continue
            records += page.records
            nxt = page.cursor
            if not page.more and nxt.get("since"):
                nxt = {**nxt, "since": resume(str(mine.get("since") or ""), str(nxt["since"]))}
            state[name] = {**nxt, "more": page.more}
        more = any(state[n].get("more") for n in todo)
        return FetchResult(
            records=records, cursor={"streams": state}, more=more, error="; ".join(failed)
        )


def read_state(conn: Any, tenant_id: str, source: str) -> dict[str, Any]:
    row = fetch_one(
        conn,
        "SELECT cursor FROM shoc.connector_state WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    return dict(row["cursor"]) if row else {}


def write_state(
    conn: Any, tenant_id: str, source: str, cursor: dict[str, Any], seen: int, error: str | None
) -> None:
    execute(
        conn,
        """INSERT INTO shoc.connector_state
               (tenant_id, source, cursor, last_run_at, last_ok_at, last_error, events_seen)
           VALUES (%s, %s, %s, now(), CASE WHEN %s::text IS NULL THEN now() END, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               cursor = EXCLUDED.cursor,
               last_run_at = now(),
               last_ok_at = COALESCE(EXCLUDED.last_ok_at, shoc.connector_state.last_ok_at),
               last_error = EXCLUDED.last_error,
               events_seen = shoc.connector_state.events_seen + EXCLUDED.events_seen""",
        (tenant_id, source, json.dumps(cursor), error, error, seen),
    )


def mark_push(conn: Any, tenant_id: str, source: str, loaded: int) -> None:
    """Record a push delivery (ING-2). The cursor and a poll's error are left
    alone: a source can be both polled and pushed."""
    execute(
        conn,
        """INSERT INTO shoc.connector_state (tenant_id, source, last_ok_at, events_seen)
           VALUES (%s, %s, now(), %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               last_ok_at = now(),
               events_seen = shoc.connector_state.events_seen + EXCLUDED.events_seen""",
        (tenant_id, source, loaded),
    )


def read_config(conn: Any, tenant_id: str, source: str, master_key: str) -> tuple[dict, dict, bool]:
    from shoc.db.secrets import open_secret

    row = fetch_one(
        conn,
        "SELECT enabled, settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source=%s",
        (tenant_id, source),
    )
    if not row:
        return {}, {}, False
    secret = open_secret(master_key, row["secret"], tenant_id, "connector_config", source)
    return dict(row["settings"]), secret, bool(row["enabled"])


def run(
    conn: Any,
    store: EventStore,
    tenant_id: str,
    source: str,
    settings: dict[str, Any],
    secret: dict[str, Any],
    *,
    cursor: dict[str, Any] | None = None,
    limit: int = 1000,
    max_pages: int = 20,
    persist: bool = True,
) -> RunStats:
    """Fetch, map to OCSF, load in batches, then persist the cursor.

    `events_seen` counts rows the store did not already hold, so the overlap a
    connector reads again is not counted twice.
    """
    from shoc.ingest.connectors import get

    connector = get(source)
    state = (
        cursor if cursor is not None else (read_state(conn, tenant_id, source) if persist else {})
    )
    stats = RunStats(source=source, cursor=dict(state))
    try:
        # Loading the mapping is inside the try: a misconfigured source is bad
        # health for that source, never an exception that stops the worker.
        mapping = ocsf.for_tenant(conn, tenant_id, settings.get("mapping") or connector_of(source))
        # Replaying a public dataset: its events are years old, so retention
        # would drop them and every detection window would miss them. The
        # caller passes the offset that moves the newest event to now; the
        # spacing between events is untouched, so rates stay honest.
        shift = float(settings.get("shift_seconds") or 0)
        # The account its records do not name (an Okta org, a GitLab group, or
        # any source's `account` setting), so a response knows its tenant (RFC 0025).
        named = getattr(connector, "account", None)
        own = str(settings.get("account") or "") or (named(settings) if named else "")
        for _ in range(max_pages):
            before = stats.cursor
            page = connector.fetch(settings, secret, before, limit)
            stats.pages += 1
            stats.fetched += len(page.records)
            if page.records:
                rows = [mapping.map_record(r, tenant_id) for r in page.records]
                if own:
                    for row in rows:
                        row["cloud_account_uid"] = row.get("cloud_account_uid") or own
                if shift:
                    for row in rows:
                        row["time"] = replay.shift_time(row["time"], shift)
                stats.loaded += batchwriter.load(store, rows).rows
                if conn is not None:
                    batchwriter.loaded(conn, tenant_id, rows)
                    if persist:
                        history(conn, tenant_id, source, rows, store)
            stats.cursor = page.cursor
            if page.error:
                stats.error = page.error
            if not page.more and page.cursor.get("since"):
                stats.cursor = {
                    **page.cursor,
                    "since": resume(str(state.get("since") or ""), str(page.cursor["since"])),
                }
            # An empty time window is not the end of a backfill (Tailscale,
            # M365): stop on an empty page only when the cursor did not move.
            if not page.more or (not page.records and page.cursor == before):
                break
    except Exception as exc:
        stats.error = explain(source, exc)
        stats.detail = f"{type(exc).__name__}: {exc}"
    if persist:
        write_state(conn, tenant_id, source, stats.cursor, stats.loaded, stats.error)
    return stats


def history(
    conn: Any, tenant_id: str, source: str, rows: list[dict[str, Any]], store: Any = None
) -> None:
    """When this source's data starts and which accounts it speaks for.

    The earliest only ever moves earlier, and the row outlives the source, so a
    source removed and added again keeps its history. Rows loaded by hand never
    pass through here, so a replay cannot make a baseline look a month old. The
    first time a source is seen, what the store already holds for the same
    product and accounts counts too: a source connected before this was
    recorded is not made to start learning again.
    """
    times = [str(r["time"]) for r in rows if r.get("time") is not None]
    products = sorted({str(r["metadata_product"]) for r in rows if r.get("metadata_product")})
    accounts = sorted({str(r["cloud_account_uid"]) for r in rows if r.get("cloud_account_uid")})
    first = min(times) if times else None
    known = fetch_one(
        conn,
        "SELECT 1 FROM shoc.source_history WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    if not known and store is not None and products and accounts:
        from shoc.store import ocsf as layout

        marks = ", ".join(f":a{i}" for i in range(len(accounts)))
        with contextlib.suppress(Exception):
            row = store.query(
                f"SELECT MIN(time) AS first FROM {layout.EVENTS_TABLE} "
                "WHERE tenant_id = :tenant_id AND metadata_product = :product "
                f"AND cloud_account_uid IN ({marks})",
                {
                    "tenant_id": tenant_id,
                    "product": products[0],
                    **{f"a{i}": a for i, a in enumerate(accounts)},
                },
                1,
            ).rows
            earlier = (row[0] if row else {}).get("first")
            if earlier is not None:
                text = earlier.isoformat() if hasattr(earlier, "isoformat") else str(earlier)
                first = min(first, text) if first else text
    execute(
        conn,
        """INSERT INTO shoc.source_history
               (tenant_id, source, products, first_event_at, account_uids)
           VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               products = ARRAY(SELECT DISTINCT p FROM unnest(
                   shoc.source_history.products || EXCLUDED.products) AS p ORDER BY p),
               account_uids = ARRAY(SELECT DISTINCT a FROM unnest(
                   shoc.source_history.account_uids || EXCLUDED.account_uids) AS a ORDER BY a),
               first_event_at = LEAST(shoc.source_history.first_event_at, EXCLUDED.first_event_at),
               last_loaded_at = now()""",
        (tenant_id, source, products, first, accounts),
    )
