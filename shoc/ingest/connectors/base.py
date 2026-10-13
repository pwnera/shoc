"""Connector contract and the run loop shared by every source (ING-1, ING-4).

A connector is one small object: it knows how to ask its API for events after a
cursor, and returns raw records plus the next cursor. Mapping, batching, dedup,
cursor persistence and health accounting all happen here, so a new source is one
module plus one mapping file.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import struct
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx

from shoc.db.pool import execute, fetch_one
from shoc.ingest import batch as batchwriter
from shoc.ingest import ocsf, replay
from shoc.store.base import EventStore, LoadStats

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# How far back a poll looks again. A listing of files named by time: a file can
# land behind the last key read, and an hourly blob keeps growing after its hour;
# the keys and bytes already read are kept, so no event is read twice. A poll by
# event time (`since_default`): a vendor can deliver an event after a newer one
# was read, and the rows already stored are dropped before the store (`run`), so
# the re-read costs API calls only. A read that stops at the vendor's published
# lag (`settled`) looks back no further than the newest event read (D164).
OVERLAP = timedelta(minutes=15)

# How long one run reads before it hands the worker back. A source still behind
# says so in `RunStats.more`, and `source.sync` queues the rest as a job of its
# own, so a backlog drains without one source holding the worker (ING-1).
RUN_SECONDS = 120

# The cursor times a vendor's record times set. One record stamped in the future
# would carry the cursor there, and every later poll would read nothing until
# then while reporting success; `run` holds them to now (ING-1).
CURSOR_TIMES = ("since", "newest", "created")


@dataclass
class FetchResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    cursor: dict[str, Any] = field(default_factory=dict)
    more: bool = False
    # Set when some streams of a source failed and the others were still read,
    # or when part of the window was past what the vendor still serves.
    error: str = ""
    # Called once the page is stored, for a vendor that wants what it handed
    # over acknowledged (a Pub/Sub ack). A page that failed to load is never
    # acknowledged, so the vendor hands it over again.
    commit: Callable[[], None] | None = None
    # An overlap read gives the `since` its walk re-reads behind: a row older
    # than it that the source had not stored arrived late (D164). A source read
    # as several streams gives `parts` instead: each stream's name, how many of
    # `records` it read, in order, and its `since`.
    since: str = ""
    parts: list[tuple[str, int, str]] = field(default_factory=list)


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
    # `error` came from a page that was still read (a stream that failed while
    # the others loaded), so the source is not down.
    partial: bool = False
    # The last page said there was more, and the run stopped at its page or
    # time cap.
    more: bool = False
    # Rows that arrived late, by stream (D164); rows the store left out; rows
    # placed at ingest time because their own time was unreadable or implausible.
    late: dict[str, int] = field(default_factory=dict)
    skipped: int = 0
    replaced: int = 0


# What a rejected credential most likely lacks. The provider's own wording, and
# how to grant it, is in docs/connectors.md; this is the one line a person needs
# while reading an error. Every connector inherits it through `run`.
PERMISSION_HINTS = {
    "aws_cloudtrail": "cloudtrail:LookupEvents and ec2:DescribeRegions, or s3:ListBucket and s3:GetObject on the trail bucket",
    "aws_guardduty": "guardduty:ListDetectors, ListFindings and GetFindings, and ec2:DescribeRegions",
    "azure_activity": "Reader on the subscription",
    "gcp_audit": "roles/pubsub.subscriber on the sink's subscription (or roles/logging.viewer without one)",
    "okta": "an API token of a read-only administrator, which reads the System Log, users and network zones",
    "entra": (
        "Graph AuditLog.Read.All and Directory.Read.All, and for the risk streams "
        "IdentityRiskEvent.Read.All and IdentityRiskyUser.Read.All "
        "(Entra ID P2 for full risk data)"
    ),
    "google_workspace": "domain-wide delegation for admin.reports.audit.readonly",
    "m365": "ActivityFeed.Read on the Management API",
    "defender": "Graph SecurityAlert.Read.All",
    "defender_hunting": "Storage Blob Data Reader on the Streaming API's storage account",
    "crowdstrike": "an API client with the Alerts: read scope",
    "crowdstrike_fdr": "the key pair of a Falcon Data Replicator feed, which CrowdStrike scopes to the feed's SQS queue and S3 bucket",
    "sentinelone": "a service-user token with viewer rights",
    "sentinelone_cloudfunnel": "s3:ListBucket and s3:GetObject on the Cloud Funnel bucket",
    "github": "a fine-grained token with organisation Administration: read",
    "gitlab": "a read_api token of a group Owner (instance-wide events need an administrator)",
    "wazuh": "an indexer user with read on wazuh-alerts-*",
    "cloudflare": "an account API token with Account Settings: Read",
    "cloudflare_logs": "an R2 API token with Object Read on the Logpush bucket, or s3:ListBucket and s3:GetObject on it",
    "tailscale": "an OAuth client with the logs:configuration:read scope",
    "stripe": (
        "a restricted key with Activity logs, Events, Charges and Refunds, and Payouts: read, "
        "and read on Radar's early fraud warnings"
    ),
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
    "entra": "Entra admin center → App registrations → New registration → API permissions: Graph AuditLog.Read.All, Directory.Read.All, IdentityRiskEvent.Read.All and IdentityRiskyUser.Read.All (application; Entra ID P2 for full risk data) → Grant admin consent → Certificates & secrets → New client secret",
    "google_workspace": "console.cloud.google.com, any project → APIs & Services → Library → Admin SDK API → Enable → IAM & Admin → Service accounts → Create service account (no roles) → open it → Keys → Add key → Create new key → JSON: its client_email and private_key go here (if key creation is refused, an organization policy blocks it: IAM & Admin → Organization policies → Disable service account key creation → override) → Details → copy the Unique ID → admin.google.com → Security → Access and data control → API controls → Manage domain-wide delegation → Add new: that ID, scope https://www.googleapis.com/auth/admin.reports.audit.readonly → Authorize → Account → Admin roles → Create new role with only the Admin console privilege Reports, assigned to one user: that user's address is admin_email",
    "m365": "Entra admin center → App registrations → your app → API permissions → Office 365 Management APIs → ActivityFeed.Read (application) → Grant admin consent → New client secret. Audit logging must be on (Microsoft Purview → Audit). shoc starts the content subscriptions itself, and the first events can take up to 12 hours to appear",
    "defender": "Entra admin center → App registrations → your app → API permissions → Graph SecurityAlert.Read.All (application) → Grant admin consent → New client secret",
    "defender_hunting": "Defender portal → Settings → Microsoft Defender XDR → Streaming API → Add: Forward events to Azure Storage, pick the tables → Azure portal → the storage account → Access control (IAM) → Add role assignment → Storage Blob Data Reader, for an app registration → Certificates & secrets → New client secret",
    "crowdstrike": "Falcon console → Support and resources → API clients and keys → Create API client, Alerts: Read",
    "crowdstrike_fdr": "Falcon console → Support and resources → Falcon Data Replicator → Create feed (FDR is a paid add-on CrowdStrike support enables) → copy the SQS URL, the client ID (the AWS access key ID) and the secret (the secret access key)",
    "sentinelone": "Settings → Users → Service Users → Create service user, Viewer → copy the API token",
    "sentinelone_cloudfunnel": "SentinelOne console → Cloud Funnel settings: stream to your own S3 bucket → AWS IAM → Users → Create user, with a policy allowing s3:ListBucket and s3:GetObject on that bucket → Security credentials → Create access key",
    "github": "Your profile → Settings → Developer settings → Fine-grained tokens → Generate, owned by the organisation, Administration: Read. Enterprise Cloud only; other plans push a webhook. Then turn on source IP disclosure, or no event carries a source address: Enterprise settings → Settings → Audit log → Source IP disclosure → Enable, or Organisation → Settings → Logs → Audit log → Settings → Enable source IP disclosure",
    "gitlab": "Group → Settings → Access tokens → Add new token, role Owner, scope read_api; or an Owner's own token, User settings → Access tokens, read_api",
    "cloudflare": "Manage account → Account API tokens → Create token → Custom, Account Settings: Read",
    "cloudflare_logs": "Cloudflare dashboard → R2 → Manage R2 API tokens → Create API token, Object Read only, scoped to the Logpush bucket → copy the Access Key ID and Secret Access Key. For an S3 destination: IAM → Users → Create user with s3:ListBucket and s3:GetObject on the bucket → Create access key",
    "tailscale": "Admin console → Settings → Trust credentials → + Credential → OAuth → Scopes: Logging → Audit Logs, Read",
    "stripe": "Dashboard → Developers → API keys → Create restricted key, Read on Activity logs, Events, Charges and Refunds, Payouts, and Radar's early fraud warnings",
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


# Vendor error codes a status alone hides: AWS answers throttling with a 400 and
# a request signed by a drifted clock with a 403, which read as a refusal and a
# missing permission.
THROTTLED = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "SlowDown",
    }
)
SKEWED = frozenset({"RequestTimeTooSkewed", "RequestExpired"})
# A code that says a permission is missing, so the permission hint applies.
DENIED = re.compile(
    r"denied|forbidden|permission|authorization|unauthorizedoperation|E0000006", re.I
)
_CODE = re.compile(r"[\w.-]{1,100}")


def vendor_error(response: httpx.Response) -> tuple[str, bool]:
    """The vendor's own error code in a refusal, and whether it says the
    request's signature expired. AWS names it in `__type` or `<Code>`, Graph and
    Azure in `error.code`, Google in `error.status`, Okta in `errorCode`, an
    OAuth token endpoint in `error`. Only a code-shaped word is kept: the body is
    the vendor's text, and the error is shown to people and agents."""
    try:
        text = response.text[:4000]
    except Exception:
        return "", False
    code: Any = None
    try:
        body = json.loads(text)
    except ValueError:
        found = re.search(r"<Code>([^<]*)</Code>", text)
        code = found.group(1) if found else None
    else:
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                code = error.get("code") if isinstance(error.get("code"), str) else None
                code = code or error.get("status")
            else:
                code = body.get("__type") or body.get("errorCode") or error
    code = str(code or "").split("#")[-1].split(":")[0]
    return (code if _CODE.fullmatch(code) else ""), "signature expired" in text.lower()


def explain(source: str, exc: Exception) -> str:
    """A sentence someone can act on, instead of a library's repr.

    A 401 from a connector used to surface as an httpx traceback with a link to
    the MDN page for HTTP 401, which tells the reader nothing about which token
    to fix.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        vendor, expired = vendor_error(exc.response)
        said = f"{code}, {vendor}" if vendor else str(code)
        if expired or vendor in SKEWED:
            return (
                f"{source} refused the request as signed at the wrong time ({said}); "
                "check the clock of the host shoc runs on."
            )
        if code == 429 or vendor in THROTTLED:
            return f"{source} is rate-limiting us ({said}); the next cycle will retry."
        if vendor == "Authentication_RequestFromNonPremiumTenantOrB2CTenant":
            return f"{source} refused the request ({said}); sign-in logs need Entra ID P1."
        if vendor == "AF20022":
            return (
                f"{source} has no subscription to this content type yet ({said}); shoc started "
                "one, and its first content can take up to 12 hours to appear."
            )
        if code in (401, 403):
            # A token's roles are fixed when it is minted: one minted before
            # admin consent, or by a client since rotated, would keep failing
            # until it expired.
            forget(exc.request, code)
            need = PERMISSION_HINTS.get(connector_of(source))
            if vendor in ("SignatureDoesNotMatch", "InvalidSignatureException"):
                need = "the right secret key, and the right clock on the host shoc runs on"
            elif vendor and not DENIED.search(vendor):
                need = None  # a wrong or expired credential, not a missing permission
            return (
                f"{source} rejected the credential ({said})"
                + (f"; it needs {need}" if need else "")
                + "."
            )
        if code >= 500:
            return f"{source} returned {code}; that is their side, the next cycle will retry."
        return f"{source} refused the request ({said})."
    if isinstance(exc, httpx.TimeoutException):
        return f"{source} did not answer in time."
    if isinstance(exc, httpx.TransportError):
        return f"{source} could not be reached: {exc}"
    return f"{type(exc).__name__}: {exc}"


def client(headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(timeout=DEFAULT_TIMEOUT, headers=headers or {}, follow_redirects=True)


# Every vendor token shoc mints (OAuth 2.0 client credentials, Google's signed
# assertion), by key: the token, when it is due to expire and when it was minted.
_TOKENS: dict[str, tuple[str, float, float]] = {}

# A 403 to a token minted this recently is about a licence or a permission still
# missing, not about when it was minted: Entra without P2 is refused two streams
# on every run, and dropping the token for each would mint two more per run.
FRESH = 900


def cached(key: str) -> str:
    """The token kept under `key`, or "" once it is a minute from expiring."""
    token, expires, _ = _TOKENS.get(key) or ("", 0.0, 0.0)
    return token if expires > time.time() else ""


def keep(key: str, payload: dict[str, Any], default_ttl: int = 3600) -> str:
    """Keep the token a vendor's token endpoint answered with, under `key`."""
    now = time.time()
    token = str(payload["access_token"])
    _TOKENS[key] = (token, now + int(payload.get("expires_in", default_ttl)) - 60, now)
    return token


def client_token(
    url: str,
    data: dict[str, str],
    default_ttl: int = 3600,
    minted: Callable[[], object] | None = None,
) -> str:
    """A client-credentials token from `url`, cached until a minute before it
    expires or a request with it is refused (`forget`). `minted` runs only when
    a new one was asked for."""
    key = hashlib.sha256(json.dumps([url, data], sort_keys=True).encode()).hexdigest()
    if token := cached(key):
        return token
    with httpx.Client(timeout=30.0) as http:
        resp = http.post(url, data=data)
        resp.raise_for_status()
        token = keep(key, resp.json(), default_ttl)
    if minted:
        minted()
    return token


def forget(request: httpx.Request, status: int = 401) -> None:
    """Drop the cached token a refused request carried, so the next call mints
    one with the permissions, or the client secret, in force now. On a 403 only a
    token older than `FRESH` goes."""
    sent = request.headers.get("authorization", "").removeprefix("Bearer ")
    young = time.time() - FRESH
    for key, (token, _, minted) in list(_TOKENS.items()):
        if token == sent and (status != 403 or minted < young):
            del _TOKENS[key]


def since_default(
    cursor: dict[str, Any], settings: dict[str, Any], overlap: timedelta = OVERLAP
) -> str:
    """Where a poll starts (D154, D164). A walk still paging holds its `start`.
    A new one starts `overlap` before `since`, the newest event the last walk
    read; a read that stops at the vendor's published lag passes no overlap. The
    first poll, which has no `since`, reads `backfill_hours` back (24 by default)."""
    if cursor.get("start"):
        return str(cursor["start"])
    if cursor.get("newest") and cursor.get("since"):
        # A walk held before D164 kept its start in `since`, and its page
        # token belongs to that filter.
        return str(cursor["since"])
    if cursor.get("since"):
        return (utc(cursor["since"]) - overlap).isoformat() if overlap else str(cursor["since"])
    hours = int(settings.get("backfill_hours", 24))
    return (datetime.now(UTC) - timedelta(hours=hours)).isoformat()


def reached(cursor: dict[str, Any], start: str) -> str:
    """The newest event a walk has read so far, never behind where the last walk
    ended, so a walk that finds only the overlap leaves the cursor where it was."""
    return str(cursor.get("newest") or cursor.get("since") or start)


def settled(cursor: dict[str, Any], lag: timedelta) -> str:
    """Where a poll stops: the vendor's documented delivery lag behind now, so
    an event it delivers late is still after the next poll's start (D154). Held
    while a walk pages, since a page token belongs to the window it came from."""
    return str(cursor.get("until") or (datetime.now(UTC) - lag).isoformat())


def utc(iso: str) -> datetime:
    """A vendor's time as an aware UTC datetime. Graph and Azure write 7-digit
    ticks, which `fromisoformat` alone refuses."""
    return datetime.fromisoformat(ocsf.TRANSFORMS["iso8601"](iso))


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
        parts: list[tuple[str, int, str]] = []
        failed: list[str] = []
        notes: list[str] = []  # streams that read, but not all of their window
        commits: list[Callable[[], None]] = []
        for name in todo:
            mine = state.get(name) or {}
            try:
                page = self.inner.fetch(
                    {**settings, self.setting: name}, secret, mine, max(1, limit // len(todo))
                )
            except Exception as exc:
                if len(failed) + 1 == len(names):
                    raise
                failed.append(
                    f"{name}: {explain(self.source, exc)} To stop reading it, set "
                    f"{self.setting} to a list without {name}."
                )
                # Not pending any more, so it cannot starve the others next run.
                state[name] = {**mine, "more": False}
                continue
            records += page.records
            parts.append((name, len(page.records), page.since))
            state[name] = {**page.cursor, "more": page.more}
            if page.commit:
                commits.append(page.commit)
            if page.error:
                notes.append(f"{name}: {page.error}")
        more = any(state[n].get("more") for n in todo)

        def commit() -> None:
            for done in commits:
                done()

        return FetchResult(
            records=records,
            cursor={"streams": state},
            more=more,
            error="; ".join(failed + notes),
            commit=commit if commits else None,
            parts=parts,
        )


def read_state(conn: Any, tenant_id: str, source: str) -> dict[str, Any]:
    row = fetch_one(
        conn,
        "SELECT cursor FROM shoc.connector_state WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    return dict(row["cursor"]) if row else {}


def write_state(
    conn: Any,
    tenant_id: str,
    source: str,
    cursor: dict[str, Any],
    seen: int,
    error: str | None,
    keys: bytes | None = None,
    partial: bool = False,
    late: dict[str, int] | None = None,
    skipped: int = 0,
    replaced: int = 0,
) -> None:
    """`keys`, when given, replaces the `stored_key`s the next run skips.
    `late`, `skipped` and `replaced` add to the source's running counts.

    A `partial` error (some streams failed, the others loaded) is kept in
    `last_error` but still counts as a pull that worked, so a source that is
    ingesting is not reported stale."""
    execute(
        conn,
        """INSERT INTO shoc.connector_state
               (tenant_id, source, cursor, last_run_at, last_ok_at, last_error, events_seen,
                stored_keys, late_events, events_skipped, times_replaced)
           VALUES (%s, %s, %s, now(), CASE WHEN %s::text IS NULL OR %s THEN now() END,
                   %s, %s, %s, %s, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               cursor = EXCLUDED.cursor,
               last_run_at = now(),
               last_ok_at = COALESCE(EXCLUDED.last_ok_at, shoc.connector_state.last_ok_at),
               last_error = EXCLUDED.last_error,
               events_seen = shoc.connector_state.events_seen + EXCLUDED.events_seen,
               stored_keys = COALESCE(EXCLUDED.stored_keys, shoc.connector_state.stored_keys),
               late_events = shoc.connector_state.late_events || (
                   SELECT coalesce(jsonb_object_agg(n.key, n.value::bigint + coalesce(
                              (shoc.connector_state.late_events ->> n.key)::bigint, 0)),
                          '{}'::jsonb)
                     FROM jsonb_each_text(EXCLUDED.late_events) n),
               events_skipped = shoc.connector_state.events_skipped + EXCLUDED.events_skipped,
               times_replaced = shoc.connector_state.times_replaced + EXCLUDED.times_replaced""",
        (
            tenant_id,
            source,
            json.dumps(cursor),
            error,
            partial,
            error,
            seen,
            keys,
            json.dumps(late or {}),
            skipped,
            replaced,
        ),
    )


def stored_key(row: dict[str, Any]) -> bytes:
    """A mapped row's identity in the store, which keeps one row per event_uid
    and time, in 8 bytes (D150). A row whose time was replaced by the ingest
    time is keyed on the vendor's value, so a re-read of it is still known."""
    unmapped = row.get("unmapped")
    when = row.get("time")
    if isinstance(unmapped, dict):
        when = unmapped.get("_time_original", when)
    text = f"{row.get('event_uid')}\0{when}"
    return hashlib.blake2b(text.encode(), digest_size=8).digest()


# A kept key: its `stored_key`, the crc32 of the stream it came from and the
# row's time in epoch seconds, so `run` keeps each stream's keys for as long
# as a re-read can still return them, and no longer.
_KEPT = struct.Struct("!8sII")


def stored_keys(conn: Any, tenant_id: str, source: str) -> dict[bytes, tuple[int, int]]:
    """The `stored_key` of every row the source read that a re-read can still
    return, with its stream and time (`run`)."""
    row = fetch_one(
        conn,
        "SELECT stored_keys FROM shoc.connector_state WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    blob = bytes((row or {}).get("stored_keys") or b"")
    size = _KEPT.size
    kept = (_KEPT.unpack_from(blob, i) for i in range(0, len(blob) - size + 1, size))
    return {key: (part, secs) for key, part, secs in kept}


def kept_keys(
    known: dict[bytes, tuple[int, int]],
    seen: dict[bytes, tuple[int, int]],
    walked: dict[int, int],
    span: timedelta = OVERLAP,
) -> bytes:
    """The keys a re-read can still return, packed for `stored_keys`: every key
    this run read, and of the earlier ones, each stream's within `span` of its
    newest row, which the next walk re-reads, and those within `span` before
    `walked`, the `since` of a walk still under way (a newest-first walk reaches
    them last). The rest go, so the set stays one run and one overlap of each
    stream (D150, D164)."""
    keys = {**known, **seen}
    newest: dict[int, int] = {}
    for part, secs in keys.values():
        newest[part] = max(newest.get(part, 0), secs)
    back = int(span.total_seconds())
    return b"".join(
        _KEPT.pack(key, part, secs)
        for key, (part, secs) in keys.items()
        if key in seen
        or secs >= newest[part] - back
        or (part in walked and walked[part] - back <= secs <= walked[part])
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

    `events_seen` counts rows the store did not already hold. A row an earlier
    run already read and stored is dropped before the store: a poll re-reads the
    last `OVERLAP` of each stream, and a load of what it re-read was three
    statements on a warehouse (D150, D164). A row older than its stream's `since`
    that no run had read arrived late, and is counted in `late`.
    """
    from shoc.ingest.connectors import get

    connector = get(source)
    state = (
        cursor if cursor is not None else (read_state(conn, tenant_id, source) if persist else {})
    )
    stats = RunStats(source=source, cursor=dict(state))
    known = stored_keys(conn, tenant_id, source) if persist else {}
    seen: dict[bytes, tuple[int, int]] = {}
    walked: dict[int, int] = {}  # each stream's `since`, in epoch seconds
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
        deadline = time.monotonic() + RUN_SECONDS
        for _ in range(max_pages):
            before = stats.cursor
            page = connector.fetch(settings, secret, before, limit)
            stats.pages += 1
            stats.fetched += len(page.records)
            if page.records:
                # A Workspace activity is one row per event it lists (ING-3).
                rows: list[dict[str, Any]] = []
                origin: list[tuple[str, int]] = []  # each row's stream and its `since`
                at = 0
                for name, count, since in page.parts or [("", len(page.records), page.since)]:
                    bound = _seconds(since) if since else 0
                    if bound:
                        part = zlib.crc32(name.encode())
                        walked[part] = max(walked.get(part, 0), bound)
                    for record in page.records[at : at + count]:
                        mapped = mapping.map_records(record, tenant_id)
                        rows += mapped
                        origin += [(name, bound)] * len(mapped)
                    at += count
                # Before any shift: `since` is in the vendor's time.
                times = [_seconds(row.get("time")) for row in rows]
                if own:
                    for row in rows:
                        row["cloud_account_uid"] = row.get("cloud_account_uid") or own
                if shift:
                    for row in rows:
                        row["time"] = replay.shift_time(row["time"], shift)
                keys = [stored_key(row) for row in rows]
                new = [row for row, key in zip(rows, keys, strict=True) if key not in known]
                result = batchwriter.load(store, new) if new else LoadStats()
                added = result.rows
                stats.skipped += result.skipped
                stats.replaced += sum(
                    isinstance(u := row.get("unmapped"), dict) and "_time_original" in u
                    for row in new
                )
                for key, (name, bound), secs in zip(keys, origin, times, strict=True):
                    # Without keys from an earlier run, nothing can be told late.
                    if known and bound and secs < bound and key not in known and key not in seen:
                        stats.late[name or source] = stats.late.get(name or source, 0) + 1
                    seen[key] = (zlib.crc32(name.encode()), secs)
                stats.loaded += added
                if conn is not None:
                    # A page read again adds nothing. Stamped as a load, it woke
                    # every rule of an idle cycle (D71).
                    if added:
                        batchwriter.loaded(conn, tenant_id, new)
                    if persist:
                        history(conn, tenant_id, source, rows, store)
            stats.cursor = page.cursor
            if page.commit:
                page.commit()
            if page.error:
                stats.error, stats.partial = page.error, True
            # An empty time window is not the end of a backfill (Tailscale,
            # M365): stop on an empty page only when the cursor did not move.
            stats.more = page.more and bool(page.records or page.cursor != before)
            if not stats.more or time.monotonic() > deadline:
                break
    except Exception as exc:
        stats.error = explain(source, exc)
        stats.detail = f"{type(exc).__name__}: {exc}"
        stats.partial = stats.more = False
    stats.cursor, moved = _clamped(stats.cursor, datetime.now(UTC))
    if moved:
        logging.getLogger("shoc.ingest").warning(
            "%s: a record stamped more than %s ahead moved the cursor; held at now",
            source,
            ocsf.AHEAD,
        )
    if persist:
        # A run that read nothing keeps the last one's keys.
        kept = kept_keys(known, seen, walked) if seen else None
        write_state(
            conn,
            tenant_id,
            source,
            stats.cursor,
            stats.loaded,
            stats.error,
            kept,
            stats.partial,
            stats.late,
            stats.skipped,
            stats.replaced,
        )
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

    Each account keeps its own earliest event too (D79): a member account that
    joins an organisation trail months after the trail started learns from its
    own first day, not the trail's.
    """
    times = [t for r in rows if (t := _instant(r.get("time")))]
    products = sorted({str(r["metadata_product"]) for r in rows if r.get("metadata_product")})
    accounts = sorted({str(r["cloud_account_uid"]) for r in rows if r.get("cloud_account_uid")})
    first = min(times) if times else None
    starts: dict[str, datetime] = {}

    def started(account: str, when: datetime) -> None:
        starts[account] = min(starts.get(account, when), when)

    for r in rows:
        if r.get("cloud_account_uid") and (when := _instant(r.get("time"))):
            started(str(r["cloud_account_uid"]), when)
    known = fetch_one(
        conn,
        "SELECT 1 FROM shoc.source_history WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    if not known and store is not None and products and accounts:
        from shoc.store import ocsf as layout

        marks = ", ".join(f":a{i}" for i in range(len(accounts)))
        with contextlib.suppress(Exception):
            for row in store.query(
                f"SELECT cloud_account_uid, MIN(time) AS first FROM {layout.EVENTS_TABLE} "
                "WHERE tenant_id = :tenant_id AND metadata_product = :product "
                f"AND cloud_account_uid IN ({marks}) GROUP BY cloud_account_uid",
                {
                    "tenant_id": tenant_id,
                    "product": products[0],
                    **{f"a{i}": a for i, a in enumerate(accounts)},
                },
                len(accounts),
            ).rows:
                if earlier := _instant(row.get("first")):
                    first = min(first, earlier) if first else earlier
                    started(str(row["cloud_account_uid"]), earlier)
    execute(
        conn,
        """INSERT INTO shoc.source_history
               (tenant_id, source, products, first_event_at, account_uids, account_starts)
           VALUES (%s,%s,%s,%s,%s,
                   (SELECT coalesce(jsonb_object_agg(key, to_jsonb((value #>> '{}')::timestamptz)),
                                    '{}'::jsonb)
                      FROM jsonb_each(%s::jsonb)))
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               products = ARRAY(SELECT DISTINCT p FROM unnest(
                   shoc.source_history.products || EXCLUDED.products) AS p ORDER BY p),
               account_uids = ARRAY(SELECT DISTINCT a FROM unnest(
                   shoc.source_history.account_uids || EXCLUDED.account_uids) AS a ORDER BY a),
               account_starts = shoc.source_history.account_starts || (
                   SELECT coalesce(jsonb_object_agg(n.key, CASE
                              WHEN o.value IS NULL THEN n.value
                              ELSE to_jsonb(LEAST((o.value #>> '{}')::timestamptz,
                                                  (n.value #>> '{}')::timestamptz)) END),
                              '{}'::jsonb)
                     FROM jsonb_each(EXCLUDED.account_starts) n
                     LEFT JOIN jsonb_each(shoc.source_history.account_starts) o
                       ON o.key = n.key),
               first_event_at = LEAST(shoc.source_history.first_event_at, EXCLUDED.first_event_at),
               last_loaded_at = now()""",
        (
            tenant_id,
            source,
            products,
            first,
            accounts,
            json.dumps({a: t.isoformat() for a, t in starts.items()}),
        ),
    )


def _clamped(cursor: dict[str, Any], now: datetime) -> tuple[dict[str, Any], bool]:
    """`cursor` with each of `CURSOR_TIMES` more than `ocsf.AHEAD` past `now` set
    to now, a stream's own cursor included, and whether one moved."""
    out: dict[str, Any] = {}
    moved = False
    for key, value in cursor.items():
        if isinstance(value, dict):
            value, inner = _clamped(value, now)
            moved = moved or inner
        elif key in CURSOR_TIMES and isinstance(value, str) and value:
            try:
                ahead = utc(value) > now + ocsf.AHEAD
            except (TypeError, ValueError, OverflowError, OSError):
                ahead = False
            if ahead:
                value, moved = now.isoformat(), True
        out[key] = value
    return out, moved


def _seconds(value: Any) -> int:
    """A time as whole epoch seconds, as a kept key holds it; 0 when it does not read."""
    try:
        when = utc(value)
    except (TypeError, ValueError, OverflowError, OSError):
        return 0
    return max(0, min(int(when.timestamp()), 2**32 - 1))


def _instant(value: Any) -> datetime | None:
    """A row's time as an aware datetime, so the earliest is the earliest
    instant whatever its spelling: a 'Z', an offset, a space for the 'T'."""
    if value is None or isinstance(value, datetime):
        when = value
    else:
        try:
            when = datetime.fromisoformat(str(value))
        except ValueError:
            return None
    return when if when is None or when.tzinfo else when.replace(tzinfo=UTC)
