"""What an action is, and how it is run (RSP-4).

An action is a small, typed thing with a target, a plan, an execution and —
wherever the world allows it — an undo. Dry run is the default: the action
describes exactly what it would do and changes nothing, so a new install can be
trusted before it is given teeth.

Actions never decide whether they may run. The policy decides (`shoc/cases/
policy.py`), the runner asks it, and only the runner holds credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from shoc.errors import ConfigError, StoreError, ValidationError

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


@dataclass
class Credentials:
    provider: str
    settings: dict[str, Any] = field(default_factory=dict)
    secret: dict[str, Any] = field(default_factory=dict)

    def require(self, *names: str) -> tuple[Any, ...]:
        missing = [n for n in names if not (self.secret.get(n) or self.settings.get(n))]
        if missing:
            raise ConfigError(
                f"{self.provider}: missing credential(s) {', '.join(missing)} — "
                f"set them with credential.configure"
            )
        return tuple(self.secret.get(n) or self.settings.get(n) for n in names)


@dataclass
class ActionResult:
    ok: bool = True
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    undo: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "detail": self.detail,
            "data": self.data,
            "undo": self.undo,
            "dry_run": self.dry_run,
        }


@runtime_checkable
class Action(Protocol):
    type: str
    provider: str
    target_kind: str
    platforms: tuple[str, ...]
    linked_from: tuple[str, ...]
    summary: str
    reversible: bool
    required_params: tuple[str, ...]

    def plan(self, params: dict[str, Any]) -> str:
        """One sentence: exactly what this would do, in a human's words."""
        ...

    def check(self, params: dict[str, Any]) -> None:
        """Raise ValidationError unless the required parameters are present."""
        ...

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult: ...

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult: ...


class _Plumbing:
    type = ""
    provider = ""
    # The log sources (a rule's `logsource.product`) whose incidents this can
    # touch. Empty means any: a page is right for every incident, but making a
    # GitHub repository private is not a response to an S3 bucket.
    platforms: tuple[str, ...] = ()
    summary = ""
    required_params: tuple[str, ...] = ()

    def check(self, params: dict[str, Any]) -> None:
        from shoc.errors import ValidationError

        missing = [p for p in self.required_params if not params.get(p)]
        if missing:
            raise ValidationError(f"{self.type}: missing parameter(s) {', '.join(missing)}")

    def client(self, headers: dict[str, str], http: httpx.Client | None = None) -> httpx.Client:
        if http is not None:
            http.headers.update(headers)
            return http
        return httpx.Client(timeout=TIMEOUT, headers=headers)


# What a module's `probe` reads with: its `client` without an action or a lookup.
READ = _Plumbing()


def unknowable_password() -> str:
    """A password nobody holds, shoc included: it is never stored or returned. It
    meets the usual complexity rules (upper, lower, digit, symbol) within 100
    characters, Google's limit."""
    import secrets

    return f"{secrets.token_urlsafe(32)}Aa1!"


class BaseAction(_Plumbing):
    """An action's plan and its default undo, which refuses."""

    target_kind = ""
    reversible = False
    # Platforms whose cases this action may answer for the login the case's user
    # is linked to, never for the name the case holds (RFC 0027).
    linked_from: tuple[str, ...] = ()

    def target_of(self, params: dict[str, Any]) -> str:
        return str(params.get(self.required_params[0], "")) if self.required_params else ""

    def plan(self, params: dict[str, Any]) -> str:
        return f"{self.summary}: {self.target_of(params)}"

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        return ActionResult(
            ok=False, detail=f"{self.type} cannot be undone automatically", data=dict(undo)
        )


def seg(value: Any) -> str:
    """One URL path segment. A target comes from log content, and `../roles` must
    not turn a user lookup into a call on another endpoint."""
    return quote(str(value), safe="@")


def send(client: httpx.Client, method: str, url: str, vendor: str, **kw: Any) -> httpx.Response:
    try:
        resp = client.request(method, url, **kw)
        resp.raise_for_status()
        return resp
    except httpx.HTTPError as exc:
        raise StoreError(f"{vendor} call failed: {exc}") from exc


def section(client: httpx.Client, url: str, vendor: str, **kw: Any) -> Any:
    """A section of a lookup. One missing permission costs that section, not the answer."""
    try:
        return send(client, "GET", url, vendor, **kw).json()
    except Exception as exc:
        return {"unavailable": str(exc)[:200]}


def newest(items: list[dict[str, Any]], days: int = 7) -> dict[str, Any]:
    """The most recently `created` item, if it is younger than `days`."""
    since = datetime.now(UTC) - timedelta(days=days)
    dated = [
        (datetime.fromisoformat(str(i["created"]).replace("Z", "+00:00")), i)
        for i in items
        if i.get("created")
    ]
    young = [(at, i) for at, i in dated if at >= since]
    return max(young, key=lambda pair: pair[0])[1] if young else {}


def digest(params: dict[str, Any], vendor: str, lengths: tuple[int, ...] = (40, 64)) -> str:
    """The `hash` parameter as lowercase hex: a SHA-1 (40) or a SHA-256 (64)."""
    value = str(params.get("hash", "")).strip().lower()
    if len(value) not in lengths or not re.fullmatch(r"[0-9a-f]+", value):
        names = " or ".join({40: "SHA-1", 64: "SHA-256"}[n] for n in lengths)
        raise ValidationError(f"{vendor}: hash must be a {names} hex digest")
    return value


# Cookies an infostealer took, a password typed into a phishing site, a Cloudflare
# Access login and a GitHub grant all belong to a person who signs in through the
# IdP. Those cases are answered for the login their user is linked to (RFC 0027).
IDP_LINKED_FROM = ("edr", "cloudflare", "github")


class BaseLookup(_Plumbing):
    """A read on a platform the crew may make while investigating (RFC 0014).

    Same credentials as the platform's actions, same `platforms` scoping, but
    nothing is proposed, approved or undone: a lookup only ever issues reads, and
    what it returns is quoted to the model as untrusted data.
    """

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError


def dry_run_result(action: Action, params: dict[str, Any]) -> ActionResult:
    return ActionResult(
        ok=True,
        detail=f"[dry run] {action.plan(params)}",
        data={"planned": params},
        dry_run=True,
    )


def out_of_scope(action: Action, platforms: set[str]) -> str:
    """Why this action does not belong to an incident seen on these platforms, or ''."""
    if not action.platforms or set(action.platforms) & platforms:
        return ""
    seen = ", ".join(sorted(platforms)) or "no known source"
    return f"{action.type} acts on {' or '.join(action.platforms)}; this case comes from {seen}"


def follows_link(action: Action, platforms: set[str]) -> bool:
    """Whether an action outside these platforms may still answer the case, for
    the login its user is linked to (RFC 0027)."""
    return bool(set(action.linked_from) & platforms)


# -- what a response credential is made of (RSP-4, RFC 0025, RFC 0031) -------
@dataclass(frozen=True)
class Need:
    """What `credential.configure` takes for one provider, and what to grant on the
    vendor's side. Every provider also takes `accounts`."""

    settings: tuple[str, ...] = ()
    secret: tuple[str, ...] = ()
    grant: str = ""
    optional: tuple[str, ...] = ()
    # Secret fields that stand in for all of `secret` (a static token instead of a client).
    alternative: tuple[str, ...] = ()
    # Where to make it on the vendor's side, as a click path (a source's is `WHERE`).
    where: str = ""


_MICROSOFT = ("tenant_id", "client_id", "client_secret")
_GOOGLE = ("client_email", "private_key")

# What `credential.configure` takes for each provider (RFC 0031: the provider is the vendor).
NEEDS: dict[str, Need] = {
    "aws": Need(
        secret=("access_key_id", "secret_access_key"),
        grant="iam:UpdateAccessKey, iam:PutUserPolicy and iam:PutRolePolicy with their Delete "
        "pairs, iam:AttachUserPolicy and iam:DetachUserPolicy, cloudtrail:StartLogging, "
        "config:StartConfigurationRecorder, guardduty:UpdateDetector, "
        "s3:PutBucketPublicAccessBlock, kms:CancelKeyDeletion, kms:EnableKey, "
        "ec2:ModifySnapshotAttribute and ec2:ModifyImageAttribute, ec2:CreateSecurityGroup, "
        "ec2:RevokeSecurityGroupEgress and ec2:ModifyNetworkInterfaceAttribute, with the "
        "matching reads (ec2:DescribeInstances, ec2:DescribeSecurityGroups)",
        optional=("regions",),
        where="IAM → Users → Create user, no console access → Attach policies directly → a "
        "policy allowing the actions above → Security credentials → Create access key "
        "(third-party service)",
    ),
    "okta": Need(
        settings=("org_url",),
        secret=("api_token",),
        grant="an API token of a super administrator: it signs users out, suspends them, "
        "removes factors and takes back admin roles",
        where="Admin Console, as a super administrator → Security → API → Tokens → Create token",
    ),
    "entra": Need(
        secret=_MICROSOFT,
        grant="Graph User.ReadWrite.All, User.RevokeSessions.All, "
        "RoleManagement.ReadWrite.Directory, UserAuthenticationMethod.ReadWrite.All and "
        "User-PasswordProfile.ReadWrite.All; resetting a password also needs the app to "
        "hold the User Administrator role (Privileged Authentication Administrator for an "
        "administrator's)",
        where="Entra admin center → App registrations → New registration → API permissions "
        "→ Microsoft Graph → Application permissions: the five above → Grant admin consent "
        "→ Certificates & secrets → New client secret → Roles and administrators → User "
        "Administrator → Add assignments → the app",
    ),
    "m365": Need(
        secret=_MICROSOFT,
        grant="Graph MailboxSettings.ReadWrite, DelegatedPermissionGrant.ReadWrite.All and "
        "User.RevokeSessions.All",
        where="Entra admin center → App registrations → New registration → API permissions "
        "→ Microsoft Graph → Application permissions: the three above → Grant admin consent "
        "→ Certificates & secrets → New client secret",
    ),
    "google": Need(
        settings=("admin_email",),
        secret=_GOOGLE,
        grant="domain-wide delegation for admin.directory.user, "
        "admin.directory.user.security and gmail.settings.sharing",
        where="console.cloud.google.com → IAM & Admin → Service accounts → Create service "
        "account (no roles) → Keys → Add key → JSON → Details → copy the Unique ID → "
        "admin.google.com → Security → Access and data control → API controls → Manage "
        "domain-wide delegation → Add new: that ID and the three scopes; admin_email is the "
        "super administrator it acts as",
    ),
    "gcp": Need(
        secret=_GOOGLE,
        grant="Service Account Key Admin, and Compute Security Admin for firewall rules",
        where="console.cloud.google.com → IAM & Admin → Service accounts → Create service "
        "account → IAM → Grant access: it, those two roles, on each project → Service "
        "accounts → it → Keys → Add key → JSON",
    ),
    "azure": Need(
        secret=_MICROSOFT,
        grant="Virtual Machine Contributor on the VMs",
        where="Entra admin center → App registrations → New registration → Certificates & "
        "secrets → New client secret → Azure portal → Subscriptions → the subscription → "
        "Access control (IAM) → Add role assignment → Virtual Machine Contributor → the app",
    ),
    "github": Need(
        secret=("token",),
        grant="a fine-grained token with organisation Members and Administration: write, "
        "and repository Administration: write",
        where="Your profile, as an organisation owner → Settings → Developer settings → "
        "Fine-grained tokens → Generate, owned by the organisation, all repositories, the "
        "permissions above",
    ),
    "gitlab": Need(
        secret=("token",),
        grant="an administrator token, which a self-managed or Dedicated instance has",
        where="Signed in as an administrator → Edit profile → Access tokens → Add new token, "
        "api scope",
        optional=("base_url",),
    ),
    "crowdstrike": Need(
        settings=("cloud",),
        secret=("client_id", "client_secret"),
        grant="an API client with Hosts: write and IOC Management: write",
        where="Falcon console → Support and resources → API clients and keys → Create API "
        "client, Hosts: Write and IOC Management: Write → copy the client ID and secret",
    ),
    "sentinelone": Need(
        settings=("console_url",),
        secret=("api_token",),
        grant="a service-user token that can disconnect agents and add blocklist items",
        where="Settings → Users → Service Users → Create service user, a role that can "
        "disconnect from network and edit the blocklist → copy the API token",
    ),
    "defender": Need(
        secret=_MICROSOFT,
        grant="WindowsDefenderATP Machine.Isolate and Ti.ReadWrite",
        where="Entra admin center → App registrations → New registration → API permissions "
        "→ APIs my organization uses → WindowsDefenderATP → Application permissions: the two "
        "above → Grant admin consent → Certificates & secrets → New client secret",
    ),
    "wazuh": Need(
        settings=("api_url",),
        secret=("username", "password"),
        grant="a server API user with active-response:command, agent:read and syscheck:read",
        where="Wazuh dashboard → Server management → Security → Roles: one with the three "
        "actions above → Users → Create user → map it to that role; the API answers on port "
        "55000",
    ),
    "cloudflare": Need(
        settings=("account_id",),
        secret=("api_token",),
        grant="an account API token with Account Firewall Access Rules: Edit, to block an "
        "address, and Account API Tokens: Edit, to disable a token",
        where="Manage account → Account API tokens → Create token → Custom, Account Firewall "
        "Access Rules: Edit and Account API Tokens: Edit",
    ),
    "tailscale": Need(
        secret=("client_id", "client_secret"),
        grant="an OAuth client with write on devices, users and auth keys",
        where="Admin console → Settings → Trust credentials → + Credential → OAuth → "
        "Scopes: Devices, Users and Auth Keys, Write",
        optional=("tailnet",),
        alternative=("api_key",),
    ),
    "stripe": Need(
        secret=("api_key",),
        grant="a restricted key with Charges: read and Radar: write",
        where="Dashboard → Developers → API keys → Create restricted key, Charges: Read and "
        "Radar: Write",
    ),
    "anthropic": Need(
        secret=("admin_key",),
        grant="an Admin API key",
        where="Claude Console, as an admin → Settings → Admin keys → Create admin key",
    ),
    "openai": Need(
        secret=("admin_key",),
        grant="an Admin key, which only an organization owner can create",
        where="As an owner: Settings → Organization → Admin keys → Create new admin key",
    ),
    "notify": Need(
        secret=("routing_key",),
        grant="a PagerDuty Events v2 integration key",
        where="PagerDuty → Services → the on-call service → Integrations → Add an "
        "integration → Events API V2 → copy the integration key",
    ),
}

# The response credential that acts on what each connector reads: a platform
# shoc can see but not act on is an incomplete integration (D56).
RESPONDS: dict[str, tuple[str, ...]] = {
    "aws_cloudtrail": ("aws",),
    "aws_guardduty": ("aws",),
    "azure_activity": ("azure", "entra"),
    "gcp_audit": ("gcp",),
    "okta": ("okta",),
    "entra": ("entra",),
    "m365": ("m365", "entra"),
    "google_workspace": ("google",),
    "defender": ("defender",),
    "defender_hunting": ("defender",),
    "crowdstrike": ("crowdstrike",),
    "crowdstrike_fdr": ("crowdstrike",),
    "sentinelone": ("sentinelone",),
    "sentinelone_cloudfunnel": ("sentinelone",),
    "wazuh": ("wazuh",),
    "github": ("github",),
    "gitlab": ("gitlab",),
    "cloudflare": ("cloudflare",),
    "cloudflare_logs": ("cloudflare",),
    "tailscale": ("tailscale",),
    "stripe": ("stripe",),
    "openai": ("openai",),
    "anthropic": ("anthropic",),
    "file": (),
}
