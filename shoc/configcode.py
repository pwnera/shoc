"""Config as code: `shoc plan` and `shoc apply` (API-4).

One YAML file describes what a deployment should look like — which sources are
connected, which intel feeds are on, how long to keep events, who may approve in
Slack — and `plan` shows the difference between that and reality before `apply`
changes anything.

Secrets are never in the file. A source names the environment variables its
credentials come from, so the repository holds the shape of the deployment and
the secret store holds the secrets. Only variables named `SHOC_SECRET_*` can be
named, so a config sent over the API cannot read `SHOC_MASTER_KEY` or the DSN.

Rules, playbooks and the policy are read from `SHOC_CONTENT_DIR` by every
process, so deploying that directory applies them; `plan` and `apply` check
they load before changing anything else.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from shoc.db.pool import Conn, fetch_all, fetch_one
from shoc.errors import ConfigError, ValidationError

if TYPE_CHECKING:
    from shoc.capabilities.registry import Context

# The only environment variables a config may name: the server's own settings
# (SHOC_MASTER_KEY, SHOC_DSN, the tokens) stay out of reach of whoever sends one.
SECRET_ENV_PREFIX = "SHOC_SECRET_"


@dataclass
class SourceSpec:
    source: str
    settings: dict[str, Any] = field(default_factory=dict)
    secret_env: dict[str, str] = field(default_factory=dict)
    interval_seconds: int = 300
    enabled: bool = True


@dataclass
class FeedSpec:
    feed: str
    parser: str = ""
    enabled: bool = True
    settings: dict[str, Any] = field(default_factory=dict)
    secret_env: dict[str, str] = field(default_factory=dict)


@dataclass
class SlackSpec:
    channel: str = ""
    approvers: dict[str, str] = field(default_factory=dict)
    bot_token_env: str = ""
    signing_secret_env: str = ""


@dataclass
class Desired:
    """What the deployment should look like."""

    version: int = 1
    # Unset leaves retention to SHOC_RETENTION_DAYS; set, it outlasts a restart.
    retention_days: int | None = None
    dry_run: bool | None = None
    sources: list[SourceSpec] = field(default_factory=list)
    intel_feeds: list[FeedSpec] = field(default_factory=list)
    slack: SlackSpec | None = None
    prune_unlisted: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Desired:
        slack = data.get("slack")
        retention = data.get("retention_days")
        return cls(
            version=int(data.get("version", 1)),
            retention_days=None if retention is None else int(retention),
            dry_run=data.get("dry_run"),
            sources=[
                SourceSpec(
                    source=s["source"],
                    settings=s.get("settings", {}) or {},
                    secret_env=s.get("secret_env", {}) or {},
                    interval_seconds=int(s.get("interval_seconds", 300)),
                    enabled=bool(s.get("enabled", True)),
                )
                for s in data.get("sources", []) or []
            ],
            intel_feeds=[
                FeedSpec(
                    feed=f_["feed"],
                    parser=f_.get("parser", ""),
                    enabled=bool(f_.get("enabled", True)),
                    settings=f_.get("settings", {}) or {},
                    secret_env=f_.get("secret_env", {}) or {},
                )
                for f_ in data.get("intel_feeds", []) or []
            ],
            slack=(
                SlackSpec(
                    channel=slack.get("channel", ""),
                    approvers=dict(slack.get("approvers", {}) or {}),
                    bot_token_env=slack.get("bot_token_env", ""),
                    signing_secret_env=slack.get("signing_secret_env", ""),
                )
                if slack
                else None
            ),
            prune_unlisted=bool(data.get("prune_unlisted", False)),
        )


def read_file(path: Path) -> dict[str, Any]:
    """The config file, parsed. Read by the CLI, which sends it on as `config`."""
    if not path.exists():
        raise ConfigError(f"no config file at {path}")
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path} is not a YAML mapping")
    return data


@dataclass
class Change:
    kind: str  # source | intel_feed | slack | retention | content
    target: str
    action: str  # create | update | delete | unchanged | invalid
    detail: str = ""

    def line(self) -> str:
        mark = {"create": "+", "update": "~", "delete": "-", "unchanged": " ", "invalid": "!"}[
            self.action
        ]
        return f"{mark} {self.kind} {self.target}" + (f" — {self.detail}" if self.detail else "")

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "action": self.action,
            "detail": self.detail,
        }


@dataclass
class Plan:
    changes: list[Change] = field(default_factory=list)
    missing_env: list[str] = field(default_factory=list)

    @property
    def to_change(self) -> list[Change]:
        return [c for c in self.changes if c.action in ("create", "update", "delete")]

    @property
    def invalid(self) -> list[Change]:
        return [c for c in self.changes if c.action == "invalid"]

    def render(self) -> str:
        lines = [c.line() for c in self.changes] or ["  nothing declared"]
        summary = (
            f"{len([c for c in self.changes if c.action == 'create'])} to create, "
            f"{len([c for c in self.changes if c.action == 'update'])} to update, "
            f"{len([c for c in self.changes if c.action == 'delete'])} to remove, "
            f"{len([c for c in self.changes if c.action == 'unchanged'])} unchanged"
        )
        if self.missing_env:
            lines.append(f"! missing environment variable(s): {', '.join(self.missing_env)}")
        if self.invalid:
            summary += f", {len(self.invalid)} invalid"
        return "\n".join(lines) + "\n\n" + summary


def _env(variable: str) -> str | None:
    return os.environ.get(variable) if variable.startswith(SECRET_ENV_PREFIX) else None


def _refused(variables: Any) -> str:
    """Why these variable names may not be read, or '' when they all may."""
    bad = sorted(v for v in variables if v and not v.startswith(SECRET_ENV_PREFIX))
    return f"may only name {SECRET_ENV_PREFIX}* variables, not {', '.join(bad)}" if bad else ""


def _secret_from_env(secret_env: dict[str, str], missing: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, variable in secret_env.items():
        value = _env(variable)
        if value is None:
            missing.append(variable)
        else:
            out[key] = value
    return out


def validate_content(config: Any = None) -> list[Change]:
    """Everything in `content/` must load and compile before anything is applied."""
    from shoc.cases.playbooks import load as load_playbooks
    from shoc.cases.policy import Policy
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import compile_rule

    out: list[Change] = []
    try:
        rules = ruleset.load(config)
        for rule in rules:
            compile_rule(rule)
        out.append(Change("content", "rules", "unchanged", f"{len(rules)} rule(s) compile"))
    except Exception as exc:
        out.append(Change("content", "rules", "invalid", str(exc)))
    try:
        books = load_playbooks(config)
        out.append(Change("content", "playbooks", "unchanged", f"{len(books)} playbook(s) valid"))
    except Exception as exc:
        out.append(Change("content", "playbooks", "invalid", str(exc)))
    try:
        policy = Policy.load(config)
        out.append(
            Change("content", "policy", "unchanged", f"{len(policy.actions)} action(s) in policy")
        )
    except Exception as exc:
        out.append(Change("content", "policy", "invalid", str(exc)))
    return out


def plan(conn: Conn, tenant_id: str, desired: Desired, config: Any = None) -> Plan:
    """What `apply` would change. Reads only."""
    from shoc.ingest import connectors

    result = Plan(changes=validate_content(config))
    missing: list[str] = []

    have_sources = {
        r["source"]: r
        for r in fetch_all(
            conn,
            "SELECT source, enabled, settings, interval_seconds FROM shoc.connector_config "
            "WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    known = set(connectors.available()) | set(connectors.push_sources()) | {"slack"}
    for spec in desired.sources:
        if connectors.connector_of(spec.source) not in known:
            result.changes.append(Change("source", spec.source, "invalid", "unknown source"))
            continue
        if refused := _refused(spec.secret_env.values()):
            result.changes.append(Change("source", spec.source, "invalid", refused))
            continue
        _secret_from_env(spec.secret_env, missing)
        current = have_sources.get(spec.source)
        if current is None:
            result.changes.append(Change("source", spec.source, "create", "not configured yet"))
        elif (
            dict(current["settings"]) != spec.settings
            or int(current["interval_seconds"]) != spec.interval_seconds
            or bool(current["enabled"]) != spec.enabled
        ):
            result.changes.append(Change("source", spec.source, "update", "settings differ"))
        else:
            result.changes.append(Change("source", spec.source, "unchanged"))
    if desired.prune_unlisted:
        for name in have_sources:
            if name not in ("slack", "llm") and name not in {s.source for s in desired.sources}:
                result.changes.append(Change("source", name, "delete", "not in the config file"))

    have_feeds = {
        r["feed"]: r
        for r in fetch_all(
            conn,
            "SELECT feed, enabled, settings FROM shoc.intel_feeds WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    from shoc.detect.intel import FEEDS, REPORT_FEEDS

    for spec in desired.intel_feeds:
        if (spec.parser or spec.feed) not in {**FEEDS, **REPORT_FEEDS}:
            result.changes.append(Change("intel_feed", spec.feed, "invalid", "unknown parser"))
            continue
        if refused := _refused(spec.secret_env.values()):
            result.changes.append(Change("intel_feed", spec.feed, "invalid", refused))
            continue
        _secret_from_env(spec.secret_env, missing)
        current = have_feeds.get(spec.feed)
        if current is None:
            result.changes.append(Change("intel_feed", spec.feed, "create"))
        elif dict(current["settings"]) != spec.settings or bool(current["enabled"]) != spec.enabled:
            result.changes.append(Change("intel_feed", spec.feed, "update", "settings differ"))
        else:
            result.changes.append(Change("intel_feed", spec.feed, "unchanged"))

    if desired.slack:
        from shoc.api.slack import load_app
        from shoc.config import Config

        cfg = config or Config.load()
        app = load_app(conn, tenant_id, cfg.master_key)
        variables = (desired.slack.bot_token_env, desired.slack.signing_secret_env)
        for variable in variables:
            if variable and _env(variable) is None:
                missing.append(variable)
        if refused := _refused(variables):
            result.changes.append(
                Change("slack", desired.slack.channel or "app", "invalid", refused)
            )
        elif not app.configured:
            result.changes.append(Change("slack", desired.slack.channel or "app", "create"))
        elif app.channel != desired.slack.channel or app.approvers != desired.slack.approvers:
            result.changes.append(
                Change(
                    "slack", desired.slack.channel or "app", "update", "channel or approvers differ"
                )
            )
        else:
            result.changes.append(Change("slack", app.channel, "unchanged"))

    if desired.retention_days is not None:
        row = fetch_one(
            conn,
            "SELECT payload FROM shoc.schedules WHERE schedule_id = %s",
            (f"{tenant_id}:retention",),
        )
        have = (row or {}).get("payload", {})
        have_days = int(have.get("days", 90))
        if have_days != desired.retention_days or "set_by" not in have:
            source = "" if "set_by" in have else " from SHOC_RETENTION_DAYS"
            result.changes.append(
                Change(
                    "retention",
                    f"{desired.retention_days}d",
                    "update",
                    f"currently {have_days}d{source}",
                )
            )
        else:
            result.changes.append(Change("retention", f"{have_days}d", "unchanged"))

    result.missing_env = sorted(set(missing))
    return result


def _capability(change: Change) -> str:
    """The capability a change goes through; '' for retention, which config:write covers."""
    if change.kind == "source":
        return "source.remove" if change.action == "delete" else "source.configure"
    return {"intel_feed": "intel.configure", "slack": "slack.configure"}.get(change.kind, "")


def apply(ctx: Context, desired: Desired) -> Plan:
    """Make reality match the file. Idempotent; refuses to run on invalid content.

    Every change is a capability called as the caller, with the caller's
    scopes, so it is allowed, refused and audited under the caller's name. All
    of them are checked before the first one runs, so a refusal changes nothing.
    """
    from shoc.capabilities.registry import call, get
    from shoc.db import jobs

    conn, tenant_id = ctx.db, ctx.tenant_id
    proposed = plan(conn, tenant_id, desired, ctx.config)
    if proposed.invalid:
        raise ValidationError(
            "config is invalid, nothing was applied: "
            + "; ".join(f"{c.kind} {c.target}: {c.detail}" for c in proposed.invalid)
        )
    if proposed.missing_env:
        raise ConfigError(
            "these environment variables must be set before applying: "
            + ", ".join(proposed.missing_env)
        )
    for name in dict.fromkeys(_capability(c) for c in proposed.to_change):
        if name:
            get(name).check(ctx.caller)

    applied: list[Change] = []
    for change in proposed.to_change:
        name = _capability(change)
        if change.kind == "source" and change.action == "delete":
            call(name, ctx, {"source": change.target})
        elif change.kind == "source":
            spec = next(s for s in desired.sources if s.source == change.target)
            call(
                name,
                ctx,
                {
                    "source": spec.source,
                    "settings": spec.settings,
                    "secret": _secret_from_env(spec.secret_env, []),
                    "interval_seconds": spec.interval_seconds,
                    "enabled": spec.enabled,
                },
            )
        elif change.kind == "intel_feed":
            spec = next(f_ for f_ in desired.intel_feeds if f_.feed == change.target)
            call(
                name,
                ctx,
                {
                    "feed": spec.feed,
                    "parser": spec.parser,
                    "settings": spec.settings,
                    "secret": _secret_from_env(spec.secret_env, []),
                    "enabled": spec.enabled,
                },
            )
        elif change.kind == "slack" and desired.slack:
            call(
                name,
                ctx,
                {
                    "bot_token": _env(desired.slack.bot_token_env) or "",
                    "signing_secret": _env(desired.slack.signing_secret_env) or "",
                    "channel": desired.slack.channel,
                    "approvers": desired.slack.approvers,
                },
            )
        elif change.kind == "retention":
            # `set_by` keeps the worker's start from writing SHOC_RETENTION_DAYS over it.
            jobs.upsert_schedule(
                conn,
                f"{tenant_id}:retention",
                tenant_id,
                "retention",
                86400,
                {"days": desired.retention_days, "set_by": "config.apply"},
            )
        applied.append(Change(change.kind, change.target, change.action, "applied"))
    return Plan(changes=applied)


EXAMPLE = """# shoc deployment, as code (API-4). Secrets stay in the environment, in
# variables named SHOC_SECRET_*.
version: 1
# Leave out to keep SHOC_RETENTION_DAYS.
retention_days: 90

sources:
  - source: aws_cloudtrail
    interval_seconds: 300
    settings: { region: eu-west-1, backfill_hours: 24 }
    secret_env:
      access_key_id: SHOC_SECRET_AWS_ACCESS_KEY_ID
      secret_access_key: SHOC_SECRET_AWS_SECRET_ACCESS_KEY

  - source: okta
    settings: { org_url: https://acme.okta.com }
    secret_env: { api_token: SHOC_SECRET_OKTA_API_TOKEN }

  - source: github
    settings: { org: acme }
    secret_env: { token: SHOC_SECRET_GITHUB_AUDIT_TOKEN }

intel_feeds:
  - feed: abuse_ch_feodo
  - feed: abuse_ch_urlhaus
  - feed: vendor-blog
    parser: rss
    settings: { url: https://blog.example.com/feed, max_items: 5 }

slack:
  channel: C0123456789
  bot_token_env: SHOC_SECRET_SLACK_BOT_TOKEN
  signing_secret_env: SHOC_SECRET_SLACK_SIGNING_SECRET
  approvers:
    U0123ALICE: alice
    U0456SAM: sam

# Remove sources that are configured here but not listed above.
prune_unlisted: false
"""


def write_example(path: Path) -> Path:
    if path.exists():
        raise ValidationError(f"{path} already exists")
    path.write_text(EXAMPLE)
    return path


def to_json(plan_: Plan) -> dict[str, Any]:
    return {
        "changes": [c.to_json() for c in plan_.changes],
        "missing_env": plan_.missing_env,
        "to_change": len(plan_.to_change),
        "invalid": len(plan_.invalid),
    }
