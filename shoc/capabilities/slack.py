"""Slack capabilities (API-3): configure the app, and push a case into a channel."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f


@dataclass
class SlackConfig:
    """Configure the Slack app. Approvers are named explicitly — being in the channel is not authority."""

    bot_token: str = f("", doc="xoxb-… bot token; stored encrypted")
    signing_secret: str = f("", doc="The app's signing secret; stored encrypted")
    channel: str = f("", doc="Channel id to post into, e.g. C0123456789")
    approvers: dict[str, str] = f(
        doc="Slack user id -> the person's name, for everyone allowed to approve", factory=dict
    )


@dataclass
class SlackState:
    channel: str = ""
    approvers: list[str] = field(default_factory=list)
    configured: bool = False


@dataclass
class Empty:
    pass


@dataclass
class SlackView:
    channel: str = ""
    # Slack user id -> the person's name: a form edits the ids.
    approvers: dict[str, str] = field(default_factory=dict)
    # Whether the bot token is stored, and the signing secret that lets shoc
    # check a request came from Slack; never either value.
    has_bot_token: bool = False
    verifies_requests: bool = False


@capability(
    name="slack.show",
    summary="Show the Slack app's channel and approvers, and whether its secrets are set",
    input=Empty,
    output=SlackView,
    scope="slack:read",
    principals=("human", "service"),
    tags=("slack", "read"),
)
def show(ctx: Context, inp: Empty) -> Result:
    from shoc.api.slack import load_app

    app = load_app(ctx.db, ctx.tenant_id, ctx.config.master_key)
    return Result(
        data=SlackView(
            channel=app.channel,
            approvers=app.approvers,
            has_bot_token=bool(app.bot_token),
            verifies_requests=bool(app.signing_secret),
        ),
        summary=(
            f"Slack posts to {app.channel or 'no channel yet'}; "
            f"{len(app.approvers)} approver(s)"
            + ("." if app.configured else "; its bot token or signing secret is not set.")
        ),
    )


@capability(
    name="slack.configure",
    summary="Connect the Slack app and say who may approve from it",
    input=SlackConfig,
    output=SlackState,
    scope="slack:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("slack", "write", "security"),
)
def configure(ctx: Context, inp: SlackConfig) -> Result:
    from shoc.api.slack import load_app
    from shoc.db.pool import execute
    from shoc.db.secrets import seal

    existing = load_app(ctx.db, ctx.tenant_id, ctx.config.master_key)
    secret = {
        "bot_token": inp.bot_token or existing.bot_token,
        "signing_secret": inp.signing_secret or existing.signing_secret,
    }
    settings = {
        "channel": inp.channel or existing.channel,
        "approvers": inp.approvers or existing.approvers,
    }
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'slack', true, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               settings = EXCLUDED.settings, secret = EXCLUDED.secret""",
        (
            ctx.tenant_id,
            json.dumps(settings),
            seal(ctx.config.master_key, secret, ctx.tenant_id, "connector_config", "slack"),
        ),
    )
    return Result(
        data=SlackState(
            channel=settings["channel"],
            approvers=sorted(settings["approvers"].values()),
            configured=bool(secret["bot_token"] and secret["signing_secret"]),
        ),
        summary=(
            f"Slack app configured for {settings['channel'] or 'no channel yet'}; "
            f"{len(settings['approvers'])} approver(s): "
            f"{', '.join(sorted(settings['approvers'].values())) or 'none — nobody can approve yet'}."
        ),
    )


@dataclass
class NotifyInput:
    case_uid: str = f("", doc="A case to post, with buttons for anything waiting on a human")
    text: str = f("", doc="A message to post; escaped, so it cannot ping anyone or hide a link")


@dataclass
class NotifyResult:
    case_uid: str = ""
    posted: bool = False
    channel: str = ""


@capability(
    name="slack.notify",
    summary="Post a message or a case to Slack; unattended, only the SOC Manager may",
    input=NotifyInput,
    output=NotifyResult,
    scope="slack:write",
    principals=("human", "agent"),
    audit=True,
    tags=("slack", "write"),
)
def notify(ctx: Context, inp: NotifyInput) -> Result:
    import httpx

    from shoc.agents.manager import CALLER
    from shoc.api.slack import escape, load_app, notify_case, post
    from shoc.errors import Denied, UpstreamError, ValidationError

    # Every unattended message goes through the Manager's gate (RFC 0015). A
    # role with something to say hands the Manager a notice instead.
    if ctx.caller.kind != "human" and ctx.caller.id != CALLER.id:
        raise Denied("only the SOC Manager posts to Slack unattended; hand it a notice")
    if not (inp.case_uid or inp.text):
        raise ValidationError("name a case_uid, give a text, or both")
    app = load_app(ctx.db, ctx.tenant_id, ctx.config.master_key)
    responses: list[dict[str, Any]] = []
    try:
        if inp.text:
            text = escape(inp.text)
            section = {"type": "section", "text": {"type": "mrkdwn", "text": text}}
            responses.append(post(app, [section], text))
        if inp.case_uid:
            responses.append(notify_case(ctx, inp.case_uid))
    except httpx.HTTPError as exc:
        raise UpstreamError(f"Slack could not be reached: {exc}") from exc
    refused = [r.get("error") for r in responses if not r.get("ok")]
    if refused:
        raise UpstreamError(f"Slack refused the message: {refused[0]}")
    return Result(
        data=NotifyResult(case_uid=inp.case_uid, posted=True, channel=app.channel),
        summary=f"Posted {inp.case_uid or 'a message'} to {app.channel}.",
        citations=[inp.case_uid] if inp.case_uid else [],
    )
