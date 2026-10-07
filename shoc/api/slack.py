"""The Slack app (API-3): alerts, `ask`, and one-click approvals.

Slack is a client like any other: it calls capabilities, and the registry does
the checking. Two things are specific to it and live here — verifying that a
request really came from Slack, and deciding which Slack user counts as a human
principal allowed to approve.

Approvers are listed explicitly in the app's settings. Being in the channel is
not authority: without the mapping, a button press is refused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import httpx

from shoc.api.auth import role_caller
from shoc.capabilities.registry import Caller, Context
from shoc.db.pool import Conn, fetch_one
from shoc.errors import ConfigError, Denied

log = logging.getLogger("shoc.slack")

API = "https://slack.com/api"
SIGNATURE_HEADER = "X-Slack-Signature"
TIMESTAMP_HEADER = "X-Slack-Request-Timestamp"
MAX_SKEW_SECONDS = 300
# Where Slack's deferred replies go, and the threads that answer `/shoc
# <question>` after Slack has had its 200. Each thread keeps its own database
# connection; a question past these waits its turn.
RESPONSE_URL = "https://hooks.slack.com/"
REPLIES = ThreadPoolExecutor(max_workers=4, thread_name_prefix="slack-reply")
SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_diamond:",
    "low": ":white_circle:",
    "informational": ":information_source:",
}


@dataclass
class SlackApp:
    bot_token: str = ""
    signing_secret: str = ""
    channel: str = ""
    approvers: dict[str, str] = field(default_factory=dict)  # slack user id -> person's name

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.signing_secret)


def load_app(conn: Conn, tenant_id: str, master_key: str) -> SlackApp:
    from shoc.db.secrets import open_secret

    row = fetch_one(
        conn,
        "SELECT settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source='slack'",
        (tenant_id,),
    )
    if not row:
        return SlackApp()
    settings = dict(row["settings"] or {})
    secret = (
        open_secret(master_key, row["secret"], tenant_id, "connector_config", "slack")
        if row["secret"]
        else {}
    )
    return SlackApp(
        bot_token=secret.get("bot_token", ""),
        signing_secret=secret.get("signing_secret", ""),
        channel=settings.get("channel", ""),
        approvers=dict(settings.get("approvers", {})),
    )


def verify(
    signing_secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None
) -> None:
    """Slack's v0 signature, with the replay window it documents."""
    if not signing_secret:
        raise ConfigError("the Slack app has no signing secret configured")
    try:
        age = abs((now or time.time()) - float(timestamp))
    except (TypeError, ValueError) as exc:
        raise Denied("missing or malformed Slack timestamp") from exc
    if age > MAX_SKEW_SECONDS:
        raise Denied(f"Slack request is {int(age)}s old; the window is {MAX_SKEW_SECONDS}s")
    base = b"v0:" + str(timestamp).encode() + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature or ""):
        raise Denied("Slack signature does not match")


def caller_for(app: SlackApp, slack_user_id: str) -> Caller:
    """A listed approver is an operator (RFC 0018). Everyone else can only read."""
    if slack_user_id in app.approvers:
        return role_caller("operator", app.approvers[slack_user_id])
    return Caller(
        kind="external_agent",
        id=f"slack:{slack_user_id}",
        scopes=("events:read", "findings:read", "cases:read", "ask:read", "health:read"),
    )


# -- outbound ---------------------------------------------------------------
def escape(text: str) -> str:
    """Log content as Slack text that cannot ping the workspace or disguise a link.

    `<!channel>`, `<@U…>` and `<https://…|label>` are all spelt with angle
    brackets; escaping them, and `&`, is what Slack documents (RFC 0015).
    """
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def post(
    app: SlackApp,
    blocks: list[dict[str, Any]],
    text: str,
    channel: str = "",
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    if not app.bot_token:
        raise ConfigError("the Slack app has no bot token configured")
    client = http or httpx.Client(timeout=15.0)
    try:
        resp = client.post(
            f"{API}/chat.postMessage",
            headers={
                "Authorization": f"Bearer {app.bot_token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json={"channel": channel or app.channel, "text": text, "blocks": blocks},
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        if http is None:
            client.close()


def case_blocks(
    case: dict[str, Any], findings: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], str]:
    """A case as Slack sees it: what happened, what it cites, what needs a person."""
    emoji = SEVERITY_EMOJI.get(case["severity"], "")
    text = f"{case['severity'].upper()} {case['title']} ({case['case_uid']})"
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {case['title']}"[:150]},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{case['severity']}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Verdict*\n{case['verdict']} ({case['confidence']:.2f})",
                },
                {"type": "mrkdwn", "text": f"*Entity*\n`{escape(case['entity_key'])}`"},
                {"type": "mrkdwn", "text": f"*State*\n{case['state']}"},
            ],
        },
    ]
    if case.get("summary"):
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": escape(case["summary"][:2800])}}
        )
    if findings:
        lines = "\n".join(
            f"• {escape(f['title'])} — {f['event_count']} event(s)" for f in findings[:5]
        )
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Findings*\n{lines}"}}
        )
    for action in actions:
        if action["state"] != "proposed":
            continue
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Waiting for you:* `{action['type']}` on `{escape(action['target'])}`\n"
                    f"{escape(action['rationale'][:300])}",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "shoc_approve",
                    "value": action["action_uid"],
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Approve this action?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": f"`{action['type']}` on `{action['target']}`",
                        },
                        "confirm": {"type": "plain_text", "text": "Approve"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
            }
        )
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "style": "danger",
                        "action_id": "shoc_reject",
                        "value": action["action_uid"],
                    }
                ],
            }
        )
    citations = [uid for f in findings for uid in (f.get("event_uids") or [])][:3]
    if citations:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Evidence: " + ", ".join(f"`{c}`" for c in citations),
                    }
                ],
            }
        )
    return blocks, text


def notify_case(ctx: Context, case_uid: str, http: httpx.Client | None = None) -> dict[str, Any]:
    """Post a case to the channel, with buttons for anything waiting on a human."""
    from shoc.cases import actions as action_store
    from shoc.cases import engine
    from shoc.db.pool import fetch_all

    app = load_app(ctx.db, ctx.tenant_id, ctx.config.master_key)
    if not app.configured:
        raise ConfigError("Slack is not configured; call slack.configure first")
    case = engine.require(ctx.db, ctx.tenant_id, case_uid)
    findings = fetch_all(
        ctx.db,
        """SELECT title, event_count, event_uids FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s ORDER BY last_seen DESC LIMIT 5""",
        (ctx.tenant_id, case_uid),
    )
    pending = action_store.listing(ctx.db, ctx.tenant_id, "proposed", case_uid)
    blocks, text = case_blocks(case, findings, pending)
    return post(app, blocks, text, http=http)


# -- inbound ----------------------------------------------------------------
def handle_command(
    ctx: Context, app: SlackApp, form: dict[str, str], http: httpx.Client | None = None
) -> dict[str, Any]:
    """`/shoc <question>` — ask, list cases, or show what is waiting.

    A question is answered after the reply, through Slack's `response_url`;
    `http` stands in for the client that posts the answer.
    """
    from shoc.capabilities.registry import call

    text = (form.get("text") or "").strip()
    user = form.get("user_id", "")
    ctx.caller = caller_for(app, user)
    if not text or text in ("help", "?"):
        return _message(
            "*shoc*\n"
            "`/shoc cases` — open cases\n"
            "`/shoc waiting` — actions waiting for a human\n"
            "`/shoc <question>` — ask, with citations"
        )
    if text.startswith("cases"):
        result = call("case.list", ctx, {"limit": 5})
        lines = "\n".join(
            f"• `{c['case_uid']}` {SEVERITY_EMOJI.get(c['severity'], '')} {c['title']} "
            f"— {c['verdict']}"
            for c in result.data.rows
        )
        return _message(f"*{result.summary}*\n{lines or '_nothing open_'}")
    if text.startswith("waiting"):
        result = call("action.list", ctx, {"state": "proposed", "limit": 5})
        lines = "\n".join(
            f"• `{a['action_uid']}` {a['type']} on `{a['target']}`" for a in result.data.rows
        )
        return _message(f"*{result.summary}*\n{lines or '_nothing waiting_'}")
    url = form.get("response_url", "")
    if not url:
        return _message(_answer(ctx, text))
    if not url.startswith(RESPONSE_URL):
        raise Denied(f"response_url must start with {RESPONSE_URL}")
    # Slack gives up on a command after 3 seconds, and the Manager can take a
    # minute asking the crew, so the answer follows through `response_url`.
    later = Context(tenant_id=ctx.tenant_id, caller=ctx.caller, config=ctx.config)
    REPLIES.submit(_reply, later, text, url, http)
    return {"response_type": "ephemeral", "text": f"Asking the crew: {escape(text)[:200]}"}


def _answer(ctx: Context, question: str) -> str:
    from shoc.capabilities.registry import call

    result = call("ask", ctx, {"question": question, "since": "-7d"})
    citations = ", ".join(f"`{c}`" for c in result.citations[:3])
    return escape(result.summary) + (f"\n_Evidence: {citations}_" if citations else "")


def _reply(ctx: Context, question: str, url: str, http: httpx.Client | None = None) -> None:
    """Answer one question and post it where Slack said to. Nobody waits on this thread."""
    try:
        body = _message(_answer(ctx, question))
    except Exception as exc:  # the person still gets an answer, even if it is this one
        log.warning("ask from Slack failed: %s", exc)
        body = _message(f"shoc could not answer that: {type(exc).__name__}")
    client = http or httpx.Client(timeout=15.0)
    try:
        client.post(url, json=body).raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("could not post an answer to Slack: %s", exc)
    finally:
        if http is None:
            client.close()


def handle_interaction(ctx: Context, app: SlackApp, payload: dict[str, Any]) -> dict[str, Any]:
    """An Approve or Reject button. Only a listed approver may press it."""
    from shoc.capabilities.registry import call

    user = (payload.get("user") or {}).get("id", "")
    ctx.caller = caller_for(app, user)
    actions = payload.get("actions") or []
    if not actions:
        return _message("Nothing to do.")
    action_id = actions[0].get("action_id")
    action_uid = actions[0].get("value", "")
    try:
        if action_id == "shoc_approve":
            result = call("action.approve", ctx, {"action_uid": action_uid})
            return _message(
                f":white_check_mark: <@{user}> approved `{action_uid}`. {result.summary}"
            )
        if action_id == "shoc_reject":
            call(
                "action.reject",
                ctx,
                {"action_uid": action_uid, "note": f"rejected in Slack by {user}"},
            )
            return _message(f":x: <@{user}> rejected `{action_uid}`.")
    except Denied:
        return _message(
            f":no_entry: <@{user}> is not on the approver list for this workspace. "
            "An approval has to come from a named person."
        )
    return _message("Unknown button.")


def _message(text: str) -> dict[str, Any]:
    return {"response_type": "in_channel", "text": text}


def parse_payload(body: bytes, content_type: str) -> dict[str, Any]:
    """Slack posts interactions as a form field containing JSON."""
    from urllib.parse import parse_qs

    if "application/json" in content_type:
        return json.loads(body or b"{}")
    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
    if "payload" in form:
        return json.loads(form["payload"])
    return form
