"""What runs with nobody logged in: the page gate, the reports and the deadline chase
(API-1, AGT-14, RSP-7, RFC 0015).

The worker runs these on a schedule as a service principal, so each run is
scope-checked and audited like any other call. A person holding the scope can
run one by hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from shoc.agents.manager import Delivered
from shoc.capabilities.registry import Context, Result, capability
from shoc.cases.unattended import Chased
from shoc.jsonschema import field as f


@dataclass
class Empty:
    pass


@capability(
    name="manager.deliver",
    summary="Run the page gate over every undelivered page notice, one page per incident",
    input=Empty,
    output=Delivered,
    scope="manager:deliver",
    principals=("human", "service"),
    audit=True,
    tags=("manager", "write"),
)
def deliver(ctx: Context, _inp: Empty) -> Result:
    from shoc.agents import manager

    done = manager.deliver(ctx.db, ctx.tenant_id, ctx.config, ctx.store)
    return Result(data=done, summary=done.summary, citations=done.paged)


@capability(
    name="case.chase",
    summary="Page, abandon or send the crew back on whatever has waited past its deadline",
    input=Empty,
    output=Chased,
    scope="cases:chase",
    principals=("human", "service"),
    audit=True,
    tags=("cases", "write"),
)
def chase(ctx: Context, _inp: Empty) -> Result:
    from shoc.cases import unattended

    out = unattended.run(ctx.db, ctx.tenant_id, ctx.config)
    return Result(data=out, summary=out.summary, citations=out.paged + out.abandoned + out.nudged)


@dataclass
class SendInput:
    kind: Literal["weekly", "exec", "exception"] = f(
        "weekly",
        doc="The weekly report, the monthly one for a founder, or the decisions that need a person",
    )


@dataclass
class Sent:
    report_uid: str = ""
    held: int = 0
    slack_error: str = ""


@capability(
    name="report.send",
    summary="Build the weekly or executive report and send it to Slack and the stream",
    input=SendInput,
    output=Sent,
    scope="reports:send",
    principals=("human", "service"),
    audit=True,
    tags=("ops", "report", "write"),
)
def send(ctx: Context, inp: SendInput) -> Result:
    from shoc.agents import reporter

    if inp.kind == "exception":  # sent only when a decision needs a person (D52)
        return Result(
            data=Sent(),
            summary=reporter.send_exceptions(ctx.db, ctx.store, ctx.tenant_id, ctx.config),
        )
    report, error = reporter.send(ctx.db, ctx.store, ctx.tenant_id, inp.kind, ctx.config)
    held = len(report.body.get("held") or [])
    return Result(
        data=Sent(report_uid=report.report_uid, held=held, slack_error=error),
        summary=f"{inp.kind} report {report.report_uid}: {held} held notice(s)"
        + (f"; Slack: {error}" if error else ""),
        citations=report.citations,
    )


@dataclass
class Rechecked:
    summary: str = ""


@capability(
    name="case.recheck",
    summary="Read a few closures the crew called nothing again, blind, and reopen any it got wrong",
    input=Empty,
    output=Rechecked,
    scope="cases:recheck",
    principals=("human", "service"),
    audit=True,
    tags=("cases", "write"),
)
def recheck(ctx: Context, _inp: Empty) -> Result:
    """The weekly second look (RFC 0020). It reopens and nothing more."""
    from shoc.agents import recheck as second_look

    said = second_look.run(ctx.db, ctx.store, ctx.tenant_id, ctx.config)
    return Result(data=Rechecked(summary=said), summary=said)
