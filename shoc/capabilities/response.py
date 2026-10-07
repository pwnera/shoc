"""Response capabilities: actions, approvals and playbook runs (RSP-2, RSP-3, RSP-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.cases import actions as action_store
from shoc.cases import credentials, playbooks
from shoc.cases.policy import Policy
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class ActionFilter:
    state: str = f("", doc="proposed, approved, running, done, failed, rejected or blocked")
    case_uid: str = f("", doc="Only actions for this case")
    limit: int = f(50, doc="Maximum rows")


@dataclass
class ActionPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    waiting_for_approval: int = 0


@capability(
    name="action.list",
    summary="List response actions and what they are waiting for",
    input=ActionFilter,
    output=ActionPage,
    scope="actions:read",
    tags=("response", "read"),
)
def list_actions(ctx: Context, inp: ActionFilter) -> Result:
    rows = action_store.listing(ctx.db, ctx.tenant_id, inp.state, inp.case_uid, inp.limit)
    waiting = sum(1 for r in rows if r["state"] == "proposed")
    return Result(
        data=ActionPage(
            rows=[to_json(r) for r in rows], count=len(rows), waiting_for_approval=waiting
        ),
        summary=f"{len(rows)} action(s); {waiting} waiting for a human.",
        citations=[r["action_uid"] for r in rows],
    )


@dataclass
class ProposeInput:
    action: str = f(doc="Action type, e.g. aws.disable_access_key")
    params: dict[str, Any] = f(
        doc="Action parameters, e.g. {'access_key_id': 'AKIA…'}", factory=dict
    )
    case_uid: str = f("", doc="The case this responds to")
    rationale: str = f("", doc="Why, in one sentence")
    credential: str = f(
        "",
        doc="One of the provider's credentials, e.g. aws:staging. Left empty, shoc "
        "acts in every account the target was seen in; a name only narrows that",
    )


@dataclass
class ActionRecord:
    action_uid: str = ""
    type: str = ""
    target: str = ""
    state: str = ""
    autonomy: str = ""
    dry_run: bool = True
    reversible: bool = True
    plan: str = ""
    rationale: str = ""
    # The credentials it acts with, by name: which platform, and which tenant of it.
    acts_in: list[str] = field(default_factory=list)


def _record(row: dict[str, Any], plan: str = "") -> ActionRecord:
    return ActionRecord(
        action_uid=row["action_uid"],
        type=row["type"],
        target=row["target"],
        state=row["state"],
        autonomy=row["autonomy"],
        dry_run=bool(row["dry_run"]),
        reversible=bool(row["reversible"]),
        plan=plan,
        rationale=row["rationale"],
        acts_in=list(row.get("acts_in") or []),
    )


@capability(
    name="action.propose",
    summary="Propose a response action; the policy decides whether a human must approve it",
    input=ProposeInput,
    output=ActionRecord,
    scope="actions:propose",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("response", "write"),
)
def propose(ctx: Context, inp: ProposeInput) -> Result:
    from shoc.actions import get as get_action

    row = action_store.propose(
        ctx.db,
        ctx.tenant_id,
        action_store.Proposal(
            action_type=inp.action,
            params=inp.params,
            rationale=inp.rationale,
            case_uid=inp.case_uid or None,
            credential=inp.credential,
        ),
        principal=f"{ctx.caller.kind}:{ctx.caller.id}",
        principal_kind=ctx.caller.kind,
        config=ctx.config,
    )
    plan = get_action(inp.action).plan(inp.params)
    if row.get("acts_in"):
        plan += f" in {', '.join(row['acts_in'])}"
    state = {
        "approved": "will run automatically",
        "proposed": "waiting for a human to approve",
        "blocked": "blocked by policy",
    }.get(row["state"], row["state"])
    return Result(
        data=_record(row, plan),
        summary=f"{plan}, {state} ({row['autonomy']}{', dry run' if row['dry_run'] else ''}).",
        citations=[row["action_uid"]] + ([inp.case_uid] if inp.case_uid else []),
    )


@dataclass
class ApprovalInput:
    action_uid: str = f(doc="The action to approve")
    note: str = f("", doc="Anything the record should say")


@capability(
    name="action.approve",
    summary="Approve a response action the crew proposed",
    input=ApprovalInput,
    output=ActionRecord,
    scope="actions:approve",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("response", "write", "approval"),
)
def approve(ctx: Context, inp: ApprovalInput) -> Result:
    row = action_store.approve(
        ctx.db, ctx.tenant_id, inp.action_uid, f"human:{ctx.caller.id}", ctx.caller.kind
    )
    return Result(
        data=_record(row),
        summary=f"{inp.action_uid} approved by {ctx.caller.id}; it will run on the next pass.",
        citations=[inp.action_uid],
    )


@capability(
    name="action.reject",
    summary="Reject a proposed action",
    input=ApprovalInput,
    output=ActionRecord,
    scope="actions:approve",
    principals=("human",),
    audit=True,
    tags=("response", "write", "approval"),
)
def reject(ctx: Context, inp: ApprovalInput) -> Result:
    row = action_store.reject(
        ctx.db, ctx.tenant_id, inp.action_uid, f"human:{ctx.caller.id}", inp.note
    )
    return Result(
        data=_record(row),
        summary=f"{inp.action_uid} rejected.",
        citations=[inp.action_uid],
    )


@dataclass
class RunActionInput:
    action_uid: str = f(doc="The approved action to run")
    dry_run: bool = f(True, doc="Plan it without touching anything")


@dataclass
class ActionOutcome:
    action_uid: str = ""
    state: str = ""
    ok: bool = True
    detail: str = ""
    dry_run: bool = True


@capability(
    name="action.run",
    summary="Run an approved action now",
    input=RunActionInput,
    output=ActionOutcome,
    scope="actions:run",
    principals=("human", "service"),
    audit=True,
    tags=("response", "write"),
)
def run_action(ctx: Context, inp: RunActionInput) -> Result:
    row, result = action_store.execute(
        ctx.db,
        ctx.tenant_id,
        inp.action_uid,
        ctx.config.master_key,
        force_dry_run=True if inp.dry_run else None,
        by=f"{ctx.caller.kind}:{ctx.caller.id}",
    )
    return Result(
        data=ActionOutcome(
            action_uid=inp.action_uid,
            state=row["state"],
            ok=result.ok,
            detail=result.detail,
            dry_run=result.dry_run,
        ),
        summary=result.detail,
        citations=[inp.action_uid],
    )


@capability(
    name="action.undo",
    summary="Roll a completed action back",
    input=ApprovalInput,
    output=ActionOutcome,
    scope="actions:run",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("response", "write"),
)
def undo(ctx: Context, inp: ApprovalInput) -> Result:
    row, result = action_store.undo(
        ctx.db,
        ctx.tenant_id,
        inp.action_uid,
        ctx.config.master_key,
        by=f"{ctx.caller.kind}:{ctx.caller.id}",
    )
    return Result(
        data=ActionOutcome(
            action_uid=inp.action_uid,
            state=row["state"],
            ok=result.ok,
            detail=result.detail,
            dry_run=result.dry_run,
        ),
        summary=result.detail,
        citations=[inp.action_uid],
    )


@dataclass
class ExpireInput:
    action_uid: str = f(doc="The done action whose `ttl_minutes` ran out")


@capability(
    name="action.expire",
    summary="Undo a block whose lifetime ran out",
    input=ExpireInput,
    output=ActionOutcome,
    scope="actions:run",
    principals=("service",),
    audit=True,
    tags=("response", "write"),
)
def expire(ctx: Context, inp: ExpireInput) -> Result:
    """The worker's side of `ttl_minutes` (RSP-4): undone, unless already undone or never run."""
    row = action_store.require(ctx.db, ctx.tenant_id, inp.action_uid)
    if row["state"] != "done":
        return Result(
            data=ActionOutcome(
                action_uid=inp.action_uid, state=row["state"], ok=True, detail="nothing to expire"
            ),
            summary=f"{inp.action_uid}: {row['state']}, nothing to expire",
            citations=[inp.action_uid],
        )
    row, result = action_store.undo(
        ctx.db, ctx.tenant_id, inp.action_uid, ctx.config.master_key, by="expiry"
    )
    return Result(
        data=ActionOutcome(
            action_uid=inp.action_uid,
            state=row["state"],
            ok=result.ok,
            detail=result.detail,
            dry_run=result.dry_run,
        ),
        summary=f"{inp.action_uid}: expired, {row['state']} — {result.detail}",
        citations=[inp.action_uid],
    )


@dataclass
class Empty:
    pass


@dataclass
class CredentialInput:
    provider: str = f(
        doc="The vendor: aws, cloudflare, crowdstrike, entra, okta, notify (PagerDuty) …, or "
        "provider:label for another tenant of the same vendor, e.g. aws:staging"
    )
    settings: dict[str, Any] = f(
        doc="Non-secret settings, e.g. {'org_url': 'https://acme.okta.com'}. `accounts` lists the accounts "
        "it acts in, as their events name them (an AWS account ID, an Entra tenant ID, an "
        "Okta org host); needed once two credentials act on the same platform",
        factory=dict,
    )
    secret: dict[str, Any] = f(doc="Credentials; encrypted with the master key", factory=dict)
    verify: bool = f(True, doc="Make one read with it once it is saved")


@dataclass
class CredentialState:
    provider: str = ""
    configured: list[str] = field(default_factory=list)
    # Fields its provider needs that are still not stored.
    missing: list[str] = field(default_factory=list)
    # The read made with it: None when none was tried (a field missing, verify off,
    # or a provider with nothing to read), and what the vendor said either way.
    verified: bool | None = None
    verify_detail: str = ""


@capability(
    name="credential.configure",
    summary="Give the playbook runner the credentials it acts with",
    input=CredentialInput,
    output=CredentialState,
    scope="actions:configure",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("response", "write", "security"),
)
def configure(ctx: Context, inp: CredentialInput) -> Result:
    from shoc.errors import ValidationError

    credentials.check_name(inp.provider)
    others = [
        i
        for i in credentials.instances(ctx.db, ctx.tenant_id, credentials.provider_of(inp.provider))
        if i.name != inp.provider
    ]
    # Two credentials that could both claim a target would leave the runner to
    # guess the tenant at 3am; it refuses instead, so refuse here first.
    if why := credentials.overlap([*others, credentials.Instance.of(inp.provider, inp.settings)]):
        raise ValidationError(why)
    credentials.save(
        ctx.db, ctx.tenant_id, inp.provider, inp.settings, inp.secret, ctx.config.master_key
    )
    have = credentials.providers(ctx.db, ctx.tenant_id)
    stored = credentials.load(ctx.db, ctx.tenant_id, inp.provider, ctx.config.master_key)
    lacks = credentials.missing(inp.provider, stored.settings, stored.secret)
    verified, detail = _verify(stored) if inp.verify and not lacks else (None, "")
    if inp.verify and not lacks:
        credentials.record_check(ctx.db, ctx.tenant_id, inp.provider, verified, detail)
    if lacks:
        said = f"; it still needs {', '.join(lacks)}."
    elif verified is False:
        said = f", and the read with them was refused: {detail}"
    else:
        said = "; the runner can act there."
    return Result(
        data=CredentialState(
            provider=inp.provider,
            configured=have,
            missing=lacks,
            verified=verified,
            verify_detail=detail,
        ),
        summary=f"Credentials stored for {inp.provider}{said}",
    )


def _verify(creds: Any) -> tuple[bool | None, str]:
    """One read with a credential just saved, so a wrong key shows now and not at
    the first containment. It is kept either way: the grant may come later."""
    from shoc.actions import probe

    try:
        said = probe(creds)
    except Exception as exc:  # whatever the vendor or the network said, as a refusal
        return False, str(exc)
    return (None, "") if said is None else (True, said)


@dataclass
class CheckInput:
    provider: str = f(doc="The credential's name, e.g. aws or aws:staging")


@capability(
    name="credential.check",
    summary="Make one read with a stored response credential and say whether it still works",
    input=CheckInput,
    output=CredentialState,
    scope="actions:configure",
    principals=("human", "service"),
    audit=True,
    tags=("response", "read", "security"),
)
def check(ctx: Context, inp: CheckInput) -> Result:
    from shoc.errors import NotFound

    if inp.provider not in credentials.providers(ctx.db, ctx.tenant_id):
        raise NotFound(f"no credential '{inp.provider}'")
    stored = credentials.load(ctx.db, ctx.tenant_id, inp.provider, ctx.config.master_key)
    lacks = credentials.missing(inp.provider, stored.settings, stored.secret)
    verified, detail = (None, "") if lacks else _verify(stored)
    if lacks:
        said = f"still needs {', '.join(lacks)}."
    else:
        credentials.record_check(ctx.db, ctx.tenant_id, inp.provider, verified, detail)
        if verified is None:
            said = "has no read to try."
        else:
            said = f"works: {detail}." if verified else f"did not work: {detail}"
    return Result(
        data=CredentialState(
            provider=inp.provider,
            configured=credentials.providers(ctx.db, ctx.tenant_id),
            missing=lacks,
            verified=verified,
            verify_detail=detail,
        ),
        summary=f"{inp.provider} {said}",
    )


@dataclass
class CredentialList:
    # One row per stored credential: what it acts on and lacks, never its secret.
    configured: list[dict[str, Any]] = field(default_factory=list)
    # One row per provider the connected sources call for, and paging.
    needs: list[dict[str, Any]] = field(default_factory=list)
    # What `credential.configure` takes for each provider, and the actions it runs.
    providers: dict[str, Any] = field(default_factory=dict)


@capability(
    name="credential.list",
    summary="List where shoc can act: the response credentials, and the sources none covers",
    input=Empty,
    output=CredentialList,
    scope="actions:read",
    tags=("response", "read"),
)
def list_credentials(ctx: Context, inp: Empty) -> Result:
    from shoc.actions import load
    from shoc.actions.base import NEEDS, RESPONDS

    covered = credentials.coverage(ctx.db, ctx.tenant_id)
    # Paging answers every case, whatever the sources.
    needs: dict[str, dict[str, Any]] = {"notify": {"provider": "notify", "sources": []}}
    for row in covered:
        need = needs.setdefault(row["provider"], {"provider": row["provider"], "sources": []})
        need["sources"].append(row["source"])
    rows = credentials.listing(ctx.db, ctx.tenant_id, ctx.config.master_key)
    names = {r["name"] for r in rows}
    for key, need in needs.items():
        mine = [r for r in covered if r["provider"] == key]
        held = {n for r in mine for n in r["credentials"]}
        if key == "notify":
            held = {n for n in names if credentials.provider_of(n) == "notify"}
        need["credentials"] = sorted(held)
        need["missing"] = sorted({a for r in mine for a in r["missing"]})
    for row in rows:
        row["sources"] = sorted({r["source"] for r in covered if row["name"] in r["credentials"]})
    actions = list(load().values())
    catalogue = {
        provider: {
            "settings": list(need.settings),
            "optional": list(need.optional),
            "secret": list(need.secret),
            "alternative": list(need.alternative),
            "grant": need.grant,
            "where": need.where,
            # The log connectors whose own credential this is: a vendor's logs
            # and its response, side by side.
            "connectors": sorted(c for c, kinds in RESPONDS.items() if kinds[:1] == (provider,)),
            "actions": sorted(a.type for a in actions if a.provider == provider),
        }
        for provider, need in NEEDS.items()
    }
    shown = sorted(needs.values(), key=lambda n: (bool(n["credentials"]), n["provider"]))
    open_ = [n for n in shown if not n["credentials"] or n["missing"]]
    return Result(
        data=CredentialList(configured=rows, needs=shown, providers=catalogue),
        summary=f"{len(rows)} response credential(s); "
        + (
            f"{len(open_)} kind(s) of source shoc cannot act on yet."
            if open_
            else "every source is covered."
        ),
        citations=[r["name"] for r in rows],
    )


@dataclass
class DisconnectInput:
    provider: str = f(doc="The credential's name, e.g. aws or aws:staging")


@capability(
    name="credential.remove",
    summary="Remove a response credential; shoc stops acting with it",
    input=DisconnectInput,
    output=CredentialState,
    scope="actions:configure",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("response", "write", "security"),
)
def disconnect(ctx: Context, inp: DisconnectInput) -> Result:
    from shoc.errors import NotFound

    if not credentials.remove(ctx.db, ctx.tenant_id, inp.provider):
        raise NotFound(f"no credential '{inp.provider}'")
    have = credentials.providers(ctx.db, ctx.tenant_id)
    return Result(
        data=CredentialState(provider=inp.provider, configured=have),
        summary=f"{inp.provider} removed; shoc no longer acts with it.",
    )


@dataclass
class PolicyView:
    version: int = 0
    defaults: dict[str, Any] = field(default_factory=dict)
    principals: dict[str, str] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)
    guards: dict[str, Any] = field(default_factory=dict)
    available_actions: list[str] = field(default_factory=list)
    # The parameters each action needs, and what it says it does. A client can
    # build the form from this instead of asking a person to write the JSON an
    # action happens to expect.
    action_params: dict[str, Any] = field(default_factory=dict)


@capability(
    name="policy.show",
    summary="Show the autonomy policy: what may run alone, and what needs a human",
    input=Empty,
    output=PolicyView,
    scope="policy:read",
    tags=("response", "read"),
)
def show_policy(ctx: Context, inp: Empty) -> Result:
    from shoc.actions import available, load

    policy = Policy.load(ctx.config)
    described = {
        name: {
            "required": list(getattr(action, "required_params", ())),
            "summary": getattr(action, "summary", ""),
            "reversible": bool(getattr(action, "reversible", False)),
            # The rule products whose cases it may act on; none means any (RFC 0033).
            "platforms": list(getattr(action, "platforms", ())),
        }
        for name, action in load().items()
    }
    automatic = [a for a, r in policy.actions.items() if r.get("autonomy") == "L1"]
    return Result(
        data=PolicyView(
            version=policy.version,
            defaults=policy.defaults,
            principals=policy.principals,
            actions=policy.actions,
            guards=policy.guards,
            available_actions=available(),
            action_params=described,
        ),
        summary=(
            f"{len(policy.actions)} action(s) in policy; {len(automatic)} may run automatically "
            f"({', '.join(sorted(automatic)) or 'none'}); everything else needs a human."
        ),
    )


@dataclass
class PlaybookFilter:
    case_uid: str = f("", doc="Only playbooks whose trigger matches this case")


@dataclass
class PlaybookList:
    playbooks: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    # When none matched: which came closest, and on which condition. Without
    # this, a client can only say "no playbook matches this case".
    near_misses: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="playbook.list",
    summary="List playbooks, or the ones that match a case",
    input=PlaybookFilter,
    output=PlaybookList,
    scope="playbooks:read",
    tags=("response", "read"),
)
def list_playbooks(ctx: Context, inp: PlaybookFilter) -> Result:
    from shoc.cases import engine

    books = playbooks.load(ctx.config, ctx.db, ctx.tenant_id)
    near: list[dict[str, Any]] = []
    if inp.case_uid:
        case = engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
        entities = playbooks.entities_of_case(ctx.db, ctx.tenant_id, inp.case_uid)
        seen = engine.platforms(ctx.db, ctx.tenant_id, inp.case_uid, ctx.config)
        fired = playbooks.rules_of_case(ctx.db, ctx.tenant_id, inp.case_uid)
        matched, near = [], []
        for book in books:
            why = book.misses(case, entities, seen, fired)
            if why:
                near.append({"playbook_id": book.id, "title": book.title, "misses": why})
            else:
                matched.append(book)
        # Closest first: one unmet condition is a case somebody may want to look
        # at again, five is a playbook for a different kind of incident.
        near.sort(key=lambda n: len(n["misses"]))
        books = matched
    return Result(
        data=PlaybookList(
            playbooks=[b.to_json() for b in books], count=len(books), near_misses=near
        ),
        summary=f"{len(books)} playbook(s)"
        + (f" match {inp.case_uid}." if inp.case_uid else " loaded.")
        + (
            f" Closest unmatched: {near[0]['playbook_id']} ({'; '.join(near[0]['misses'])})."
            if inp.case_uid and not books and near
            else ""
        ),
    )


@dataclass
class PlaybookMerge:
    playbook: dict[str, Any] = f(
        doc="The playbook in the YAML shape of content/playbooks, as JSON, or as "
        "playbook.list returns one: id, title, rules, questions, benign_when, trigger, "
        "steps. A step uses an action policy.show lists. A shipped id is refused; an id "
        "merged here before is replaced",
        factory=dict,
    )
    reason: str = f("", doc="One sentence on why this playbook, now")
    dry_run: bool = f(False, doc="Run the whole gate and write nothing")


@dataclass
class PlaybookMerged:
    playbook_id: str = ""
    rules: list[str] = field(default_factory=list)
    # The rules it took, and the playbook that answered each before.
    took_from: dict[str, str] = field(default_factory=dict)
    # Open runs of the version it replaced; on a dry run, the ones it would cancel.
    cancelled_runs: int = 0
    dry_run: bool = False


@capability(
    name="playbook.merge",
    summary="Add or replace a playbook here, made of existing actions, behind a gate",
    input=PlaybookMerge,
    output=PlaybookMerged,
    scope="playbooks:merge",
    principals=("human",),
    audit=True,
    tags=("response", "write"),
)
def merge_playbook(ctx: Context, inp: PlaybookMerge) -> Result:
    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    out = playbooks.merge(
        ctx.db, ctx.tenant_id, ctx.config, inp.playbook, inp.reason, who, dry_run=inp.dry_run
    )
    took, runs = out["took_from"], out["cancelled_runs"]
    return Result(
        data=PlaybookMerged(**out, dry_run=inp.dry_run),
        summary=(
            f"{out['playbook_id']} "
            + (
                "passes the gate; nothing merged. It would answer "
                if inp.dry_run
                else "merged; it answers "
            )
            + ", ".join(out["rules"])
            + (
                " (took " + ", ".join(f"{r} from {p}" for r, p in took.items()) + ")"
                if took
                else ""
            )
            + (
                "."
                if not runs
                else f". It would cancel {runs} open run(s) of the version it replaces."
                if inp.dry_run
                else f". {runs} open run(s) of the version it replaced were cancelled."
            )
        ),
        citations=[out["playbook_id"], *out["rules"]],
    )


@dataclass
class PlaybookRevert:
    playbook_id: str = f(doc="A playbook playbook.merge added")
    reason: str = f(doc="Why it goes")


@dataclass
class PlaybookReverted:
    playbook_id: str = ""
    state: str = ""
    # Each of its rules, and the playbook that answers it now.
    answered_by: dict[str, str] = field(default_factory=dict)
    cancelled_runs: int = 0


@capability(
    name="playbook.revert",
    summary="Take back a merged playbook; its rules go back to the playbooks that had them",
    input=PlaybookRevert,
    output=PlaybookReverted,
    scope="playbooks:merge",
    principals=("human",),
    audit=True,
    tags=("response", "write"),
)
def revert_playbook(ctx: Context, inp: PlaybookRevert) -> Result:
    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    out = playbooks.revert(ctx.db, ctx.tenant_id, ctx.config, inp.playbook_id, inp.reason, who)
    back = out["answered_by"]
    return Result(
        data=PlaybookReverted(**out),
        summary=(
            f"{inp.playbook_id} reverted"
            + (
                "; " + ", ".join(f"{r} is answered by {p} again" for r, p in back.items())
                if back
                else ""
            )
            + (
                f"; {out['cancelled_runs']} open run(s) were cancelled."
                if out["cancelled_runs"]
                else "."
            )
        ),
        citations=[inp.playbook_id, *back],
    )


@dataclass
class StartRun:
    playbook_id: str = f(doc="Which playbook to run")
    case_uid: str = f(doc="The case it responds to")
    dry_run: bool = f(True, doc="Plan every step without touching anything")


@dataclass
class RunView:
    run_uid: str = ""
    playbook_id: str = ""
    case_uid: str = ""
    state: str = ""
    steps_done: int = 0
    steps_total: int = 0
    waiting_on: str = ""
    pending_approval: list[str] = field(default_factory=list)
    dry_run: bool = True
    detail: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="playbook.run",
    summary="Start a playbook on a case and run it until something needs a human",
    input=StartRun,
    output=RunView,
    scope="playbooks:run",
    principals=("human", "service", "agent"),
    audit=True,
    tags=("response", "write"),
)
def run_playbook(ctx: Context, inp: StartRun) -> Result:
    run = playbooks.start(
        ctx.db, ctx.tenant_id, inp.playbook_id, inp.case_uid, ctx.config, dry_run=inp.dry_run
    )
    report = playbooks.advance(
        ctx.db, ctx.tenant_id, run["run_uid"], ctx.config.master_key, ctx.config
    )
    steps = playbooks.steps_of(ctx.db, run["run_uid"])
    return Result(
        data=RunView(
            run_uid=report.run_uid,
            playbook_id=inp.playbook_id,
            case_uid=inp.case_uid,
            state=report.state,
            steps_done=report.steps_done,
            steps_total=report.steps_total,
            waiting_on=report.waiting_on,
            pending_approval=report.pending_approval,
            dry_run=bool(run["dry_run"]),
            detail=report.detail,
            steps=[to_json(s) for s in steps],
        ),
        summary=(
            f"{inp.playbook_id} on {inp.case_uid}: {report.state}, "
            f"{report.steps_done}/{report.steps_total} step(s)"
            + (f", waiting on {report.waiting_on}" if report.waiting_on else "")
            + (
                f", {len(report.pending_approval)} optional step(s) left for a human"
                if report.pending_approval
                else ""
            )
            + ("; dry run, nothing was changed." if run["dry_run"] else ".")
        ),
        citations=[report.run_uid, inp.case_uid],
    )


@dataclass
class RunRef:
    run_uid: str = f(doc="The playbook run")


@capability(
    name="playbook.resume",
    summary="Continue a run that was waiting for an approval or a fix",
    input=RunRef,
    output=RunView,
    scope="playbooks:run",
    principals=("human", "service", "agent"),
    audit=True,
    tags=("response", "write"),
)
def resume(ctx: Context, inp: RunRef) -> Result:
    report = playbooks.advance(
        ctx.db, ctx.tenant_id, inp.run_uid, ctx.config.master_key, ctx.config
    )
    steps = playbooks.steps_of(ctx.db, inp.run_uid)
    return Result(
        data=RunView(
            run_uid=report.run_uid,
            state=report.state,
            steps_done=report.steps_done,
            steps_total=report.steps_total,
            waiting_on=report.waiting_on,
            pending_approval=report.pending_approval,
            detail=report.detail,
            steps=[to_json(s) for s in steps],
        ),
        summary=f"{inp.run_uid}: {report.state}, {report.steps_done}/{report.steps_total} step(s).",
        citations=[inp.run_uid],
    )


@capability(
    name="playbook.get",
    summary="Read one playbook run and its steps",
    input=RunRef,
    output=RunView,
    scope="playbooks:read",
    tags=("response", "read"),
)
def get_run(ctx: Context, inp: RunRef) -> Result:
    from shoc.db.pool import fetch_all, fetch_one
    from shoc.errors import NotFound

    run = fetch_one(
        ctx.db,
        "SELECT * FROM shoc.playbook_runs WHERE tenant_id = %s AND run_uid = %s",
        (ctx.tenant_id, inp.run_uid),
    )
    if not run:
        raise NotFound(f"no playbook run '{inp.run_uid}'")
    steps = playbooks.steps_of(ctx.db, inp.run_uid)
    waiting = next(
        (s["action_uid"] for s in steps if s["state"] == "running" and s["action_uid"]), ""
    )
    done = sum(1 for s in steps if s["state"] in ("done", "skipped"))
    pending = [
        str(r["action_uid"])
        for r in fetch_all(
            ctx.db,
            """SELECT action_uid FROM shoc.actions
               WHERE tenant_id = %s AND run_uid = %s AND state = 'proposed'
               ORDER BY created_at""",
            (ctx.tenant_id, inp.run_uid),
        )
    ]
    return Result(
        data=RunView(
            run_uid=run["run_uid"],
            playbook_id=run["playbook_id"],
            case_uid=run["case_uid"] or "",
            state=run["state"],
            steps_done=done,
            steps_total=len(steps),
            waiting_on=waiting if run["state"] == "waiting_approval" else "",
            pending_approval=[p for p in pending if p != waiting],
            dry_run=bool(run["dry_run"]),
            detail=[run["error"]] if run["error"] else [],
            steps=[to_json(s) for s in steps],
        ),
        summary=(
            f"{run['playbook_id']} on {run['case_uid']}: {run['state']}, "
            f"{done}/{len(steps)} step(s)"
            + (f", {len(pending)} awaiting a human" if pending else "")
            + ("; dry run." if run["dry_run"] else ".")
        ),
        citations=[run["run_uid"]] + ([run["case_uid"]] if run["case_uid"] else []),
    )


@dataclass
class RunFilter:
    case_uid: str = f("", doc="Only runs for this case")
    limit: int = f(25, doc="Maximum rows")


@dataclass
class RunPage:
    runs: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="playbook.runs",
    summary="List playbook runs and where each one stopped",
    input=RunFilter,
    output=RunPage,
    scope="playbooks:read",
    tags=("response", "read"),
)
def list_runs(ctx: Context, inp: RunFilter) -> Result:
    rows = playbooks.runs_for(ctx.db, ctx.tenant_id, inp.case_uid, inp.limit)
    waiting = sum(1 for r in rows if r["state"] == "waiting_approval")
    return Result(
        data=RunPage(runs=[to_json(r) for r in rows], count=len(rows)),
        summary=f"{len(rows)} run(s); {waiting} waiting for approval.",
        citations=[r["run_uid"] for r in rows],
    )
