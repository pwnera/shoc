from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from shoc.capabilities import registry
from shoc.capabilities.registry import Caller, Capability, Context, Result, all_capabilities, get
from shoc.db import audit
from shoc.errors import Denied


def test_every_capability_declares_a_scope_and_schemas():
    caps = all_capabilities()
    assert len(caps) >= 10
    for cap in caps:
        assert cap.scope and ":" in cap.scope
        assert cap.input_schema()["type"] == "object"
        assert cap.rest_path.startswith("/v1/")
        assert cap.mcp_name.isidentifier()


def test_rest_paths_and_mcp_names_are_unique():
    caps = all_capabilities()
    assert len({c.rest_path for c in caps}) == len(caps)
    assert len({c.mcp_name for c in caps}) == len(caps)


def test_scope_check_blocks_a_caller_without_the_scope_and_audits_it(steps):
    cap = get("events.query")
    ctx = Context(tenant_id="t", caller=Caller(kind="human", id="u", scopes=("findings:read",)))
    with pytest.raises(Denied, match="lacks scope"):
        cap.invoke(ctx, {})
    assert steps == ["audit events.query: caller lacks scope 'events:read'"]


def test_principal_check_blocks_an_agent_from_a_human_only_capability(steps):
    cap = get("source.configure")
    ctx = Context(tenant_id="t", caller=Caller(kind="agent", id="crew", scopes=("*",)))
    with pytest.raises(Denied, match="principal"):
        cap.invoke(ctx, {"source": "okta"})
    assert len(steps) == 1 and "may not call" in steps[0]


def test_a_refusal_repeated_within_the_minute_leaves_one_row(steps):
    cap = get("events.query")
    ctx = Context(tenant_id="t", caller=Caller(kind="human", id="u", scopes=("findings:read",)))
    for _ in range(3):
        with pytest.raises(Denied):
            cap.invoke(ctx, {})
    assert len(steps) == 1


def test_a_refusal_stands_when_its_audit_row_cannot_be_written(monkeypatch):
    def lost(*_args, **_kwargs):
        raise RuntimeError("the database is gone")

    monkeypatch.setattr(audit, "record", lost)
    ctx = Context(tenant_id="t", caller=Caller(kind="human", id="u", scopes=()))
    with pytest.raises(Denied):
        get("events.query").invoke(ctx, {})


def test_area_wildcard_scope_is_accepted():
    caller = Caller(kind="agent", id="worker", scopes=("events:*",))
    assert caller.allows("events:read")
    assert not caller.allows("findings:read")


# -- audit (SEC-1) ------------------------------------------------------------
@dataclass
class Nothing:
    pass


def audited(fn, **kwargs) -> Capability:
    return Capability(
        name="test.write",
        summary="Write",
        input=Nothing,
        output=Nothing,
        scope="test:write",
        fn=fn,
        audit=True,
        **kwargs,
    )


@pytest.fixture
def steps(monkeypatch) -> list[str]:
    said: list[str] = []

    def record(ctx, name, inp, result=None, error=None) -> None:
        said.append(f"audit {error}")

    monkeypatch.setattr(audit, "record", record)
    monkeypatch.setattr(registry, "_refused", {})
    return said


def broken(ctx, inp):
    raise RuntimeError("password authentication failed for user shoc_app")


def test_an_unexpected_failure_is_audited_by_its_class_not_its_message(steps):
    with pytest.raises(RuntimeError):
        audited(broken).invoke(Context(tenant_id="t", caller=Caller()), {})
    assert steps == ["audit RuntimeError"]


def test_a_security_change_commits_with_its_audit_row_or_not_at_all(steps):
    db = MagicMock()
    db.transaction.return_value.__enter__.side_effect = lambda: steps.append("begin")
    db.transaction.return_value.__exit__.side_effect = lambda kind, *_: steps.append(
        "rollback" if kind else "commit"
    )

    def change(ctx, inp):
        steps.append("change")
        return Result(data=Nothing())

    ctx = Context(tenant_id="t", caller=Caller(), _db=db)
    audited(change, tags=("security",)).invoke(ctx, {})
    assert steps == ["begin", "change", "audit None", "commit"]
    steps.clear()
    with pytest.raises(RuntimeError):
        audited(broken, autonomy="L2", principals=("human",)).invoke(ctx, {})
    assert steps == ["begin", "rollback", "audit RuntimeError"]


@dataclass
class Query:
    include_raw: bool = False
    limit: int = 100


def read(name: str) -> Capability:
    return Capability(
        name=name,
        summary="Read",
        input=Query,
        output=Nothing,
        scope="events:read",
        fn=lambda ctx, inp: Result(data=Nothing()),
    )


@pytest.mark.parametrize(
    ("name", "kind", "payload", "audited"),
    [
        ("events.query", "external_agent", {}, True),
        ("case.get", "service", {}, True),
        ("events.query", "human", {}, False),
        ("events.query", "human", {"include_raw": True}, True),
        ("events.query", "human", {"limit": 1000}, True),
        ("case.get", "human", {"include_raw": True}, False),
        ("events.query", "agent", {"include_raw": True, "limit": 1000}, False),
        ("finding.list", "external_agent", {}, False),
    ],
)
def test_a_tokens_read_and_a_bulk_or_raw_read_of_events_are_audited(
    steps, name, kind, payload, audited
):
    read(name).invoke(Context(tenant_id="t", caller=Caller(kind=kind, id="x")), payload)
    assert steps == (["audit None"] if audited else [])
