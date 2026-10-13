"""An action that reads what it changes acts on the state kept before its first try
(RSP-4).

A retry after a lost answer used to read the changed state and keep that for undo
(an owner demoted to member restored as member), or fail for ever on a role or a
rule its first try had already removed.
"""

from __future__ import annotations

import httpx
import pytest

from shoc.actions import aws, entra, github, m365, okta
from shoc.actions.base import Credentials
from shoc.errors import StoreError

OKTA = Credentials("okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"})


def vendor(gone: bool = False):
    """A vendor that records each call; with `gone`, the thing is no longer there."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(404 if gone else 200, json={"role": "member"})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def tokens(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.msgraph.access_token", lambda *a, **k: "t")


def test_a_retried_demotion_restores_the_role_kept_before_the_first_try():
    seen, client = vendor()
    creds = Credentials("github", secret={"token": "ghp"})
    result = github.DemoteOrgOwner().execute(
        creds, {"user": "eve", "org": "acme"}, client, before={"role": "admin"}
    )
    assert [r.method for r in seen] == ["PUT"], "the role is not read again"
    assert result.undo["role"] == "admin"


def test_a_role_the_first_try_removed_is_done_with_the_grant_kept():
    seen, client = vendor(gone=True)
    grant = {"type": "SUPER_ADMIN"}
    result = okta.RemoveAdminRole().execute(
        OKTA, {"user": "00u1", "role": "ra1"}, client, before=grant
    )
    assert [r.method for r in seen] == ["DELETE"]
    assert result.ok and result.undo == {"user": "00u1", "grant": grant}


def test_an_entra_assignment_the_first_try_removed_is_done_with_the_grant_kept(tokens):
    seen, client = vendor(gone=True)
    grant = {"roleDefinitionId": "rd1", "principalId": "u1", "directoryScopeId": "/"}
    result = entra.RemoveAdminRole().execute(
        Credentials("entra"), {"user": "u1", "role": "ra1"}, client, before=grant
    )
    assert [r.method for r in seen] == ["DELETE"]
    assert result.ok and result.undo["grant"] == grant


def test_a_role_that_was_never_there_still_fails_on_a_first_try():
    _seen, client = vendor(gone=True)
    with pytest.raises(StoreError):
        okta.RemoveAdminRole().execute(OKTA, {"user": "00u1", "role": "ra1"}, client)


def test_an_inbox_rule_the_first_try_deleted_can_still_be_recreated(tokens):
    seen, client = vendor(gone=True)
    rule = {"displayName": "fwd", "actions": {"forwardTo": ["x"]}}
    params = {"user": "alice@example.com", "rule_id": "r1"}
    action = m365.DeleteInboxRule()
    result = action.execute(Credentials("m365"), params, client, before=rule)
    assert result.ok and result.undo == {"user": "alice@example.com", "rule": rule}
    assert [r.method for r in seen] == ["DELETE"]


def test_an_instance_retried_restores_the_groups_it_had_before_isolation(monkeypatch):
    swapped: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(aws, "_isolation_group", lambda *a: "sg-iso")
    monkeypatch.setattr(
        aws, "_set_groups", lambda _c, _r, eni, groups, _h: swapped.append((eni, groups))
    )
    before = {"region": "eu-west-1", "vpc": "vpc-1", "interfaces": {"eni-a": ["sg-web"]}}
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    result = aws.IsolateInstance().execute(
        creds, {"instance_id": "i-0abc1234def567890"}, before=before
    )
    assert swapped == [("eni-a", ["sg-iso"])], "the instance is not looked up again"
    assert result.undo["interfaces"] == {"eni-a": ["sg-web"]}
