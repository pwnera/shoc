"""An AWS source or response credential that assumes a role (po-15, ING-1, RSP-4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from shoc.actions import get
from shoc.actions.base import Credentials
from shoc.errors import ConfigError
from shoc.ingest.connectors import awssig
from shoc.ingest.connectors.base import FetchResult

ROLE = "arn:aws:iam::123456789012:role/shoc-read"
KEYS = {"access_key_id": "AKIAEXAMPLEBASE0001", "secret_access_key": "s"}


def session_xml(expires_in: timedelta) -> str:
    expiry = (datetime.now(UTC) + expires_in).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        "<AssumeRoleResult><Credentials>"
        "<AccessKeyId>ASIAEXAMPLESESSION1</AccessKeyId>"
        "<SecretAccessKey>session-secret</SecretAccessKey>"
        "<SessionToken>session/token+1=</SessionToken>"
        f"<Expiration>{expiry}</Expiration>"
        "</Credentials></AssumeRoleResult></AssumeRoleResponse>"
    )


def sts(expires_in: timedelta = timedelta(hours=1)):
    """STS answers AssumeRole; every other call answers an empty JSON body."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if b"Action=AssumeRole" in request.content:
            return httpx.Response(200, text=session_xml(expires_in))
        return httpx.Response(200, json={})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def no_sessions(monkeypatch):
    monkeypatch.setattr(awssig, "_sessions", {})


def test_a_response_credential_with_a_role_signs_as_the_role_and_assumes_it_once():
    creds = Credentials("aws", settings={"role_arn": ROLE, "external_id": "ext-7"}, secret=KEYS)
    seen, client = sts()
    action = get("aws.start_config_recorder")
    action.execute(creds, {"recorder": "eu-west-3/default"}, client)
    action.execute(creds, {"recorder": "eu-west-3/default"}, client)
    assumes = [r for r in seen if b"Action=AssumeRole" in r.content]
    assert len(assumes) == 1, "the session is kept until it nearly expires"
    sent = assumes[0].content.decode()
    assert "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fshoc-read" in sent
    assert "ExternalId=ext-7" in sent
    assert assumes[0].url.host == "sts.amazonaws.com"
    assert "Credential=AKIAEXAMPLEBASE0001/" in assumes[0].headers["Authorization"]
    calls = [r for r in seen if r not in assumes]
    assert len(calls) == 2
    for r in calls:
        assert "Credential=ASIAEXAMPLESESSION1/" in r.headers["Authorization"]
        assert r.headers["x-amz-security-token"] == "session/token+1="


def test_a_session_about_to_expire_is_renewed():
    creds = Credentials("aws", settings={"role_arn": ROLE}, secret=KEYS)
    seen, client = sts(expires_in=awssig.RENEW / 2)
    action = get("aws.start_config_recorder")
    action.execute(creds, {"recorder": "eu-west-3/default"}, client)
    action.execute(creds, {"recorder": "eu-west-3/default"}, client)
    assumes = [r for r in seen if b"Action=AssumeRole" in r.content]
    assert len(assumes) == 2
    assert "ExternalId" not in assumes[0].content.decode()


def test_without_a_role_the_key_signs_its_own_calls():
    seen, client = sts()
    get("aws.start_config_recorder").execute(
        Credentials("aws", secret=KEYS), {"recorder": "eu-west-3/default"}, client
    )
    assert len(seen) == 1 and b"AssumeRole" not in seen[0].content
    assert "Credential=AKIAEXAMPLEBASE0001/" in seen[0].headers["Authorization"]


def test_a_role_needs_a_key_to_assume_it():
    with pytest.raises(ConfigError, match="role_arn"):
        awssig.assumed({"role_arn": ROLE}, {})


def test_an_aws_source_with_a_role_reads_with_the_role_s_session(monkeypatch):
    seen, client = sts()
    monkeypatch.setattr(awssig, "client", lambda *a, **k: client)
    got: list[dict[str, Any]] = []

    class Inner:
        source = "aws_guardduty"

        def fetch(self, settings, secret, cursor, limit) -> FetchResult:
            got.append(secret)
            return FetchResult()

    awssig.Regions(Inner()).fetch(
        {"region": "eu-west-1", "role_arn": ROLE, "external_id": "ext-7"}, KEYS, {}, 10
    )
    assert got[0]["access_key_id"] == "ASIAEXAMPLESESSION1"
    assert got[0]["session_token"] == "session/token+1="
    assert len(seen) == 1 and b"ExternalId=ext-7" in seen[0].content
