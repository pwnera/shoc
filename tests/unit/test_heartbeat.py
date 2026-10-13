"""The ping an outside monitor waits for after each hourly check (OPS-1, D57)."""

from __future__ import annotations

import logging

import httpx
import pytest

from shoc import worker
from shoc.config import Config


def test_with_no_url_nothing_leaves(monkeypatch: pytest.MonkeyPatch):
    sent: list[str] = []
    monkeypatch.setattr(httpx, "get", lambda url, **_: sent.append(url))
    assert worker.heartbeat(Config(heartbeat_url="")) == ""
    assert not sent, "the ping is egress a deployer opts into"


def test_a_ping_goes_to_the_url_set(monkeypatch: pytest.MonkeyPatch):
    sent: list[str] = []

    def answer(url: str, **_: object) -> httpx.Response:
        sent.append(url)
        return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", answer)
    url = "https://hc.example.test/ping/0000-test"
    assert worker.heartbeat(Config(heartbeat_url=url)) == ""
    assert sent == [url]


def test_a_failed_ping_is_said_without_its_url(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    """The URL's path is the monitor's secret, so a summary or a log never carries it."""

    def refuse(url: str, **_: object) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {url}")

    monkeypatch.setattr(httpx, "get", refuse)
    with caplog.at_level(logging.DEBUG):
        said = worker.heartbeat(Config(heartbeat_url="https://hc.example.test/ping/secret-0000"))
    assert said == " Heartbeat not sent: ConnectError."
    assert caplog.records, "a failed ping is logged"
    assert not [r for r in caplog.records if "secret-0000" in r.getMessage()]
