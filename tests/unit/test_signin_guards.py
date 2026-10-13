"""What the /auth/* routes refuse or hold back before they reach the database (SEC-3)."""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
from starlette.requests import Request

from shoc.api import people, signin
from shoc.config import Config
from shoc.db.pool import ALL_TENANTS
from shoc.errors import Denied, SignInError


def request(**headers: str) -> Request:
    return Request(
        {"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers.items()]}
    )


def test_a_sign_in_cannot_name_every_tenant():
    with pytest.raises(SignInError):
        signin._tenant(request(**{"x-shoc-tenant": ALL_TENANTS}), Config())
    assert signin._tenant(request(**{"x-shoc-tenant": "acme"}), Config()) == "acme"
    with pytest.raises(Denied), people.pinned(Config(), ALL_TENANTS):
        pass


def test_forgotten_passwords_are_handled_two_at_a_time(monkeypatch):
    cfg = Config()
    cfg.smtp_url, cfg.mail_from = "smtps://mailer:pw@mail.example.com:465", "shoc@example.com"
    release, lock = threading.Event(), threading.Lock()
    running, most = [0], [0]

    def slow(*args) -> None:
        with lock:
            running[0] += 1
            most[0] = max(most[0], running[0])
        release.wait(5)
        with lock:
            running[0] -= 1

    monkeypatch.setattr(signin, "_forgot", slow)
    for _ in range(6):
        answer = asyncio.run(signin.forgot(request(), {"email": "ann@example.com"}, cfg))
        assert json.loads(bytes(answer.body)) == {"sent": True}, (
            "the answer stays the same, at once"
        )
    time.sleep(0.3)
    release.set()
    signin._forgetting.submit(lambda: None).result(10)
    assert most[0] == 2, "each one holds a database connection while it runs"
