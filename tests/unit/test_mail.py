"""Whether invitation and reset mail can go out (SEC-3, RFC 0028)."""

from __future__ import annotations

import pytest

from shoc import mail
from shoc.config import Config

SERVER = "smtps://apikey:pw@mail.example.com:465"


@pytest.mark.parametrize(
    ("smtp_url", "mail_from", "ready"),
    [
        ("", "shoc@example.com", False),
        (SERVER, "", False),  # the SMTP user is not an address
        (SERVER, "shoc@example.com", True),
        ("smtps://shoc%40example.com:pw@mail.example.com:465", "", True),
    ],
)
def test_mail_needs_a_server_and_a_sender(smtp_url, mail_from, ready):
    assert mail.configured(Config(smtp_url=smtp_url, mail_from=mail_from)) is ready
