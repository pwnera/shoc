"""Passwords, authenticator codes and link seeds for people signing in (SEC-3, RFC 0028)."""

from __future__ import annotations

import asyncio
import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from shoc.api import credentials
from shoc.errors import ConfigError, SignInError

# RFC 6238 appendix B, SHA-1: the seed and the 8-digit codes at each time. Six
# digits are the last six, since both are the same number modulo a power of ten.
RFC_SEED = b"12345678901234567890"
RFC_CODES = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}


@pytest.mark.parametrize("now", sorted(RFC_CODES))
def test_codes_match_the_rfc_6238_vectors(now):
    code = RFC_CODES[now][-6:]
    assert credentials._code(RFC_SEED, now // 30) == code
    assert credentials.totp_step(RFC_SEED, code, float(now), 0) == now // 30


def test_a_code_works_one_step_either_side_and_no_further():
    step = 1234567890 // 30
    code = credentials._code(RFC_SEED, step)
    for now_step in (step - 1, step, step + 1):
        assert credentials.totp_step(RFC_SEED, code, now_step * 30 + 5.0, 0) == step
    for now_step in (step - 2, step + 2):
        assert credentials.totp_step(RFC_SEED, code, now_step * 30 + 5.0, 0) is None


def test_a_code_is_refused_at_or_below_the_last_accepted_step():
    """A code works once: the step it belongs to must be above the stored one."""
    step = 1111111111 // 30
    code = credentials._code(RFC_SEED, step)
    now = step * 30 + 1.0
    assert credentials.totp_step(RFC_SEED, code, now, step - 1) == step
    assert credentials.totp_step(RFC_SEED, code, now, step) is None
    assert credentials.totp_step(RFC_SEED, code, now, step + 1) is None


@pytest.mark.parametrize(
    "code", ["", "12345", "1234567", "12a456", " 12345", "\u0661\u0662\u0663\u0664\u0665\u0666"]
)
def test_a_code_that_is_not_six_ascii_digits_is_refused(code):
    assert credentials.totp_step(RFC_SEED, code, 59.0, 0) is None


def test_a_password_is_kept_as_scrypt_with_its_own_salt():
    stored = credentials.hash_password("correct horse battery")
    name, n, r, p, salt, key = stored.split("$")
    assert (name, n, r, p) == ("scrypt", "32768", "8", "1")
    assert len(bytes.fromhex(salt)) == 16 and len(bytes.fromhex(key)) == 32
    assert "correct horse battery" not in stored
    assert credentials.hash_password("correct horse battery") != stored  # a new salt each time
    assert credentials.check_password("correct horse battery", stored)
    assert not credentials.check_password("correct horse batterY", stored)
    assert not credentials.check_password("", stored)


def test_an_unknown_account_costs_one_hash_and_never_matches(monkeypatch):
    """No account still runs scrypt, so timing does not say whether the email exists."""
    calls: list[int] = []
    real = credentials._scrypt

    def counted(*args):
        calls.append(1)
        return real(*args)

    monkeypatch.setattr(credentials, "_scrypt", counted)
    assert credentials.check_password("anything at all", None) is False
    assert credentials.check_password("", None) is False
    assert len(calls) == 2


def test_an_overlong_password_never_matches():
    stored = credentials.hash_password("x" * credentials.MAX_PASSWORD)
    assert credentials.check_password("x" * credentials.MAX_PASSWORD, stored)
    assert not credentials.check_password("x" * (credentials.MAX_PASSWORD + 1), stored)


def test_the_password_policy():
    email = "ann@example.com"
    assert credentials.password_problem("x" * 11, email) is not None
    assert credentials.password_problem("x" * 12, email) is None
    assert credentials.password_problem("x" * 256, email) is None
    assert credentials.password_problem("x" * 257, email) is not None
    assert credentials.password_problem("ANN@example.com", email) is not None
    assert credentials.password_problem(" ann@example.com ", email) is not None


def test_a_link_seed_is_derived_from_the_master_key_and_the_link():
    link = "shoc_link_abc"
    seed = credentials.link_seed("master-one", link)
    assert len(seed) == 20
    assert credentials.link_seed("master-one", link) == seed
    assert credentials.link_seed("master-two", link) != seed
    assert credentials.link_seed("master-one", "shoc_link_abd") != seed
    with pytest.raises(ConfigError):
        credentials.link_seed("", link)


def test_otpauth_carries_the_seed_for_an_authenticator_app():
    seed = credentials.new_seed()
    assert len(seed) == 20 and credentials.new_seed() != seed
    uri = credentials.otpauth(seed, "ann@example.com")
    parts = urlsplit(uri)
    assert (parts.scheme, parts.netloc) == ("otpauth", "totp")
    assert parts.path == "/shoc:ann%40example.com"
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query["issuer"] == "shoc" and query["algorithm"] == "SHA1"
    assert (query["digits"], query["period"]) == ("6", "30")
    secret = query["secret"]
    assert "=" not in secret
    assert base64.b32decode(secret + "=" * (-len(secret) % 8)) == seed


def test_sessions_and_links_are_long_random_values():
    one, two = credentials.new_secret("shoc_link_"), credentials.new_secret("shoc_link_")
    assert one.startswith("shoc_link_") and one != two
    assert len(one) >= len("shoc_link_") + 43  # 32 bytes, url-safe base64
    assert credentials.digest(one) != one and len(credentials.digest(one)) == 64


def test_hashing_runs_off_the_loop_and_refuses_a_pile_up(monkeypatch):
    assert asyncio.run(credentials.hashing(lambda a, b: a + b, 2, 3)) == 5
    monkeypatch.setattr(credentials, "_waiting", credentials.MAX_WAITING)
    with pytest.raises(SignInError) as refused:
        asyncio.run(credentials.hashing(lambda: 1))
    assert (refused.value.code, refused.value.status) == ("slow_down", 429)
    assert refused.value.retry_after == 5
