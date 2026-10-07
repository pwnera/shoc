"""What shoc trusts from the company's OpenID Connect provider (SEC-3, RFC 0028).

No network: discovery, the token exchange and the provider's keys are replaced
by fakes, and the ID tokens are signed here with keys made for the test.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from shoc.api import oidc
from shoc.errors import SignInError, UpstreamError, ValidationError

ISSUER = "https://idp.example.com"
CLIENT = "shoc-client"
NONCE = "the-nonce"
GOOGLE = "https://accounts.google.com"
TENANT = "8a2f3c1e-0b4d-4e6f-9a7b-1c2d3e4f5a6b"
MICROSOFT = f"https://login.microsoftonline.com/{TENANT}/v2.0"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())

# Whatever refuses a token: pyjwt's own checks or shoc's.
REFUSED = (jwt.PyJWTError, SignInError)


def provider(issuer: str = ISSUER, domains: tuple[str, ...] = ("example.com",)) -> dict[str, Any]:
    return {
        "issuer": issuer,
        "client_id": CLIENT,
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/keys",
        "domains": list(domains),
    }


class Keys:
    """Stands in for jwt.PyJWKClient: always the key the test chose."""

    def __init__(self, key: Any) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, token: str) -> Keys:
        return self


@pytest.fixture
def jwks(monkeypatch) -> Keys:
    keys = Keys(RSA_KEY.public_key())
    monkeypatch.setattr(oidc, "_keys", lambda uri: keys)
    return keys


def payload(**changes: Any) -> dict[str, Any]:
    """A valid ID token's claims; a change to None drops that claim."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT,
        "sub": "subject-1",
        "iat": now,
        "exp": now + 300,
        "nonce": NONCE,
        "email": "ann@example.com",
        "email_verified": True,
    }
    claims.update(changes)
    return {k: v for k, v in claims.items() if v is not None}


def signed(claims: dict[str, Any], key: Any = RSA_KEY, algorithm: str = "RS256") -> str:
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "k1"})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def forged(claims: dict[str, Any], algorithm: str, secret: bytes = b"") -> str:
    """A token pyjwt would not make: unsigned, or HMAC'd with the public key as the secret."""
    head = _b64(json.dumps({"alg": algorithm, "typ": "JWT", "kid": "k1"}).encode())
    body = _b64(json.dumps(claims).encode())
    if algorithm == "none":
        return f"{head}.{body}."
    mac = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(mac)}"


# -- the ID token ------------------------------------------------------------------
def test_a_valid_id_token_is_accepted(jwks):
    found = oidc.claims(provider(), signed(payload()), NONCE)
    assert found["sub"] == "subject-1" and found["email"] == "ann@example.com"


def test_ps256_and_es256_are_accepted(jwks):
    assert oidc.claims(provider(), signed(payload(), algorithm="PS256"), NONCE)["sub"]
    jwks.key = EC_KEY.public_key()
    assert oidc.claims(provider(), signed(payload(), EC_KEY, "ES256"), NONCE)["sub"]


def test_a_token_within_the_leeway_is_accepted(jwks):
    now = int(time.time())
    assert oidc.claims(provider(), signed(payload(exp=now - 30)), NONCE)


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "another-client"},
        {"aud": [CLIENT, "another-client"], "azp": "another-client"},
        {"azp": "another-client"},
        {"iss": "https://idp.example.com/"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) - 120, "iat": int(time.time()) - 600},
        {"nonce": None},
        {"nonce": "another-nonce"},
        {"sub": None},
        {"exp": None},
        {"iat": None},
    ],
    ids=[
        "wrong-aud",
        "azp-other-in-aud-list",
        "azp-mismatch",
        "issuer-trailing-slash",
        "wrong-iss",
        "expired",
        "no-nonce",
        "wrong-nonce",
        "no-sub",
        "no-exp",
        "no-iat",
    ],
)
def test_an_id_token_that_fails_a_check_is_refused(jwks, changes):
    with pytest.raises(REFUSED):
        oidc.claims(provider(), signed(payload(**changes)), NONCE)


def test_a_token_signed_by_another_key_is_refused(jwks):
    with pytest.raises(REFUSED):
        oidc.claims(provider(), signed(payload(), OTHER_KEY), NONCE)


def test_alg_none_is_refused(jwks):
    with pytest.raises(REFUSED):
        oidc.claims(provider(), forged(payload(), "none"), NONCE)


def test_hs256_with_the_public_key_as_secret_is_refused(jwks):
    """The classic confusion: an HMAC keyed with the provider's public key."""
    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(REFUSED):
        oidc.claims(provider(), forged(payload(), "HS256", pem), NONCE)


def test_keys_are_one_client_per_jwks_uri(monkeypatch):
    monkeypatch.setattr(oidc, "_jwks", {})
    first = oidc._keys("https://idp.example.com/keys")
    assert oidc._keys("https://idp.example.com/keys") is first
    assert oidc._keys("https://idp.example.com/other-keys") is not first


# -- whose email it is ---------------------------------------------------------------
def refused_code(found: dict[str, Any], issuer: str = ISSUER) -> str:
    with pytest.raises(SignInError) as refused:
        oidc.email_of(provider(issuer), found)
    return refused.value.code


def test_another_provider_must_say_the_email_is_verified():
    assert oidc.email_of(provider(), payload(email="Ann@Example.com")) == "ann@example.com"
    assert oidc.email_of(provider(), payload(email_verified="true")) == "ann@example.com"
    assert refused_code(payload(email_verified=False)) == "sso_unverified"
    assert refused_code(payload(email_verified=None)) == "sso_unverified"
    assert refused_code(payload(email_verified="yes")) == "sso_unverified"


def test_google_needs_a_verified_email_and_the_company_domain_as_hd():
    assert oidc.email_of(provider(GOOGLE), payload(iss=GOOGLE, hd="example.com"))
    # A personal Google account on a company address carries no hd.
    assert refused_code(payload(iss=GOOGLE), GOOGLE) == "sso_unverified"
    assert refused_code(payload(iss=GOOGLE, hd="gmail.com"), GOOGLE) == "sso_unverified"
    unverified = payload(iss=GOOGLE, hd="example.com", email_verified=False)
    assert refused_code(unverified, GOOGLE) == "sso_unverified"


def test_microsoft_needs_its_own_tenant_and_no_guest():
    member = payload(iss=MICROSOFT, tid=TENANT, email_verified=None)
    assert oidc.email_of(provider(MICROSOFT), member) == "ann@example.com"
    assert oidc.email_of(provider(MICROSOFT), {**member, "tid": TENANT.upper()})
    guest = {**member, "idp": "https://sts.windows.net/99999999-0000-0000-0000-000000000000/"}
    assert refused_code(guest, MICROSOFT) == "sso_unverified"
    elsewhere = {**member, "tid": "99999999-0000-0000-0000-000000000000"}
    assert refused_code(elsewhere, MICROSOFT) == "sso_unverified"
    assert refused_code(payload(iss=MICROSOFT, email_verified=True), MICROSOFT) == "sso_unverified"


def test_the_email_must_be_in_a_configured_domain():
    assert refused_code(payload(email="eve@other.example")) == "sso_domain"
    assert refused_code(payload(email="eve@sub.example.com")) == "sso_domain"
    assert refused_code(payload(email="eve@example.com.evil.example")) == "sso_domain"


def test_no_usable_email_no_sign_in():
    assert refused_code(payload(email=None)) == "sso_unverified"
    assert refused_code(payload(email="")) == "sso_unverified"
    assert refused_code(payload(email="Ann <ann@example.com>")) == "sso_unverified"
    assert refused_code(payload(email=["ann@example.com"])) == "sso_unverified"


# -- discovery ---------------------------------------------------------------------
def document(issuer: str = ISSUER, **changes: Any) -> dict[str, Any]:
    found = {
        "issuer": issuer,
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/keys",
    }
    found.update(changes)
    return {k: v for k, v in found.items() if v is not None}


@pytest.fixture
def offline(monkeypatch):
    """Discovery must refuse before it reaches the network."""

    def no_network(*args, **kwargs):
        raise AssertionError("discovery reached the network")

    monkeypatch.setattr(oidc.httpx, "get", no_network)
    monkeypatch.setattr(oidc.httpx, "post", no_network)


def serve(monkeypatch, found: dict[str, Any]) -> list[str]:
    asked: list[str] = []

    def get_json(url: str) -> dict[str, Any]:
        asked.append(url)
        return found

    monkeypatch.setattr(oidc, "_get_json", get_json)
    return asked


def test_discovery_reads_the_endpoints(monkeypatch):
    asked = serve(monkeypatch, document(extra="ignored"))
    assert oidc.discover(ISSUER) == {
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/keys",
    }
    assert asked == [f"{ISSUER}/.well-known/openid-configuration"]


def test_discovery_takes_a_microsoft_tenant_issuer(monkeypatch):
    serve(monkeypatch, document(MICROSOFT))
    assert oidc.discover(MICROSOFT)["issuer"] == MICROSOFT


@pytest.mark.parametrize(
    "issuer",
    [
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/organizations/v2.0",
        "https://login.microsoftonline.com/consumers/v2.0",
        "https://login.microsoftonline.com/Common/v2.0",
        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    ],
)
def test_discovery_refuses_microsofts_shared_issuers(issuer, offline):
    with pytest.raises(ValidationError, match="shared Microsoft issuer"):
        oidc.discover(issuer)


@pytest.mark.parametrize(
    "issuer",
    [
        "http://idp.example.com",
        "https://127.0.0.1",
        "https://10.0.0.5",
        "https://169.254.169.254",
        "https://[::1]",
        "https://idp.corp",
        "https://localhost",
    ],
)
def test_discovery_refuses_plain_http_and_private_addresses(issuer, offline):
    with pytest.raises(ValidationError):
        oidc.discover(issuer)


@pytest.mark.parametrize(
    "changes",
    [
        {"jwks_uri": "http://idp.example.com/keys"},
        {"token_endpoint": "https://10.0.0.5/token"},
        {"authorization_endpoint": "https://127.0.0.1/authorize"},
        {"jwks_uri": None},
        {"token_endpoint": 7},
    ],
)
def test_discovery_refuses_an_endpoint_that_is_not_public_https(monkeypatch, changes):
    serve(monkeypatch, document(**changes))
    with pytest.raises(ValidationError):
        oidc.discover(ISSUER)


@pytest.mark.parametrize("named", ["https://idp.example.com/", "https://evil.example", None])
def test_discovery_must_name_the_issuer_exactly(monkeypatch, named):
    serve(monkeypatch, document(named))
    with pytest.raises(ValidationError, match="names the issuer"):
        oidc.discover(ISSUER)


def test_an_unreachable_provider_is_an_upstream_error(monkeypatch):
    def down(url: str) -> dict[str, Any]:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(oidc, "_get_json", down)
    with pytest.raises(UpstreamError):
        oidc.discover(ISSUER)


# -- the round trip ----------------------------------------------------------------
def test_the_authorize_url_carries_state_nonce_pkce_and_the_hint():
    verifier, challenge = oidc.pkce()
    expected = _b64(hashlib.sha256(verifier.encode()).digest())
    assert challenge == expected and 43 <= len(verifier) <= 128
    url = oidc.authorize_url(
        provider(), "st", "nn", challenge, "ann@example.com", "https://shoc.example.com/cb"
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://idp.example.com/authorize"
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query == {
        "response_type": "code",
        "client_id": CLIENT,
        "redirect_uri": "https://shoc.example.com/cb",
        "scope": "openid email profile",
        "state": "st",
        "nonce": "nn",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "login_hint": "ann@example.com",
    }
    with_query = {**provider(), "authorization_endpoint": "https://idp.example.com/auth?tenant=1"}
    joined = oidc.authorize_url(with_query, "st", "nn", challenge, "a@example.com", "https://x/cb")
    assert joined.startswith("https://idp.example.com/auth?tenant=1&response_type=code")


def test_the_exchange_posts_the_verifier_and_the_secret(monkeypatch):
    posted: list[tuple[str, dict[str, str]]] = []

    def post_form(url: str, data: dict[str, str]) -> dict[str, Any]:
        posted.append((url, data))
        return {"id_token": "the.id.token", "access_token": "ignored"}

    monkeypatch.setattr(oidc, "_post_form", post_form)
    found = {**provider(), "client_secret": "client-secret"}
    token = oidc.exchange(found, "the-code", "the-verifier", "https://shoc.example.com/cb")
    assert token == "the.id.token"
    url, data = posted[0]
    assert url == "https://idp.example.com/token"
    assert data == {
        "grant_type": "authorization_code",
        "code": "the-code",
        "redirect_uri": "https://shoc.example.com/cb",
        "client_id": CLIENT,
        "client_secret": "client-secret",
        "code_verifier": "the-verifier",
    }


def test_an_exchange_without_an_id_token_fails(monkeypatch):
    monkeypatch.setattr(oidc, "_post_form", lambda url, data: {"access_token": "x"})
    with pytest.raises(SignInError) as refused:
        oidc.exchange(provider(), "code", "verifier", "https://shoc.example.com/cb")
    assert refused.value.code == "sso_failed"


def test_the_network_helpers_refuse_plain_http_and_private_hosts(offline):
    with pytest.raises(ValidationError):
        oidc._post_form("http://idp.example.com/token", {})
    with pytest.raises(ValidationError):
        oidc._get_json("https://192.168.1.10/.well-known/openid-configuration")
