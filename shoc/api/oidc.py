"""OpenID Connect against the company's identity provider (SEC-3, RFC 0028).

shoc is a client of a provider the company already runs: the authorization code
flow with PKCE, the ID token checked with `pyjwt`, and its email trusted only
when the provider vouches for it. The network calls are `_get_json` and
`_post_form` (plus `PyJWKClient` for the keys), so tests replace those.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

from shoc.errors import SignInError, UpstreamError, ValidationError

ALGORITHMS = ["RS256", "PS256", "ES256"]
LEEWAY = 60
TIMEOUT = 10
MICROSOFT = "login.microsoftonline.com"
GOOGLE = "accounts.google.com"
# Microsoft's issuers shared by every tenant, and the personal-accounts tenant:
# a token from any of them says nothing about the company.
MICROSOFT_SHARED = {"common", "organizations", "consumers", "9188040d-6c67-4c5b-b112-36a304b66dad"}
ENDPOINTS = ("authorization_endpoint", "token_endpoint", "jwks_uri")


def _https(url: str) -> str:
    """Only https, and only to a public host (the report fetcher's SSRF guard)."""
    from shoc.detect.report import guard

    if urlsplit(url).scheme != "https":
        raise ValidationError(f"{url} must be https")
    guard(url)
    return url


def _object(response: httpx.Response) -> dict[str, Any]:
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise ValueError(f"{response.url} answered with something other than a JSON object")
    return body


def _get_json(url: str) -> dict[str, Any]:
    return _object(httpx.get(_https(url), timeout=TIMEOUT, follow_redirects=False))


def _post_form(url: str, data: dict[str, str]) -> dict[str, Any]:
    return _object(httpx.post(_https(url), data=data, timeout=TIMEOUT, follow_redirects=False))


def _microsoft_tenant(issuer: str) -> str | None:
    """The tenant an issuer at login.microsoftonline.com names, or None for another host."""
    parts = urlsplit(issuer)
    if parts.hostname != MICROSOFT:
        return None
    return parts.path.strip("/").split("/")[0].lower()


def discover(issuer: str) -> dict[str, Any]:
    """The provider's endpoints, from a discovery document that names `issuer` exactly."""
    if _microsoft_tenant(issuer) in MICROSOFT_SHARED:
        raise ValidationError(
            "a shared Microsoft issuer admits every Microsoft account; use your tenant's "
            "issuer, https://login.microsoftonline.com/<tenant id>/v2.0"
        )
    try:
        document = _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
    except (httpx.HTTPError, ValueError) as exc:
        raise UpstreamError(f"could not read {issuer}'s discovery document: {exc}") from exc
    if document.get("issuer") != issuer:
        raise ValidationError(
            f"the discovery document names the issuer {document.get('issuer')!r}, not {issuer!r}"
        )
    found = {"issuer": issuer}
    for name in ENDPOINTS:
        value = document.get(name)
        if not isinstance(value, str):
            raise ValidationError(f"the discovery document has no {name}")
        found[name] = _https(value)
    return found


def pkce() -> tuple[str, str]:
    """A PKCE verifier and its S256 challenge."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.decode().rstrip("=")


def authorize_url(
    provider: dict[str, Any], state: str, nonce: str, challenge: str, email: str, redirect_uri: str
) -> str:
    endpoint = provider["authorization_endpoint"]
    query = urlencode(
        {
            "response_type": "code",
            "client_id": provider["client_id"],
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "login_hint": email,
        }
    )
    return f"{endpoint}{'&' if '?' in endpoint else '?'}{query}"


def exchange(provider: dict[str, Any], code: str, verifier: str, redirect_uri: str) -> str:
    """The ID token for an authorization code (client_secret_post)."""
    answer = _post_form(
        provider["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider["client_id"],
            "client_secret": provider.get("client_secret", ""),
            "code_verifier": verifier,
        },
    )
    token = answer.get("id_token")
    if not isinstance(token, str):
        raise SignInError("sso_failed", 401, "the provider returned no ID token")
    return token


_jwks: dict[str, jwt.PyJWKClient] = {}
_jwks_lock = threading.Lock()


def _keys(uri: str) -> jwt.PyJWKClient:
    """One key client per JWKS URI, keeping the keys for an hour."""
    with _jwks_lock:
        if uri not in _jwks:
            _jwks[uri] = jwt.PyJWKClient(uri, lifespan=3600, timeout=TIMEOUT)
        return _jwks[uri]


def claims(provider: dict[str, Any], id_token: str, nonce: str) -> dict[str, Any]:
    """The ID token's claims, once its signature, issuer, audience, time and nonce check out."""
    key = _keys(provider["jwks_uri"]).get_signing_key_from_jwt(id_token)
    found = jwt.decode(
        id_token,
        key.key,
        algorithms=ALGORITHMS,
        audience=provider["client_id"],
        issuer=provider["issuer"],
        leeway=LEEWAY,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    if "azp" in found and found["azp"] != provider["client_id"]:
        raise SignInError("sso_failed", 401, "the ID token was issued to another client")
    if not hmac.compare_digest(str(found.get("nonce", "")), nonce):
        raise SignInError("sso_failed", 401, "the ID token's nonce does not match")
    return found


def email_of(provider: dict[str, Any], found: dict[str, Any]) -> str:
    """The email the provider vouches for, in a configured domain (RFC 0028's claim rules)."""
    from shoc.api.people import clean_email, domain_of

    try:
        email = clean_email(found.get("email"))
    except ValidationError as exc:
        raise SignInError("sso_unverified", 401, "the provider sent no usable email") from exc
    domains = provider["domains"]
    if domain_of(email) not in domains:
        raise SignInError("sso_domain", 401, f"{domain_of(email)} is not a configured domain")
    tenant = _microsoft_tenant(provider["issuer"])
    if tenant is not None:
        # A member's address is set by the company's administrators; a guest's
        # (`idp` present) by its home company.
        vouched = str(found.get("tid", "")).lower() == tenant and "idp" not in found
    else:
        vouched = found.get("email_verified") in (True, "true")
        if urlsplit(provider["issuer"]).hostname == GOOGLE:
            # A personal Google account on a company address carries no `hd`.
            vouched = vouched and found.get("hd") in domains
    if not vouched:
        raise SignInError("sso_unverified", 401, "the provider does not vouch for this email")
    return email
