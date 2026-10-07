"""Google service-account authentication shared by the Google connectors (ING-1).

Workspace impersonates an admin through domain-wide delegation; GCP acts as the
service account itself. Both sign the same JWT assertion and swap it for an
access token, so `pyjwt` and `cryptography` cover it and no Google SDK is needed.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt

from shoc.errors import ConfigError

TOKEN_URL = "https://oauth2.googleapis.com/token"
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
_TOKENS: dict[str, tuple[str, float]] = {}
_CLIENT_IDS: dict[str, str] = {}


def client_id(secret: dict[str, Any], token: str = "") -> str:
    """The service account's numeric client id, as Google's token log names it.

    A key file carries it as `client_id`; one pasted without it is asked once
    per process, from the token Google just issued (`azp`).
    """
    known = str(secret.get("client_id") or "")
    email = str(secret.get("client_email") or "")
    if known or not email:
        return known
    if email not in _CLIENT_IDS and token:
        with httpx.Client(timeout=30.0) as http:
            resp = http.get(TOKENINFO_URL, params={"access_token": token})
        if resp.is_success:
            _CLIENT_IDS[email] = str(resp.json().get("azp") or resp.json().get("issued_to") or "")
    return _CLIENT_IDS.get(email, "")


def access_token(secret: dict[str, Any], scope: str, subject: str | None = None) -> str:
    """Signed-assertion token, cached until a minute before it expires."""
    client_email = secret.get("client_email")
    private_key = secret.get("private_key")
    if not (client_email and private_key):
        raise ConfigError("google: secret needs client_email and private_key")
    key = f"{client_email}|{scope}|{subject or ''}"
    cached = _TOKENS.get(key)
    if cached and cached[1] > time.time():
        return cached[0]
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": client_email,
        "scope": scope,
        "aud": TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }
    if subject:
        claims["sub"] = subject
    assertion = jwt.encode(claims, private_key.replace("\\n", "\n"), algorithm="RS256")
    with httpx.Client(timeout=30.0) as http:
        resp = http.post(
            TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
    token = payload["access_token"]
    _TOKENS[key] = (token, time.time() + int(payload.get("expires_in", 3600)) - 60)
    # Google logs this request as an OAuth authorisation by this client id; shoc
    # remembers making it so the record is read as shoc's own (RFC 0021).
    from shoc.cases.own import note_token

    note_token(client_id(secret, token))
    return token
