"""Microsoft identity plumbing shared by the Entra ID and M365 connectors (ING-1).

Both use the same OAuth 2.0 client-credentials flow against a tenant's Azure AD;
only the resource and the query differ.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from shoc.errors import ConfigError

LOGIN = "https://login.microsoftonline.com"
_TOKENS: dict[str, tuple[str, float]] = {}


def access_token(
    secret: dict[str, Any], scope: str = "https://graph.microsoft.com/.default"
) -> str:
    """Client-credentials token, cached until a minute before it expires."""
    tenant = secret.get("tenant_id")
    client_id = secret.get("client_id")
    client_secret = secret.get("client_secret")
    if not (tenant and client_id and client_secret):
        raise ConfigError("microsoft: secret needs tenant_id, client_id and client_secret")
    key = f"{tenant}|{client_id}|{scope}"
    cached = _TOKENS.get(key)
    if cached and cached[1] > time.time():
        return cached[0]
    with httpx.Client(timeout=30.0) as http:
        resp = http.post(
            f"{LOGIN}/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
    token = payload["access_token"]
    _TOKENS[key] = (token, time.time() + int(payload.get("expires_in", 3600)) - 60)
    return token
