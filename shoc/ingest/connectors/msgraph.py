"""Microsoft identity plumbing shared by the Entra ID and M365 connectors (ING-1).

Both use the same OAuth 2.0 client-credentials flow against a tenant's Azure AD;
only the resource and the query differ.
"""

from __future__ import annotations

from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import client_token

LOGIN = "https://login.microsoftonline.com"


def access_token(
    secret: dict[str, Any], scope: str = "https://graph.microsoft.com/.default"
) -> str:
    """Client-credentials token, cached as `client_token` says."""
    tenant = secret.get("tenant_id")
    client_id = secret.get("client_id")
    client_secret = secret.get("client_secret")
    if not (tenant and client_id and client_secret):
        raise ConfigError("microsoft: secret needs tenant_id, client_id and client_secret")
    return client_token(
        f"{LOGIN}/{tenant}/oauth2/v2.0/token",
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
