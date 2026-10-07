"""Per-tenant secrets, encrypted at rest with the master key (SEC-1).

AES-256-GCM from `cryptography`, keyed from SHOC_MASTER_KEY. The row a value
is stored in (tenant, table, key column) is the associated data, so a sealed
value copied into another row, or into another tenant's, does not open. The
SaaS will swap this module's key source for KMS without touching callers.

Values sealed before that were Fernet tokens bound to nothing. `shoc migrate`
re-seals them (`reseal`), and `open_secret` refuses one it still finds.
`shoc rotate-key` re-seals every value under a new master key the same way.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shoc.errors import ConfigError

BOUND = b"\x02"  # a Fernet token starts with "gAAAA", so the two never collide

# Every column that holds a sealed value, and the column that names its row.
SEALED = (
    ("connector_config", "source"),
    ("action_credentials", "provider"),
    ("intel_feeds", "feed"),
    ("lookup_sources", "source"),  # keyed lookup sources (RFC 0030)
    ("webhooks", "webhook_id"),
    ("users", "user_id"),  # the authenticator's seed (RFC 0028)
    ("sso_providers", "provider"),  # the OIDC client secret
)


def _aead(master_key: str) -> AESGCM:
    if not master_key:
        raise ConfigError("SHOC_MASTER_KEY is not set; connector secrets cannot be stored")
    return AESGCM(hashlib.sha256(b"shoc secrets\0" + master_key.encode()).digest())


def _row(tenant_id: str, table: str, key: str) -> bytes:
    return json.dumps([tenant_id, table, key]).encode()


def generate_key() -> str:
    return Fernet.generate_key().decode()


def seal(master_key: str, secret: dict[str, Any], tenant_id: str, table: str, key: str) -> bytes:
    """Encrypt `secret` for one row: `table` where the tenant is `tenant_id` and its key is `key`."""
    nonce = os.urandom(12)
    body = json.dumps(secret, sort_keys=True).encode()
    return BOUND + nonce + _aead(master_key).encrypt(nonce, body, _row(tenant_id, table, key))


def open_secret(
    master_key: str, blob: bytes | memoryview | None, tenant_id: str, table: str, key: str
) -> dict[str, Any]:
    if not blob:
        return {}
    raw = bytes(blob)
    if raw[:1] != BOUND:
        raise ConfigError(
            f"the secret for {table} '{key}' was sealed before secrets were bound to their "
            "row; run `shoc migrate` to re-seal it"
        )
    try:
        body = _aead(master_key).decrypt(raw[1:13], raw[13:], _row(tenant_id, table, key))
    except InvalidTag as exc:
        raise ConfigError(
            f"the secret for {table} '{key}' could not be decrypted with this master key, "
            "or it was sealed for another row"
        ) from exc
    return json.loads(body.decode())


def _unbound(master_key: str, raw: bytes) -> dict[str, Any]:
    """A value sealed before secrets were bound to their row."""
    digest = hashlib.sha256(master_key.encode()).digest()
    return json.loads(Fernet(base64.urlsafe_b64encode(digest)).decrypt(raw).decode())


def reseal(conn: Any, old_key: str, new_key: str, unbound_only: bool = False) -> tuple[int, int]:
    """Seal every stored secret again under `new_key`. Returns (resealed, unreadable).

    With `unbound_only`, only values from before binding are touched. A value
    `old_key` cannot open was already unusable and is left as it is.
    """
    from shoc.db.pool import execute, fetch_all

    done = unreadable = 0
    for table, column in SEALED:
        rows = fetch_all(
            conn,
            f"SELECT tenant_id, {column} AS key, secret FROM shoc.{table} WHERE secret IS NOT NULL",
        )
        for row in rows:
            raw, where = bytes(row["secret"]), (row["tenant_id"], table, row["key"])
            if unbound_only and raw[:1] == BOUND:
                continue
            try:
                value = (
                    open_secret(old_key, raw, *where)
                    if raw[:1] == BOUND
                    else _unbound(old_key, raw)
                )
            except (ConfigError, InvalidToken):
                unreadable += 1
                continue
            execute(
                conn,
                f"UPDATE shoc.{table} SET secret = %s WHERE tenant_id = %s AND {column} = %s",
                (seal(new_key, value, *where), row["tenant_id"], row["key"]),
            )
            done += 1
    return done, unreadable
