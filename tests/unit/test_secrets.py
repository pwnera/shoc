"""Sealed secrets are bound to the row they are stored in (SEC-1). No database."""

from __future__ import annotations

import pytest

from shoc.db.secrets import _unbound, open_secret, seal
from shoc.errors import ConfigError

KEY = "test-master-key"
OKTA = ("acme", "connector_config", "okta")


def test_a_sealed_value_opens_only_in_its_own_row():
    blob = seal(KEY, {"token": "s3cret"}, *OKTA)
    assert open_secret(KEY, blob, *OKTA) == {"token": "s3cret"}
    for elsewhere in (
        ("other", "connector_config", "okta"),  # another tenant
        ("acme", "connector_config", "github"),  # another source
        ("acme", "action_credentials", "okta"),  # another table
    ):
        with pytest.raises(ConfigError, match="another row"):
            open_secret(KEY, blob, *elsewhere)
    with pytest.raises(ConfigError, match="master key"):
        open_secret("another key", blob, *OKTA)


def test_a_value_sealed_before_binding_is_refused_until_migrate_reseals_it():
    import base64
    import hashlib
    import json

    from cryptography.fernet import Fernet

    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(KEY.encode()).digest()))
    old = fernet.encrypt(json.dumps({"token": "s3cret"}).encode())
    with pytest.raises(ConfigError, match="shoc migrate"):
        open_secret(KEY, old, *OKTA)
    assert _unbound(KEY, old) == {"token": "s3cret"}, "migrate can still read it to re-seal"
