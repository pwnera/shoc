"""A tenant id names its namespace as it is, and never a merge gate's scratch (wh-13, D4)."""

from __future__ import annotations

import json

import pytest

from shoc.api.auth import authenticate
from shoc.config import Config
from shoc.errors import ConfigError, Denied


def _config(tenant: str) -> Config:
    cfg = Config()
    cfg.tenant_id = tenant
    return cfg


def test_a_tenant_id_names_its_namespace_unchanged():
    cfg = _config("acme_co")
    assert cfg.tenant_schema() == "t_acme_co"
    assert cfg.tenant_catalog() == "shoc_acme_co"
    assert cfg.tenant_database() == "SHOC_ACME_CO"


@pytest.mark.parametrize("tenant", ["acme-co", "ACME_co", "_acme", "acme.co", "a" * 42, "x;drop"])
def test_an_id_that_folding_would_merge_with_another_is_refused(tenant):
    """'acme-co' and 'acme_co' once shared one event schema."""
    with pytest.raises(ConfigError, match="tenant id"):
        _config("default").tenant_schema(tenant)


@pytest.mark.parametrize("suffix", ["_gate", "_hunt_gate"])
def test_the_running_tenant_may_not_be_another_tenants_scratch(suffix):
    with pytest.raises(ConfigError, match="tenant id"):
        _config(f"acme{suffix}").tenant_schema()


def test_a_gate_scratch_tenant_still_opens():
    cfg = _config("a" * 41)
    assert cfg.tenant_schema("a" * 41 + "_hunt_gate") == "t_" + "a" * 41 + "_hunt_gate"
    assert len(cfg.tenant_schema("a" * 41 + "_hunt_gate")) <= 63, "Postgres' identifier limit"
    assert cfg.tenant_catalog("acme_gate") == "shoc_acme_gate"


@pytest.mark.parametrize("tenant", ["default_gate", "acme_hunt_gate", "acme-co"])
def test_a_request_may_not_name_a_scratch_or_invalid_tenant(monkeypatch, tenant):
    """The next gate run empties a scratch tenant; a bad id would fail later (wh-13)."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    local = {"host": "127.0.0.1:8080"}
    with pytest.raises(Denied, match="not a tenant"):
        authenticate(local | {"x-shoc-tenant": tenant}, "default")
    entry = {"kind": "human", "id": "ann", "scopes": ["*"], "tenant": tenant}
    monkeypatch.setenv("SHOC_TOKENS", json.dumps({"sk-ann": entry}))
    with pytest.raises(Denied, match="not a tenant"):
        authenticate(local | {"authorization": "Bearer sk-ann"}, "default")


def test_a_request_names_a_valid_tenant(monkeypatch):
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    headers = {"host": "127.0.0.1:8080", "x-shoc-tenant": "acme_co"}
    assert authenticate(headers, "default")[1] == "acme_co"
