"""The crew's model changed at runtime, with SHOC_LLM_* as the fallback (RFC 0007)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from shoc.agents.llm import for_hint, from_config
from shoc.capabilities.registry import Caller, Context, call
from shoc.errors import ConfigError, Denied

pytestmark = pytest.mark.postgres


@pytest.fixture
def env_model(ctx, config, clean):
    ctx.config = replace(
        config,
        llm_provider="openai",
        llm_model="env-model",
        llm_model_cheap="",
        llm_base_url="https://api.openai.com/v1",
        llm_api_key="env-key",
    )
    return ctx


def test_stored_settings_win_field_by_field(env_model):
    call("llm.configure", env_model, {"model": "stored-model", "model_cheap": "stored-cheap"})
    client = from_config(env_model.config, env_model.db, env_model.tenant_id)
    assert client.model == "stored-model"
    assert getattr(client, "base_url", "").startswith("https://api.openai.com")  # never stored
    assert for_hint(client, "cheap").model == "stored-cheap"
    assert for_hint(client, "strong").model == "stored-model"


def test_the_key_is_never_returned(env_model):
    out = call("llm.configure", env_model, {"api_key": "sk-stored"}).data
    assert out.key == "set" and "api_key" in out.stored
    assert "sk-stored" not in repr(call("llm.show", env_model, {}).data)


def test_clear_falls_back_to_the_environment(env_model):
    call("llm.configure", env_model, {"model": "stored-model"})
    out = call("llm.configure", env_model, {"clear": True}).data
    assert out.model == "env-model" and out.stored == []


def test_a_base_url_outside_the_allowlist_is_refused(env_model):
    with pytest.raises(ConfigError):
        call("llm.configure", env_model, {"base_url": "https://collector.example.net/v1"})


def test_an_agent_cannot_change_its_own_model(env_model):
    agent = Context(
        tenant_id=env_model.tenant_id,
        caller=Caller(kind="agent", id="agent:test"),
        config=env_model.config,
    )
    with pytest.raises(Denied):
        call("llm.configure", agent, {"model": "anything"})


def test_the_llm_row_is_not_a_source(env_model):
    call("llm.configure", env_model, {"model": "stored-model"})
    sources = call("source.list", env_model, {}).data
    assert "llm" not in repr(sources)
