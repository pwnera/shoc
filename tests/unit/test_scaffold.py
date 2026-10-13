from __future__ import annotations

import json

import pytest

from shoc import scaffold
from shoc.errors import ValidationError


def test_new_connector_writes_module_mapping_and_fixture(tmp_path):
    written = scaffold.new_connector("cloudflare", tmp_path)
    names = {p.name for p in written.paths}
    assert names == {"cloudflare.py", "cloudflare.yaml", "cloudflare.json"}
    module = (tmp_path / "shoc/ingest/connectors/cloudflare.py").read_text()
    assert "class CloudflareConnector" in module and 'source = "cloudflare"' in module


def test_a_scaffolded_connector_holds_since_while_paging(tmp_path, monkeypatch):
    import importlib.util

    import httpx

    scaffold.new_connector("acme_saas", tmp_path)
    path = tmp_path / "shoc/ingest/connectors/acme_saas.py"
    spec = importlib.util.spec_from_file_location("acme_saas", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    replies = [
        {"items": [{"timestamp": "2026-09-20T10:05:00Z"}], "next_page": "p2"},
        {"items": [{"timestamp": "2026-09-20T10:00:00Z"}]},
    ]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=replies.pop(0))

    real_client = httpx.Client
    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    since = "2026-09-20T09:00:00+00:00"
    reread = "2026-09-20T08:45:00+00:00"  # the overlap behind the cursor (D164)
    first = module.CONNECTOR.fetch({}, {"api_token": "t"}, {"since": since}, 10)
    assert seen[0].url.params["since"] == reread
    assert first.more and first.cursor["start"] == reread and first.since == since
    second = module.CONNECTOR.fetch({}, {"api_token": "t"}, first.cursor, 10)
    assert seen[1].url.params["since"] == reread and seen[1].url.params["page"] == "p2"
    assert second.cursor == {"since": "2026-09-20T10:05:00Z"} and second.more is False
    assert second.since == since


def test_a_scaffolded_connector_keeps_its_cursor_on_a_quiet_poll(tmp_path, monkeypatch):
    """A poll that finds only the overlap leaves the cursor where it was (D164)."""
    import importlib.util

    import httpx

    scaffold.new_connector("acme_saas", tmp_path)
    path = tmp_path / "shoc/ingest/connectors/acme_saas.py"
    spec = importlib.util.spec_from_file_location("acme_saas", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    real_client = httpx.Client
    mock = httpx.MockTransport(lambda request: httpx.Response(200, json={"items": []}))
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    since = "2026-09-20T09:00:00+00:00"
    quiet = module.CONNECTOR.fetch({}, {"api_token": "t"}, {"since": since}, 10)
    assert quiet.cursor == {"since": since} and quiet.more is False


def test_a_scaffolded_mapping_is_valid_and_maps_its_own_fixture(tmp_path, monkeypatch):
    scaffold.new_mapping("acme_saas", tmp_path)
    from shoc.ingest import ocsf

    monkeypatch.setattr(ocsf, "mappings_dir", lambda: tmp_path / "shoc/ingest/mappings")
    ocsf._CACHE.clear()
    mapping = ocsf.load_mapping("acme_saas")
    assert mapping.validate() == []
    records = json.loads((tmp_path / "tests/fixtures/mappings/acme_saas.json").read_text())
    row = mapping.map_record(records[0], "t1")
    assert row["actor_user_name"] == "jane@example.com"
    assert row["src_endpoint_ip"] == "198.51.100.5"
    ocsf._CACHE.clear()


def test_a_scaffolded_rule_loads_and_compiles(tmp_path):
    scaffold.new_rule("okta_new_thing", "okta", "system_log", tmp_path)
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import compile_rule

    rule = ruleset.load_file(tmp_path / "content/rules/okta_new_thing.yaml")
    assert rule.logsource["product"] == "okta"
    assert compile_rule(rule).where
    assert rule.created, "test_rule_metadata_is_complete asks for the Sigma date"
    for kind in ("positive", "negative"):
        assert (tmp_path / f"tests/fixtures/rules/okta_new_thing/{kind}.json").exists()


def test_a_scaffolded_rule_names_the_playbooks_that_could_take_it(tmp_path, monkeypatch):
    """Every rule belongs to exactly one playbook, and CI checks it."""
    from tests.support import ROOT

    books = scaffold._playbooks_for("okta", ROOT)
    assert books, "the shipped okta rules are answered by a playbook"
    monkeypatch.setattr(scaffold, "_playbooks_for", lambda product, root: books)
    written = scaffold.new_rule("okta_new_thing", "okta", "system_log", tmp_path)
    text = (tmp_path / "content/rules/okta_new_thing.yaml").read_text()
    assert f"one of {', '.join(books)}" in text
    assert "test_rules_content.py" in written.steps and "test_rules.py" in written.steps


def test_a_scaffolded_connector_names_every_test_that_judges_it(tmp_path):
    """A connector that passed the one test named failed CI on the rest (D56)."""
    steps = scaffold.new_connector("acme_saas", tmp_path).steps
    for needed in (
        "FIELDS",
        "WHERE",
        "PERMISSION_HINTS",
        "RESPONDS",
        "shoc/actions/acme_saas.py",
        "tests/unit/test_mappings_all.py",
        "tests/unit/test_credential_routing.py",
        "tests/unit/test_actions.py",
        "tests/conformance/test_integrator.py",
    ):
        assert needed in steps
    assert "CONNECTOR_PROVIDERS" in steps and "lookup" in steps
    mapping = scaffold.new_mapping("acme_other", tmp_path).steps
    for needed in (
        "FIELDS",
        "PUSH_WHERE",
        "PERMISSION_HINTS",
        "RESPONDS",
        "tests/unit/test_mappings_all.py",
        "tests/unit/test_credential_routing.py",
        "tests/unit/test_actions.py",
        "tests/conformance/test_integrator.py",
    ):
        assert needed in mapping


def test_a_bad_name_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not a usable name"):
        scaffold.new_connector("Cloud Flare!", tmp_path)


def test_existing_files_are_not_clobbered(tmp_path):
    scaffold.new_mapping("acme", tmp_path)
    with pytest.raises(ValidationError, match="already exists"):
        scaffold.new_mapping("acme", tmp_path)
    scaffold.new_mapping("acme", tmp_path, force=True)
