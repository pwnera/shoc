"""The Compose file, the Helm chart and the image builds keep their safety settings."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest
import yaml

from shoc.config import Config

COMPOSE = yaml.safe_load(Path("deploy/docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
RUNTIME = ("shoc", "worker", "worker-urgent")
PASS_THROUGH = re.compile(r"^\$\{(\w+):-([^${}]*)\}$")


def _defaults() -> dict[str, str]:
    """x-shoc-env's plain `${VAR:-default}` entries."""
    found = {}
    for key, value in COMPOSE["x-shoc-env"].items():
        m = PASS_THROUGH.match(str(value))
        if m and m.group(1) == key:
            found[key] = m.group(2)
    return found


def _seen() -> dict:
    from shoc.agents import ops
    from shoc.capabilities import llm

    cfg = Config()
    return {
        **dataclasses.asdict(cfg),
        "cycle_seconds": cfg.cycle_seconds,
        "price": ops.price_for("unpriced-model"),
        "hosts": llm.allowed_hosts(),
    }


# -- po-9: Compose passes documented variables through ------------------------
def test_compose_passes_the_documented_variables_through():
    """SHOC_INTEL_FEEDS=off in .env never reached a container, so shoc kept polling abuse.ch."""
    env = COMPOSE["x-shoc-env"]
    for name in (
        "SHOC_INTEL_FEEDS",
        "SHOC_LLM_MODEL_CHEAP",
        "SHOC_LLM_MAX_TOKENS",
        "SHOC_LLM_BASE_URL_ALLOWLIST",
        "SHOC_LLM_PRICE_IN",
        "SHOC_CYCLE_SECONDS",
        "SHOC_CREW_SAMPLES",
        "SHOC_REDSHIFT_DSN",
        "SHOC_BIGQUERY_CREDENTIALS",
        "SHOC_BIGQUERY_MAX_BYTES_BILLED",
        "SHOC_HEARTBEAT_URL",
        "SHOC_DISK_BUDGET_GB",
    ):
        assert f"${{{name}:-" in str(env.get(name)), name


def test_a_compose_default_is_shocs_own(monkeypatch):
    """`${SHOC_LLM_MAX_TOKENS:-}` would hand int() an empty string and stop every process."""
    defaults = _defaults()
    defaults.pop("SHOC_DRY_RUN")  # Compose starts in dry run on purpose; unset defers to policy
    defaults.pop("SHOC_BIND")  # not in Config; unset, serve checks its --host (0.0.0.0 here)
    assert len(defaults) > 20
    for name in defaults:
        monkeypatch.delenv(name, raising=False)
    unset = _seen()
    for name, value in defaults.items():
        monkeypatch.setenv(name, value)
    assert _seen() == unset


def test_serve_and_worker_never_see_the_owners_dsn():
    """secrets.env is handed over whole; the empty SHOC_MIGRATE_DSN wins over it (RFC 0024)."""
    for name in RUNTIME:
        service = SERVICES[name]
        assert service["environment"]["SHOC_MIGRATE_DSN"] == "", name
        assert service["env_file"] == [{"path": "secrets.env", "required": False}], name
    assert "shoc:${SHOC_DB_PASSWORD}" in SERVICES["migrate"]["environment"]["SHOC_MIGRATE_DSN"]
    assert "env_file" not in SERVICES["migrate"]


def test_secrets_env_stays_out_of_git():
    """secrets.env sits in the checkout, so `git add -A` committed live provider secrets."""
    assert "secrets.env" in Path(".gitignore").read_text().splitlines()
    example = Path("deploy/secrets.env.example").read_text().splitlines()
    assert all(not line or line.startswith("#") for line in example)
    assert any("SHOC_SECRET_" in line for line in example)


# -- sre-21: Compose hardening -------------------------------------------------
def test_compose_ships_no_database_password():
    """Anyone who read .env.example knew the superuser's and the owner's passwords."""
    text = Path("deploy/docker-compose.yml").read_text()
    for name in (
        "SHOC_DB_PASSWORD",
        "SHOC_APP_DB_PASSWORD",
        "SHOC_AGENT_DB_PASSWORD",
        "POSTGRES_SUPERUSER_PASSWORD",
    ):
        assert f"${{{name}:-" not in text, name
        assert f"${{{name}:?" in text, name


def test_every_service_rotates_its_logs():
    """json-file never rotates by default, and a full disk stops Postgres."""
    console = yaml.safe_load(Path("console/deploy/docker-compose.yml").read_text())["services"]
    for name, service in {**SERVICES, **console}.items():
        assert service["logging"]["options"]["max-size"], name


@pytest.mark.parametrize("name", RUNTIME)
def test_serve_and_workers_run_hardened(name):
    service = SERVICES[name]
    assert service["read_only"] is True
    # In memory and counted against mem_limit, so it is capped below it.
    assert service["tmpfs"] == ["/tmp:size=512m"]
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["mem_limit"]


# -- sre-19, sre-20: the Helm chart --------------------------------------------
def _hook_weight(template: str) -> int:
    text = Path(f"deploy/helm/shoc/templates/{template}").read_text()
    assert '"helm.sh/hook": pre-install,pre-upgrade' in text, template
    weight = re.search(r'"helm.sh/hook-weight": "(-?\d+)"', text)
    assert weight, template
    return int(weight.group(1))


def test_the_charts_secret_exists_before_the_migrate_hook_reads_it():
    """An ordinary Secret is created after pre-install hooks, so migrate never started."""
    assert _hook_weight("secret.yaml") < _hook_weight("migrate-job.yaml")


def test_chart_pods_carry_no_api_token_and_a_bounded_tmp():
    values = yaml.safe_load(Path("deploy/helm/shoc/values.yaml").read_text())
    assert values["podSecurityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert values["tmpSizeLimit"]
    for template in ("serve.yaml", "worker.yaml", "migrate-job.yaml", "serviceaccount.yaml"):
        text = Path(f"deploy/helm/shoc/templates/{template}").read_text()
        assert "automountServiceAccountToken: false" in text, template
    for template in ("serve.yaml", "worker.yaml", "migrate-job.yaml"):
        text = Path(f"deploy/helm/shoc/templates/{template}").read_text()
        assert "emptyDir: {}" not in text, template
        assert re.search(r"sizeLimit: \{\{ \$?\.Values\.tmpSizeLimit \}\}", text), template
    worker = Path("deploy/helm/shoc/templates/worker.yaml").read_text()
    assert "kind: PodDisruptionBudget" in worker
    assert "$.Values.nodeSelector" in worker


def test_the_chart_passes_the_heartbeat_the_disk_budget_and_snowflake():
    """A Helm install had no way to set the heartbeat, the disk budget or Snowflake's sign-in."""
    values = yaml.safe_load(Path("deploy/helm/shoc/values.yaml").read_text())
    secret = values["secrets"]["values"]
    snowflake = set(re.findall(r"SHOC_SNOWFLAKE_\w+", Path("shoc/config.py").read_text()))
    assert len(snowflake) == 7
    for name in {"SHOC_HEARTBEAT_URL", *snowflake}:
        assert name in secret, name
    assert "diskBudgetGb" in values
    for template in ("serve.yaml", "worker.yaml"):
        text = Path(f"deploy/helm/shoc/templates/{template}").read_text()
        assert "name: SHOC_DISK_BUDGET_GB" in text, template


def test_the_chart_passes_every_variable_compose_passes():
    """A Helm install could not set the LLM prices, so spend on an unpriced model counted $0."""
    values = yaml.safe_load(Path("deploy/helm/shoc/values.yaml").read_text())
    chart = {*values["env"], *values["secrets"]["values"]}
    for template in ("_helpers.tpl", "serve.yaml", "worker.yaml"):
        text = Path(f"deploy/helm/shoc/templates/{template}").read_text()
        chart |= set(re.findall(r"name: (SHOC_\w+)", text))
    # SHOC_BIND is the address Compose publishes on; the chart's serve listens on 0.0.0.0.
    assert set(COMPOSE["x-shoc-env"]) - chart == {"SHOC_BIND"}
    assert not set(values["env"]) & set(values["secrets"]["values"])
    assert (
        "range $name, $value := .Values.env"
        in Path("deploy/helm/shoc/templates/_helpers.tpl").read_text()
    )


def test_the_console_checks_run_when_the_contract_changes():
    """The labels test reads contract/v1.json; a new kernel action alone never ran it."""
    on = yaml.safe_load(Path(".github/workflows/console.yml").read_text())[True]
    for trigger in ("pull_request", "push"):
        assert "contract/v1.json" in on[trigger]["paths"], trigger


# -- sre-17, sre-18: image builds ----------------------------------------------
@pytest.mark.parametrize("path", ["deploy/Dockerfile", "console/Dockerfile"])
def test_base_images_are_pinned_by_digest(path):
    froms = re.findall(r"^FROM (\S+)", Path(path).read_text(), re.MULTILINE)
    assert froms
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), image


def test_the_console_build_requires_its_lockfile():
    """`npm ci || npm install` resolved versions nobody reviewed when the lockfile drifted."""
    dockerfile = Path("console/Dockerfile").read_text()
    assert "npm install" not in dockerfile
    assert "package-lock.json*" not in dockerfile
    assert "nginx-unprivileged" in dockerfile
    assert "npm install" not in Path(".github/workflows/console.yml").read_text()
