"""Configuration. Environment first, so one container image needs no config file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


def _content_dir() -> Path:
    env = os.environ.get("SHOC_CONTENT_DIR")
    if env:
        return Path(env)
    packaged = Path(__file__).parent / "_content"
    if packaged.is_dir():
        return packaged
    return Path(__file__).parent.parent / "content"


def scenarios_dir() -> Path:
    """Where the recorded attack scenarios live: in the wheel, or in a checkout."""
    packaged = Path(__file__).parent / "_scenarios"
    if packaged.is_dir():
        return packaged
    return Path(__file__).parent.parent / "evals" / "scenarios"


def rule_fixtures_dir() -> Path:
    """Each shipped rule's positive and negative records: in the wheel, or in a checkout."""
    packaged = Path(__file__).parent / "_rule_fixtures"
    if packaged.is_dir():
        return packaged
    return Path(__file__).parent.parent / "tests" / "fixtures" / "rules"


# Every SHOC_LLM_PROVIDER `llm.from_config` builds a client for, aliases included;
# empty is "none".
LLM_PROVIDERS = frozenset(
    {"none", "off", "anthropic", "openai", "openai-compatible", "compatible", "openai-responses"}
)

# The merge gates' scratch tenants are the tenant id with one of these added.
SCRATCH_SUFFIXES = ("_gate", "_hunt_gate")
# A tenant id names its schema, catalog, dataset or database as it is (D4),
# and so does a scratch tenant's; `t_` and the longest suffix fit Postgres' 63.
TENANT_ID = re.compile(r"[a-z0-9][a-z0-9_]{0,40}(?:_gate|_hunt_gate)?")


@dataclass
class Config:
    dsn: str = field(default_factory=lambda: os.environ.get("SHOC_DSN", ""))
    # The role that owns the schema, for `shoc migrate` and `shoc rotate-key`
    # (RFC 0024). SHOC_DSN is then a role that does not own it, so `serve` and
    # `worker` cannot disable the audit log's triggers. Unset, both are SHOC_DSN.
    migrate_dsn: str = field(default_factory=lambda: os.environ.get("SHOC_MIGRATE_DSN", ""))
    tenant_id: str = field(default_factory=lambda: os.environ.get("SHOC_TENANT", "default"))
    backend: str = field(default_factory=lambda: os.environ.get("SHOC_BACKEND", "postgres"))
    master_key: str = field(default_factory=lambda: os.environ.get("SHOC_MASTER_KEY", ""))
    content_dir: Path = field(default_factory=_content_dir)
    # How long events are kept. The nightly job drops whole partitions older than
    # this, so an instance loaded with historical data (a replayed public dataset,
    # a backfill) has to say so or lose it.
    retention_days: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_RETENTION_DAYS", "90"))
    )
    # SHOC_DRY_RUN, set either way, wins over the policy; unset (None), the
    # policy's `dry_run` decides (RSP-7). `Policy.dry_run_for` reads both.
    dry_run: bool | None = field(
        default_factory=lambda: (
            os.environ["SHOC_DRY_RUN"] not in ("0", "false", "no")
            if os.environ.get("SHOC_DRY_RUN")
            else None
        )
    )
    # The crew. "none" keeps shoc fully deterministic: rules, findings and cases
    # still work, and agent turns are skipped instead of guessed at.
    llm_provider: str = field(
        default_factory=lambda: os.environ.get("SHOC_LLM_PROVIDER", "none").lower()
    )
    llm_model: str = field(default_factory=lambda: os.environ.get("SHOC_LLM_MODEL", ""))
    llm_api_key: str = field(default_factory=lambda: os.environ.get("SHOC_LLM_API_KEY", ""))
    llm_base_url: str = field(default_factory=lambda: os.environ.get("SHOC_LLM_BASE_URL", ""))
    # Current models think before they answer and the thinking counts against
    # this; 2048 truncated the Investigator's JSON before it got to its claims.
    llm_max_tokens: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_LLM_MAX_TOKENS", "16000"))
    )
    # The model for roles whose work is narrow (`Role.model_hint == "cheap"`):
    # the Challenger, the Surveyor, the Manager, and the independent reads and
    # claim checks behind a verdict's confidence. Empty runs everything on one.
    llm_model_cheap: str = field(default_factory=lambda: os.environ.get("SHOC_LLM_MODEL_CHEAP", ""))
    # Independent reads of a case beside the Investigator's own (RFC 0020). The
    # confidence an action is gated on is how many of them agree, so 0 leaves
    # only the Investigator and its Challenger round to agree with each other.
    crew_samples: int = field(default_factory=lambda: int(os.environ.get("SHOC_CREW_SAMPLES", "2")))
    # Databricks SQL backend (STO-3), used only when backend == "databricks".
    databricks_host: str = field(default_factory=lambda: os.environ.get("SHOC_DATABRICKS_HOST", ""))
    databricks_http_path: str = field(
        default_factory=lambda: os.environ.get("SHOC_DATABRICKS_HTTP_PATH", "")
    )
    databricks_token: str = field(
        default_factory=lambda: os.environ.get("SHOC_DATABRICKS_TOKEN", "")
    )
    # Agents read through this token when it is set (SEC-1): a principal that
    # holds USE and SELECT, which `shoc migrate` grants to the principal named
    # here, per tenant catalog.
    databricks_readonly_token: str = field(
        default_factory=lambda: os.environ.get("SHOC_DATABRICKS_READONLY_TOKEN", "")
    )
    databricks_readonly_principal: str = field(
        default_factory=lambda: os.environ.get("SHOC_DATABRICKS_READONLY_PRINCIPAL", "")
    )
    # People sign in through a browser (SEC-3, RFC 0028). The console's origin as
    # people reach it: emailed links and the SSO redirect URI are built from it,
    # it is the only Origin a sign-in or cookie request is taken from, and its
    # scheme decides whether cookies are Secure. Unset, nobody signs in.
    public_url: str = field(
        default_factory=lambda: os.environ.get("SHOC_PUBLIC_URL", "").strip().rstrip("/")
    )
    # smtps://user:pass@host:465 or smtp://user:pass@host:587 (STARTTLS required).
    # Optional: without it, invitation and reset links are returned to the admin.
    smtp_url: str = field(default_factory=lambda: os.environ.get("SHOC_SMTP_URL", ""))
    mail_from: str = field(default_factory=lambda: os.environ.get("SHOC_MAIL_FROM", ""))
    # The proxies whose X-Forwarded-For the sign-in throttles believe, as
    # comma-separated CIDRs. Unset: loopback and Docker's default address pools.
    trusted_proxies: str = field(
        default_factory=lambda: (
            os.environ.get("SHOC_TRUSTED_PROXIES") or "127.0.0.0/8,::1/128,172.16.0.0/12"
        )
    )
    # Agents read through this DSN when it is set (SEC-1): a Postgres role with
    # SELECT and nothing else, so a prompt-injected agent cannot write.
    readonly_dsn: str = field(default_factory=lambda: os.environ.get("SHOC_READONLY_DSN", ""))
    # Public threat-intel feeds a new install pulls without being asked. The
    # hosts they reach are named in the quick start and logged the first time
    # they are pulled; `off` stops shoc contacting anything on its own.
    intel_feeds: str = field(default_factory=lambda: os.environ.get("SHOC_INTEL_FEEDS", "default"))
    # A URL an outside monitor (healthchecks.io, Cronitor, Uptime Kuma) expects a
    # GET on after every hourly `ops.check`, so a host, Postgres or both roles
    # being down is noticed by something that is not shoc. Unset, nothing is
    # sent; set, its host is logged when the worker starts (D57).
    heartbeat_url: str = field(
        default_factory=lambda: os.environ.get("SHOC_HEARTBEAT_URL", "").strip()
    )
    # The disk Postgres may fill, in GB. Postgres cannot see the filesystem, so
    # only the operator can say; set, its size against this is an alert at 80%
    # and a page at 90%. Unset (0), there is no check.
    disk_budget_gb: float = field(
        default_factory=lambda: float(os.environ.get("SHOC_DISK_BUDGET_GB") or 0)
    )
    # Limits that keep one bad query or one huge request from taking the rest
    # of the deployment with it.
    statement_timeout_seconds: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_STATEMENT_TIMEOUT", "120"))
    )
    max_request_bytes: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_MAX_REQUEST_BYTES", str(32 * 1024 * 1024)))
    )
    max_ingest_records: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_MAX_INGEST_RECORDS", "50000"))
    )
    # Snowflake backend (STO-4), used only when backend == "snowflake".
    snowflake_account: str = field(
        default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_ACCOUNT", "")
    )
    snowflake_user: str = field(default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_USER", ""))
    snowflake_password: str = field(
        default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_PASSWORD", "")
    )
    snowflake_private_key: str = field(
        default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_PRIVATE_KEY", "")
    )
    snowflake_warehouse: str = field(
        default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_WAREHOUSE", "")
    )
    snowflake_role: str = field(default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_ROLE", ""))
    # Agents connect with this role when it is set (SEC-1). The shoc user must
    # hold it; `shoc migrate` grants it USAGE and SELECT per tenant database.
    snowflake_readonly_role: str = field(
        default_factory=lambda: os.environ.get("SHOC_SNOWFLAKE_READONLY_ROLE", "")
    )

    # Amazon Redshift backend (STO-5), used only when backend == "redshift". The
    # DSN is a Postgres one (postgresql://user:pass@cluster:5439/db). Batches
    # are staged under SHOC_REDSHIFT_STAGE (s3://bucket/prefix) with this key,
    # and COPY reads them as the cluster's IAM role ("default" or an ARN).
    redshift_dsn: str = field(default_factory=lambda: os.environ.get("SHOC_REDSHIFT_DSN", ""))
    redshift_stage: str = field(default_factory=lambda: os.environ.get("SHOC_REDSHIFT_STAGE", ""))
    redshift_access_key: str = field(
        default_factory=lambda: os.environ.get("SHOC_REDSHIFT_AWS_ACCESS_KEY_ID", "")
    )
    redshift_secret_key: str = field(
        default_factory=lambda: os.environ.get("SHOC_REDSHIFT_AWS_SECRET_ACCESS_KEY", "")
    )
    redshift_region: str = field(default_factory=lambda: os.environ.get("SHOC_REDSHIFT_REGION", ""))
    redshift_iam_role: str = field(
        default_factory=lambda: os.environ.get("SHOC_REDSHIFT_IAM_ROLE") or "default"
    )
    # Agents read through this DSN when it is set (SEC-1); `shoc migrate` grants
    # its user USAGE and SELECT on each tenant schema.
    redshift_readonly_dsn: str = field(
        default_factory=lambda: os.environ.get("SHOC_REDSHIFT_READONLY_DSN", "")
    )
    # Google BigQuery backend (STO-6), used only when backend == "bigquery". The
    # credentials are a service-account key, as its JSON or the path of the file.
    bigquery_project: str = field(
        default_factory=lambda: os.environ.get("SHOC_BIGQUERY_PROJECT", "")
    )
    bigquery_credentials: str = field(
        default_factory=lambda: os.environ.get("SHOC_BIGQUERY_CREDENTIALS", "")
    )
    bigquery_location: str = field(
        default_factory=lambda: os.environ.get("SHOC_BIGQUERY_LOCATION") or "US"
    )
    # Agents read as this service account when it is set (SEC-1). It needs
    # BigQuery Job User on the project; `shoc migrate` grants it Data Viewer
    # on each tenant dataset.
    bigquery_readonly_credentials: str = field(
        default_factory=lambda: os.environ.get("SHOC_BIGQUERY_READONLY_CREDENTIALS", "")
    )
    # The most one BigQuery read (store.query) may bill, in bytes; past it the
    # job fails and bills nothing, and the error lands on the rule or read that
    # ran it. BigQuery checks the cap against its estimate, which for a read
    # bounded only by `time` is an upper bound over every retained partition of
    # the columns read, not the bytes the clustering prunes to. So it is sized
    # to the retained bytes of the columns a rule reads, and stays off (0) until
    # the first STO-6 run measures that (wh-6).
    bigquery_max_bytes_billed: int = field(
        default_factory=lambda: int(os.environ.get("SHOC_BIGQUERY_MAX_BYTES_BILLED") or 0)
    )

    @classmethod
    def load(cls) -> Config:
        return cls()

    def check_llm_provider(self) -> None:
        """Refuse a SHOC_LLM_PROVIDER no model client speaks, as a worker starts.

        Unchecked, a typo raised in the hourly `ops.check`, and only when a
        source was down, which is when its page was due (sre-10). The names are
        the ones `llm.from_config` takes; `llm.configure` checks a stored one.
        """
        from shoc.errors import ConfigError

        if self.llm_provider and self.llm_provider not in LLM_PROVIDERS:
            raise ConfigError(
                f"unknown SHOC_LLM_PROVIDER '{self.llm_provider}' "
                "(use anthropic, openai, openai-responses or none)"
            )

    def readonly_configured(self) -> bool:
        """Whether agents have a credential of their own on this backend (SEC-1)."""
        return bool(
            {
                "postgres": self.readonly_dsn,
                "databricks": self.databricks_readonly_token,
                "snowflake": self.snowflake_readonly_role,
                "redshift": self.redshift_readonly_dsn,
                "bigquery": self.bigquery_readonly_credentials,
            }.get(self.backend)
        )

    @property
    def cycle_seconds(self) -> int:
        """How often detection runs, and the shortest interval a source polls at
        (DET-3, D71, D153).

        The same on every backend, so moving to another one changes no
        schedule. The scheduler starts every cycle on the same clock boundary,
        so the polls and detection wake a warehouse once.
        """
        return int(os.environ.get("SHOC_CYCLE_SECONDS") or 900)

    def tenant_schema(self, tenant_id: str | None = None) -> str:
        """Postgres and Redshift tenancy is a schema per tenant (decision D4)."""
        return f"t_{self._safe(tenant_id)}"

    def tenant_catalog(self, tenant_id: str | None = None) -> str:
        """A catalog per tenant on Databricks, a dataset on BigQuery (decision D4)."""
        return f"shoc_{self._safe(tenant_id)}"

    def tenant_database(self, tenant_id: str | None = None) -> str:
        """Snowflake tenancy is a database per tenant (decision D4)."""
        return f"SHOC_{self._safe(tenant_id).upper()}"

    def _safe(self, tenant_id: str | None = None) -> str:
        """The tenant id as its namespace is named, unchanged (wh-13).

        Folding other characters to `_` gave 'acme-co' and 'acme_co' one
        namespace. A merge gate's scratch tenant is `<tenant>_gate` or
        `<tenant>_hunt_gate`, and each gate empties it, so the tenant this
        deployment runs and `shoc migrate` registers may not end that way.
        """
        from shoc.errors import ConfigError

        tid = tenant_id or self.tenant_id
        if not TENANT_ID.fullmatch(tid) or (
            tid == self.tenant_id and tid.endswith(SCRATCH_SUFFIXES)
        ):
            raise ConfigError(
                f"tenant id '{tid}' must be 1-41 lowercase letters, digits or '_', start with "
                f"a letter or digit, and not end in {' or '.join(SCRATCH_SUFFIXES)}"
            )
        return tid
