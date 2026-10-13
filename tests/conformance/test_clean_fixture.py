"""The `clean` fixture: what one test leaves in the tenant's tables, the next does not see."""

from __future__ import annotations

import pytest

from shoc.db import jobs
from shoc.db.pool import fetch_all

pytestmark = pytest.mark.postgres


def test_clean_clears_the_tenants_schedules(conn, config, clean):
    """A configured pulled source left its sync schedule for the rest of the session."""
    schedule_id = f"{config.tenant_id}:sync:okta"
    jobs.upsert_schedule(conn, schedule_id, config.tenant_id, "source.sync", 900, {})
    clean()
    assert not fetch_all(
        conn, "SELECT 1 FROM shoc.schedules WHERE tenant_id = %s", (config.tenant_id,)
    )
