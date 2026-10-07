"""EventStore conformance (STO-1): `shoc.store.conformance` on every backend reached."""

from __future__ import annotations

import pytest

from shoc.store.conformance import CHECKS

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.__name__)
def test_the_store_conforms(check, store, clean):
    check(store)


def test_a_missing_tenant_schema_says_what_to_do_about_it(config, clean):
    """The 3am version of this error used to be 'relation ocsf_events does not exist'."""
    from shoc.errors import StoreError
    from shoc.store.postgres import PostgresStore

    stranger = PostgresStore(config.dsn, "nobody", "t_does_not_exist")
    try:
        with pytest.raises(StoreError, match="grant-readonly"):
            stranger.query(
                "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id",
                {"tenant_id": "nobody"},
            )
    finally:
        stranger.close()
