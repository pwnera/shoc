"""A sign-in's session id is `session:` wherever an entity is named (hunt-23).

The detection engine types Okta's and Entra's actor.session.uid as `session:`;
the graph and the Surveyor name the same value the same way, so a walk from a
finding's session entity finds its node.
"""

from __future__ import annotations

import pytest

from shoc.agents import graph, surveyor
from shoc.db.pool import fetch_all

pytestmark = pytest.mark.postgres


def test_an_okta_session_is_a_session_in_the_graph_and_the_survey(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "okta_mfa_fatigue", tenant_id=config.tenant_id, store=store)
    graph.refresh(ctx.db, store, config.tenant_id)
    sessions = {
        str(r["label"])
        for r in fetch_all(
            ctx.db,
            "SELECT label FROM shoc.graph_nodes WHERE tenant_id = %s AND kind = 'session'",
            (config.tenant_id,),
        )
    }
    assert sessions, "Okta's session ids are sessions"
    keys = fetch_all(
        ctx.db,
        "SELECT label FROM shoc.graph_nodes WHERE tenant_id = %s AND kind = 'key'",
        (config.tenant_id,),
    )
    assert not sessions & {str(r["label"]) for r in keys}, "and not keys as well"
    walk = graph.neighbours(ctx.db, config.tenant_id, f"session:{min(sessions)}", hops=1)
    assert any(n["kind"] == "user" for n in walk.nodes), "the walk reaches who signed in"
    posture = surveyor.survey(ctx.db, store, config.tenant_id, config=config, keep=False)
    assert posture.counts.get("session", 0) == len(sessions)
    assert "key" not in posture.counts
