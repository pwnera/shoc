"""First-seen rules learn per account, from each account's own first event (D79)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shoc.detect import engine
from shoc.detect import rules as ruleset

NOW = datetime(2026, 10, 12, 2, 0, tzinfo=UTC)
RULE = ruleset.from_dict(
    {
        "id": "TEST-FIRST-LOGIN",
        "title": "First console login from an address",
        "logsource": {"product": "aws"},
        "detection": {"s": {"api.operation": "ConsoleLogin"}, "condition": "s"},
        "baseline": {"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "30d"},
    }
)


def test_an_account_that_joined_the_trail_last_week_learns_from_its_own_start():
    history = [
        {
            "products": ["AWS CloudTrail"],
            "account_uids": ["111111111111", "222222222222"],
            "account_starts": {"222222222222": (NOW - timedelta(days=7)).isoformat()},
            "start": NOW - timedelta(days=90),
        }
    ]
    learning = engine.accounts_learning(RULE, history)
    assert learning["111111111111"] == NOW - timedelta(days=60), "named before: the trail's start"
    assert learning["222222222222"] == NOW + timedelta(days=23)
