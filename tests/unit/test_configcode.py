"""What `shoc.yaml` may say, checked before anything is read from the database (API-4)."""

from __future__ import annotations

import pytest

from shoc.configcode import EXAMPLE, Desired
from shoc.errors import ValidationError


@pytest.mark.parametrize(
    ("config", "named"),
    [
        ({"version": 1, "dry_run": False}, "dry_run"),  # response dry run is the policy's
        ({"version": 1, "source": [{"source": "okta"}]}, "source"),
        ({"sources": [{"source": "okta", "retention": 180}]}, "retention"),
        ({"intel_feeds": [{"feed": "abuse_ch_urlhaus", "url": "x"}]}, "url"),
        ({"slack": {"channel": "C0123", "approver": {"U1": "sam"}}}, "approver"),
    ],
)
def test_a_key_shoc_does_not_read_is_refused(config, named):
    """Ignored keys planned and applied as if the operator had not written them."""
    with pytest.raises(ValidationError, match=rf"unknown key\(s\) {named};.*allowed: "):
        Desired.from_dict(config)


def test_slack_readers_left_out_are_not_emptied():
    import yaml

    desired = Desired.from_dict(yaml.safe_load(EXAMPLE))
    assert desired.slack and desired.slack.readers and desired.slack.team_id
    left_out = Desired.from_dict({"slack": {"channel": "C0123"}}).slack
    emptied = Desired.from_dict({"slack": {"channel": "C0123", "readers": {}}}).slack
    assert left_out and left_out.readers is None
    assert emptied and emptied.readers == {}
