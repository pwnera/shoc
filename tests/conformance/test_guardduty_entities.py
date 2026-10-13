"""A GuardDuty finding about an outbound call names the address it called (DET-3, RSP-2)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.engine import run_rule
from shoc.ingest import batch
from tests.support import fixture_rows, fixture_source

pytestmark = pytest.mark.postgres

RULE = next(r for r in ruleset.load() if r.id == "aws_guardduty_finding")

OUTBOUND = {
    "schemaVersion": "2.0",
    "accountId": "123456789012",
    "region": "eu-west-1",
    "partition": "aws",
    "id": "gd-outbound-c2",
    "type": "Backdoor:EC2/C&CActivity.B",
    "severity": 8,
    "title": "Backdoor:EC2/C&CActivity.B",
    "description": "An instance is talking to a known command and control server.",
    "resource": {
        "resourceType": "Instance",
        "instanceDetails": {"instanceId": "i-0abc123def4567890", "instanceType": "t3.large"},
    },
    "service": {
        "serviceName": "guardduty",
        "detectorId": "12abc34d567e8fa901bc2d34e56789f0",
        "archived": False,
        "count": 1,
        "action": {
            "actionType": "NETWORK_CONNECTION",
            "networkConnectionAction": {
                "connectionDirection": "OUTBOUND",
                "protocol": "TCP",
                "blocked": False,
                "localIpDetails": {"ipAddressV4": "192.0.2.10"},
                "localPortDetails": {"port": 49152},
                "remoteIpDetails": {"ipAddressV4": "203.0.113.50"},
                "remotePortDetails": {"port": 443},
            },
        },
    },
}


def test_an_outbound_finding_names_its_remote_peer(store, config, clean, now):
    """`entities_of` read the remote peer from columns no rule selected, so the
    C2 address never joined the case it was about."""
    batch.load(store, fixture_rows([OUTBOUND], fixture_source(RULE), config.tenant_id, now))
    (finding,) = run_rule(
        store, config.tenant_id, RULE, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert "ip:203.0.113.50" in finding.entities, finding.entities
    assert "ip:192.0.2.10" in finding.entities, "the instance's own address is its source"
    assert "device:i-0abc123def4567890" in finding.entities
