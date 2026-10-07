"""GuardDuty severity bands, connection direction and DNS query name (ING-3)."""

from __future__ import annotations

import pytest

from shoc.ingest import ocsf


def _row(**record):
    return ocsf.load_mapping("aws_guardduty").map_record({"id": "gd", **record}, "t1")


@pytest.mark.parametrize(
    ("severity", "expected"), [(2, 2), (3.9, 2), (4, 3), (6.9, 3), (7, 4), (8.9, 4), (9, 5)]
)
def test_severity_follows_the_documented_bands(severity, expected):
    assert _row(severity=severity)["severity_id"] == expected


def test_dns_finding_puts_the_looked_up_name_in_the_query_column():
    row = _row(
        severity=8,
        type="Trojan:EC2/DNSDataExfiltration",
        service={
            "action": {
                "actionType": "DNS_REQUEST",
                "dnsRequestAction": {"domain": "exfil.example.com"},
            }
        },
        resource={"resourceType": "Instance", "instanceDetails": {"instanceId": "i-0abc"}},
    )
    assert row["dns_query_hostname"] == "exfil.example.com"
    assert row["src_endpoint_domain"] is None
    assert row["device_uid"] == "i-0abc"


@pytest.mark.parametrize(
    ("direction", "src", "dst"),
    [
        ("OUTBOUND", ("10.0.0.23", 39677), ("198.51.100.7", 80)),
        ("INBOUND", ("198.51.100.7", 80), ("10.0.0.23", 39677)),
    ],
)
def test_connection_direction_decides_which_end_is_the_source(direction, src, dst):
    action = {
        "connectionDirection": direction,
        "localIpDetails": {"ipAddressV4": "10.0.0.23"},
        "localPortDetails": {"port": 39677},
        "remoteIpDetails": {"ipAddressV4": "198.51.100.7"},
        "remotePortDetails": {"port": 80},
    }
    row = _row(severity=8, service={"action": {"networkConnectionAction": action}})
    assert (row["src_endpoint_ip"], row["src_endpoint_port"]) == src
    assert (row["dst_endpoint_ip"], row["dst_endpoint_port"]) == dst
