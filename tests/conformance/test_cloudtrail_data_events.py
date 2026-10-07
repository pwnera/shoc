"""S3 data events reach shoc only through the trail's bucket (ING-1)."""

from __future__ import annotations

import gzip
import json
from datetime import timedelta

import pytest

from shoc.agents import integrator
from shoc.db.pool import execute, fetch_one
from shoc.detect import rules as ruleset
from shoc.detect.engine import run_rule
from shoc.ingest import batch, ocsf
from shoc.ingest.connectors import get
from tests.unit.test_connectors import AWS, s3_list, transport

pytestmark = pytest.mark.postgres

DATA_RULES = ["aws_s3_mass_object_read", "aws_s3_sse_c_encryption"]


def test_the_bucket_mode_carries_the_mass_object_read_rule(monkeypatch, store, config, clean, now):
    prefix = "AWSLogs/123456789012/CloudTrail/us-east-1/"
    when = (now - timedelta(minutes=10)).replace(second=0, microsecond=0)
    key = f"{prefix}{when:%Y/%m/%d}/123456789012_CloudTrail_us-east-1_{when:%Y%m%dT%H%M}Z_a.json.gz"
    reads = [
        {
            "eventVersion": "1.09",
            "eventID": f"data-{n}",
            "eventCategory": "Data",
            "eventTime": (when + timedelta(seconds=n)).isoformat(),
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.10",
            "recipientAccountId": "123456789012",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "deploy-ci",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            },
            "resources": [{"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::payroll/{n}.csv"}],
        }
        for n in range(60)
    ]
    transport(
        monkeypatch,
        [
            s3_list(prefixes=("AWSLogs/123456789012/",)),
            s3_list(prefixes=(prefix,)),
            s3_list((key,)),
            {"content": gzip.compress(json.dumps({"Records": reads}).encode())},
            s3_list(),
        ],
    )
    page = get("aws_cloudtrail").fetch({"bucket": "trail-bucket"}, AWS, {}, 1000)
    mapping = ocsf.load_mapping("aws_cloudtrail")
    batch.load(store, [mapping.map_record(r, config.tenant_id) for r in page.records])
    rule = next(r for r in ruleset.load() if r.id == "aws_s3_mass_object_read")
    found = run_rule(store, config.tenant_id, rule, now - timedelta(hours=1), now)
    assert [f.entity_key for f in found] == ["AKIAIOSFODNN7EXAMPLE"]


def test_onboarding_says_lookup_events_cannot_carry_data_event_rules(ctx, config, clean):
    def configure(settings: dict) -> None:
        execute(
            ctx.db, "DELETE FROM shoc.connector_config WHERE tenant_id = %s", (config.tenant_id,)
        )
        execute(
            ctx.db,
            """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings)
               VALUES (%s, 'aws_cloudtrail', true, %s)""",
            (config.tenant_id, json.dumps(settings)),
        )

    configure({})
    integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    row = fetch_one(
        ctx.db,
        "SELECT supports, cannot_support FROM shoc.source_onboarding "
        "WHERE tenant_id = %s AND source = 'aws_cloudtrail'",
        (config.tenant_id,),
    )
    assert row
    said = {c.split(":", 1)[0]: c for c in row["cannot_support"]}
    for rule_id in DATA_RULES:
        assert "set `bucket`" in said[rule_id] and rule_id not in row["supports"]
    # A rule that management events feed keeps its own reason.
    assert "set `bucket`" not in said["aws_root_account_activity"]

    configure({"bucket": "trail-bucket"})
    supports, cannot = integrator.unfed(ctx.db, config.tenant_id, "aws_cloudtrail", DATA_RULES, [])
    assert supports == DATA_RULES and cannot == []
