"""What each pull connector asks its API for, and where it leaves the cursor (ING-1).

Every connector is exercised against a mock transport: the assertions are on the
request it built and the cursor it returned, because those are the two things a
connector owns. Mapping, batching and health accounting belong to `base.run`.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors
from shoc.ingest.connectors import awssig, base, gitlab, okta
from shoc.store.base import LoadStats
from tests.support import FIXTURES


def transport(monkeypatch, replies: list[dict[str, Any]]) -> list[httpx.Request]:
    """Answer each request with the next reply, and keep what was sent.

    A reply is `{"json": …}` or `{"content": b"…"}` plus optional `headers` and `status`.
    """
    seen: list[httpx.Request] = []
    real_client = httpx.Client
    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        reply: dict[str, Any] = queue.pop(0) if queue else {}
        body = (
            {"content": reply["content"]} if "content" in reply else {"json": reply.get("json", {})}
        )
        return httpx.Response(
            int(reply.get("status", 200)), headers=dict(reply.get("headers") or {}), **body
        )

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    return seen


def query(request: httpx.Request) -> dict[str, str]:
    return dict(request.url.params)


SINCE = "2026-09-20T09:00:00+00:00"


# -- the registry ----------------------------------------------------------


def test_every_builtin_connector_loads_and_names_itself():
    for source in connectors.available():
        assert connectors.get(source).source == source


def test_a_source_is_pushed_only_in_the_form_its_vendor_sends():
    """GitHub's signed webhook; every other vendor is polled (ING-2)."""
    assert connectors.push_sources() == []
    for source in ("defender", "crowdstrike", "sentinelone", "gitlab", "wazuh"):
        assert source in connectors.available() and not connectors.accepts_push(source)
    assert connectors.accepts_push("github")


# -- Microsoft Defender ----------------------------------------------------


def test_defender_asks_graph_for_alerts_after_the_cursor(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.defender.access_token", lambda secret: "tok")
    seen = transport(
        monkeypatch,
        [{"json": {"value": [{"id": "a1", "createdDateTime": "2026-09-20T10:00:00Z"}]}}],
    )
    result = connectors.get("defender").fetch({}, {}, {"since": "2026-09-20T09:00:00+00:00"}, 100)
    assert "security/alerts_v2" in str(seen[0].url)
    assert query(seen[0])["$filter"] == "createdDateTime gt 2026-09-20T09:00:00+00:00"
    assert query(seen[0])["$orderby"] == "createdDateTime asc"
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert result.records[0]["id"] == "a1"
    assert result.cursor == {"since": "2026-09-20T10:00:00Z"}
    assert result.more is False


def test_defender_follows_the_graph_next_link(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.defender.access_token", lambda secret: "tok")
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "value": [{"id": "a1", "createdDateTime": "2026-09-20T10:00:00Z"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?$skip=1",
                }
            },
            {"json": {"value": [{"id": "a2", "createdDateTime": "2026-09-20T10:01:00Z"}]}},
        ],
    )
    connector = connectors.get("defender")
    first = connector.fetch({}, {}, {"since": SINCE}, 100)
    assert first.more is True and "next_link" in first.cursor
    assert first.cursor["since"] == SINCE, "the window holds while the link is followed"
    second = connector.fetch({}, {}, first.cursor, 100)
    assert str(seen[1].url).endswith("$skip=1")
    assert second.records[0]["id"] == "a2"
    assert second.cursor == {"since": "2026-09-20T10:01:00Z"}


# -- CrowdStrike Falcon ----------------------------------------------------


def falcon_secret() -> dict[str, str]:
    return {"client_id": "cid", "client_secret": "csec"}


def test_crowdstrike_queries_ids_then_asks_for_those_entities(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {"json": {"access_token": "tok", "expires_in": 1800}},
            {"json": {"resources": ["ldt:1:ind:1"]}},
            {
                "json": {
                    "resources": [
                        {"composite_id": "ldt:1:ind:1", "created_timestamp": "2026-09-20T10:00:00Z"}
                    ]
                }
            },
        ],
    )
    result = connectors.get("crowdstrike").fetch(
        {"cloud": "eu-1"}, falcon_secret(), {"since": "2026-09-20T09:00:00+00:00"}, 100
    )
    token_req, list_req, entity_req = seen
    assert str(token_req.url) == "https://api.eu-1.crowdstrike.com/oauth2/token"
    assert "api.eu-1.crowdstrike.com/alerts/queries/alerts/v2" in str(list_req.url)
    assert query(list_req)["filter"] == "created_timestamp:>'2026-09-20T09:00:00+00:00'"
    assert query(list_req)["sort"] == "created_timestamp|asc"
    assert json.loads(entity_req.content) == {"composite_ids": ["ldt:1:ind:1"]}
    assert result.records[0]["composite_id"] == "ldt:1:ind:1"
    assert result.cursor == {"since": "2026-09-20T10:00:00Z"}


def test_crowdstrike_walks_a_full_page_by_offset_without_moving_the_window(monkeypatch):
    transport(
        monkeypatch,
        [
            {"json": {"access_token": "tok", "expires_in": 1800}},
            {"json": {"resources": ["a", "b"]}},
            {
                "json": {
                    "resources": [
                        {"composite_id": "a", "created_timestamp": "2026-09-20T10:00:00Z"}
                    ]
                }
            },
        ],
    )
    result = connectors.get("crowdstrike").fetch(
        {"cloud": "us-1"}, falcon_secret(), {"since": "2026-09-20T09:00:00+00:00"}, 2
    )
    assert result.more is True
    assert result.cursor == {"since": "2026-09-20T09:00:00+00:00", "offset": 2}


def test_crowdstrike_stops_cleanly_when_nothing_matched(monkeypatch):
    transport(
        monkeypatch,
        [
            {"json": {"access_token": "tok", "expires_in": 1800}},
            {"json": {"resources": []}},
        ],
    )
    result = connectors.get("crowdstrike").fetch(
        {}, falcon_secret(), {"since": "2026-09-20T09:00:00+00:00"}, 100
    )
    assert result.records == [] and result.more is False


def test_crowdstrike_refuses_an_unknown_cloud(monkeypatch):
    with pytest.raises(ConfigError, match="unknown cloud"):
        connectors.get("crowdstrike").fetch({"cloud": "mars-1"}, falcon_secret(), {}, 10)


# -- SentinelOne -----------------------------------------------------------


def test_sentinelone_reads_threats_and_keeps_the_page_cursor(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "data": [{"id": "t1", "threatInfo": {"createdAt": "2026-09-20T10:00:00Z"}}],
                    "pagination": {"nextCursor": "abc"},
                }
            }
        ],
    )
    result = connectors.get("sentinelone").fetch(
        {"console_url": "https://acme.sentinelone.net/"},
        {"api_token": "tok"},
        {"threats": {"since": "2026-09-20T09:00:00+00:00"}},
        100,
    )
    assert str(seen[0].url).startswith("https://acme.sentinelone.net/web/api/v2.1/threats")
    assert query(seen[0])["createdAt__gt"] == "2026-09-20T09:00:00+00:00"
    assert seen[0].headers["authorization"] == "ApiToken tok"
    held = result.cursor["threats"]
    assert held["page_cursor"] == "abc" and result.more is True
    assert held["since"] == "2026-09-20T09:00:00+00:00", "held while paging"


def test_sentinelone_needs_a_console_and_a_token():
    with pytest.raises(ConfigError, match="console_url"):
        connectors.get("sentinelone").fetch({}, {}, {}, 10)


# -- Azure Activity Log ----------------------------------------------------


def test_azure_activity_filters_on_the_event_timestamp(monkeypatch):
    monkeypatch.setattr(
        "shoc.ingest.connectors.azure_activity.access_token", lambda secret, scope: "tok"
    )
    seen = transport(
        monkeypatch,
        [{"json": {"value": [{"eventDataId": "e1", "eventTimestamp": "2026-09-20T10:00:00Z"}]}}],
    )
    result = connectors.get("azure_activity").fetch(
        {"subscription_id": "sub-1"}, {}, {"since": "2026-09-20T09:00:00+00:00"}, 100
    )
    assert "/subscriptions/sub-1/providers/Microsoft.Insights/eventtypes/management/values" in str(
        seen[0].url
    )
    assert query(seen[0])["$filter"].startswith(
        "eventTimestamp ge '2026-09-20T09:00:00+00:00' and eventTimestamp le '"
    ), "the window stops Microsoft's 20 minutes before now (D154)"
    assert result.cursor == {"since": "2026-09-20T10:00:00Z"}


def test_azure_activity_carries_the_newest_event_across_a_newest_first_walk(monkeypatch):
    monkeypatch.setattr(
        "shoc.ingest.connectors.azure_activity.access_token", lambda secret, scope: "tok"
    )
    link = "https://management.azure.com/subscriptions/sub-1/next?$skiptoken=s2"
    seen = transport(
        monkeypatch,
        [
            {"json": {"value": [{"eventTimestamp": "2026-09-20T10:05:00Z"}], "nextLink": link}},
            {"json": {"value": [{"eventTimestamp": "2026-09-20T10:00:00Z"}]}},
        ],
    )
    connector = connectors.get("azure_activity")
    settings = {"subscription_id": "sub-1"}
    first = connector.fetch(settings, {}, {"since": SINCE}, 100)
    assert first.cursor["since"] == SINCE and first.more is True
    second = connector.fetch(settings, {}, first.cursor, 100)
    assert seen[1].url.params["$skiptoken"] == "s2" and "$filter" not in seen[1].url.params
    assert second.cursor == {"since": "2026-09-20T10:05:00Z"} and second.more is False


def test_azure_activity_needs_a_subscription():
    with pytest.raises(ConfigError, match="subscription_id"):
        connectors.get("azure_activity").fetch({}, {}, {}, 10)


# -- GCP Cloud Audit -------------------------------------------------------


def test_gcp_audit_asks_cloud_logging_for_admin_activity(monkeypatch):
    monkeypatch.setattr(
        "shoc.ingest.connectors.gcp_audit.googleauth.access_token",
        lambda secret, scope: "tok",
    )
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "entries": [{"insertId": "g1", "timestamp": "2026-09-20T10:00:00Z"}],
                    "nextPageToken": "p2",
                }
            }
        ],
    )
    result = connectors.get("gcp_audit").fetch(
        {"project_id": "example-prod"}, {}, {"since": "2026-09-20T09:00:00+00:00"}, 100
    )
    body = json.loads(seen[0].content)
    assert body["resourceNames"] == ["projects/example-prod"]
    assert "cloudaudit.googleapis.com%2Factivity" in body["filter"]
    assert 'timestamp > "2026-09-20T09:00:00+00:00"' in body["filter"]
    assert body["orderBy"] == "timestamp asc"
    assert result.cursor["page_token"] == "p2" and result.more is True


def test_gcp_audit_holds_the_filter_while_following_a_page_token(monkeypatch):
    monkeypatch.setattr(
        "shoc.ingest.connectors.gcp_audit.googleauth.access_token",
        lambda secret, scope: "tok",
    )
    seen = transport(
        monkeypatch,
        [
            {"json": {"entries": [{"timestamp": "2026-09-20T10:00:00Z"}], "nextPageToken": "p2"}},
            {"json": {"entries": [{"timestamp": "2026-09-20T10:05:00Z"}]}},
        ],
    )
    connector = connectors.get("gcp_audit")
    settings = {"project_id": "example-prod"}
    first = connector.fetch(settings, {}, {"since": SINCE}, 1)
    assert first.cursor["since"] == SINCE
    second = connector.fetch(settings, {}, first.cursor, 1)
    one, two = (json.loads(r.content) for r in seen)
    assert two["filter"] == one["filter"] and two["pageToken"] == "p2"
    assert second.cursor == {"since": "2026-09-20T10:05:00Z"} and second.more is False


def test_gcp_audit_needs_a_project():
    with pytest.raises(ConfigError, match="project_id"):
        connectors.get("gcp_audit").fetch({}, {}, {}, 10)


# -- GitLab ----------------------------------------------------------------


def test_gitlab_reads_group_audit_events(monkeypatch):
    seen = transport(
        monkeypatch,
        [{"json": [{"id": 1, "created_at": "2026-09-20T10:00:00Z"}]}],
    )
    result = connectors.get("gitlab").fetch(
        {"group": "acme"}, {"token": "tok"}, {"since": "2026-09-20T09:00:00+00:00"}, 50
    )
    assert str(seen[0].url).startswith("https://gitlab.com/api/v4/groups/acme/audit_events")
    assert query(seen[0])["created_after"] == "2026-09-20T09:00:00+00:00"
    assert seen[0].headers["private-token"] == "tok"
    assert result.cursor == {"since": "2026-09-20T10:00:00Z"}


def test_gitlab_holds_the_window_still_while_paging(monkeypatch):
    transport(
        monkeypatch,
        [
            {
                "json": [{"id": 1, "created_at": "2026-09-20T10:00:00Z"}],
                "headers": {"x-next-page": "2"},
            }
        ],
    )
    result = connectors.get("gitlab").fetch(
        {}, {"token": "tok"}, {"since": "2026-09-20T09:00:00+00:00"}, 50
    )
    assert result.cursor == {"since": "2026-09-20T09:00:00+00:00", "page": 2}
    assert result.more is True


def test_gitlab_falls_back_to_the_instance_endpoint_and_needs_a_token(monkeypatch):
    seen = transport(monkeypatch, [{"json": []}])
    connectors.get("gitlab").fetch({"base_url": "https://git.acme.test"}, {"token": "t"}, {}, 10)
    assert str(seen[0].url).startswith("https://git.acme.test/api/v4/audit_events")
    with pytest.raises(ConfigError, match="token"):
        connectors.get("gitlab").fetch({}, {}, {}, 10)


# -- where the next poll starts ---------------------------------------------


def test_a_complete_walk_starts_the_next_poll_at_the_newest_event_read(monkeypatch):
    """No overlap: the next poll asks only for what came after (D154)."""

    class Quiet:
        source = "okta"

        def fetch(self, settings, secret, cursor, limit):
            return base.FetchResult(cursor={"since": cursor.get("since") or "2026-09-20T10:00:00Z"})

    monkeypatch.setattr(connectors, "get", lambda source: Quiet())
    first = base.run(None, None, "t1", "okta", {}, {}, cursor={}, persist=False)  # type: ignore[arg-type]
    assert first.error is None and first.cursor == {"since": "2026-09-20T10:00:00Z"}
    again = base.run(None, None, "t1", "okta", {}, {}, cursor=first.cursor, persist=False)  # type: ignore[arg-type]
    assert again.cursor == first.cursor, "a quiet source stays where it is"


def test_an_event_its_record_does_not_place_carries_its_source_account(monkeypatch):
    # An Okta System Log record never names the org, and a response must know
    # which org to sign the user out of (RFC 0025).
    record = json.loads((FIXTURES / "mappings" / "okta.json").read_text())[0]

    class One:
        source = "okta"
        account = okta.CONNECTOR.account

        def fetch(self, settings, secret, cursor, limit):
            return base.FetchResult(records=[record], cursor={"after": "x"})

    loaded: list[dict[str, Any]] = []
    monkeypatch.setattr(connectors, "get", lambda source: One())
    monkeypatch.setattr(
        base.batchwriter, "load", lambda store, rows: loaded.extend(rows) or LoadStats(len(rows))
    )
    settings = {"org_url": "https://acme.okta.com/"}
    base.run(None, None, "t1", "okta:acme", settings, {}, cursor={}, persist=False)  # type: ignore[arg-type]
    assert loaded and {r["cloud_account_uid"] for r in loaded} == {"acme.okta.com"}
    assert gitlab.CONNECTOR.account({"group": "acme"}) == "acme"
    assert gitlab.CONNECTOR.account({}) == "gitlab.com"


# -- several streams of one source -----------------------------------------


class Pages:
    """A connector whose streams answer from a script; an exception is raised."""

    source = "google_workspace"

    def __init__(self, pages: dict[str, list[Any]]) -> None:
        self.pages, self.asked = pages, []

    def fetch(self, settings, secret, cursor, limit):
        name = settings["application"]
        self.asked.append((name, dict(cursor)))
        page = self.pages[name].pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def test_streams_read_every_stream_by_default_each_with_its_own_cursor():
    inner = Pages(
        {
            "admin": [
                base.FetchResult([{"id": 1}], {"since": SINCE, "page_token": "p2"}, more=True),
                base.FetchResult([{"id": 2}], {"since": "2026-09-20T10:00:00+00:00"}),
            ],
            "login": [base.FetchResult([{"id": 3}], {"since": "2026-09-20T10:30:00+00:00"})],
        }
    )
    streams = base.Streams(inner, "application", ("admin", "login"))
    first = streams.fetch({}, {}, {}, 1000)
    assert [r["id"] for r in first.records] == [1, 3] and first.more is True
    assert first.cursor["streams"] == {
        "admin": {"since": SINCE, "page_token": "p2", "more": True},
        "login": {"since": "2026-09-20T10:30:00+00:00", "more": False},
    }, "each stream starts its next poll at its own newest event"

    second = streams.fetch({}, {}, first.cursor, 1000)
    assert [name for name, _ in inner.asked] == ["admin", "login", "admin"], "only the one paging"
    assert inner.asked[2][1]["page_token"] == "p2"
    assert second.more is False
    assert second.cursor["streams"]["admin"] == {
        "since": "2026-09-20T10:00:00+00:00",
        "more": False,
    }


def test_a_failing_stream_does_not_hold_the_others_back():
    refused = httpx.HTTPStatusError(
        "403", request=httpx.Request("GET", "https://x"), response=httpx.Response(403)
    )
    inner = Pages({"admin": [refused], "login": [base.FetchResult([{"id": 1}], {"since": SINCE})]})
    page = base.Streams(inner, "application", ("admin", "login")).fetch({}, {}, {}, 10)
    assert [r["id"] for r in page.records] == [1]
    assert page.error.startswith("admin: google_workspace rejected the credential (403)")
    assert page.cursor["streams"]["admin"] == {"more": False}, "not pending, so it cannot starve"

    alone = base.Streams(Pages({"admin": [ConfigError("no admin")]}), "application", ("admin",))
    with pytest.raises(ConfigError):
        alone.fetch({}, {}, {}, 10)

    one = Pages({"login": [base.FetchResult([], {"since": SINCE})]})
    named = base.Streams(one, "application", ("admin", "login")).fetch(
        {"application": "login"}, {}, {}, 10
    )
    assert named.cursor == {"since": SINCE}, "one named stream keeps a plain cursor"


# -- AWS Signature Version 4 -----------------------------------------------


def test_sigv4_matches_the_aws_documentation_vectors():
    # "Examples of how to derive a signing key for Signature Version 4".
    key = awssig.signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam"
    )
    assert key.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    # get-vanilla, from the Signature Version 4 test suite.
    signed = awssig.headers(
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        session_token=None,
        region="us-east-1",
        service="service",
        host="example.amazonaws.com",
        method="GET",
        now=datetime(2015, 8, 30, 12, 36, tzinfo=UTC),
    )
    assert signed["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


# -- AWS CloudTrail --------------------------------------------------------

AWS = {"access_key_id": "AKIDEXAMPLE", "secret_access_key": "not-a-secret"}


def trail(event_id: str, when: str) -> dict[str, Any]:
    event = json.dumps({"eventID": event_id, "eventTime": when})
    return {"EventId": event_id, "CloudTrailEvent": event}


def test_cloudtrail_holds_start_time_while_following_next_token(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {"json": {"Events": [trail("e2", "2026-09-20T10:05:00Z")], "NextToken": "n2"}},
            {"json": {"Events": [trail("e1", "2026-09-20T10:00:00Z")]}},
        ],
    )
    connector = connectors.get("aws_cloudtrail")
    first = connector.fetch({"region": "eu-west-1"}, AWS, {"since": SINCE}, 1000)
    assert str(seen[0].url) == "https://cloudtrail.eu-west-1.amazonaws.com/"
    assert seen[0].headers["x-amz-target"].endswith("LookupEvents")
    # AWS joins a repeated header before signing, so a second copy breaks the signature.
    assert seen[0].headers.get_list("content-type") == ["application/x-amz-json-1.1"]
    assert seen[0].headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert first.records[0]["eventID"] == "e2" and first.more is True
    assert first.cursor["since"] == SINCE, "the window holds while NextToken is followed"

    second = connector.fetch({"region": "eu-west-1"}, AWS, first.cursor, 1000)
    one, two = (json.loads(r.content) for r in seen)
    assert one.keys() == {"StartTime", "EndTime", "MaxResults"} and one["MaxResults"] == 50
    assert one["StartTime"] == datetime.fromisoformat(SINCE).timestamp()
    behind = datetime.now(UTC) - datetime.fromtimestamp(one["EndTime"], tz=UTC)
    assert timedelta(minutes=5) <= behind < timedelta(minutes=6), "AWS's delivery lag (D154)"
    assert two == {**one, "NextToken": "n2"}, "the window holds while NextToken is followed"
    # LookupEvents answers newest first: the newest event came on page one.
    assert second.cursor == {"since": "2026-09-20T10:05:00Z"} and second.more is False


def test_cloudtrail_reads_every_enabled_region_unless_told_otherwise(monkeypatch):
    regions = "".join(
        f"<item><regionName>{r}</regionName><optInStatus>opted-in</optInStatus></item>"
        for r in ("us-east-1", "eu-west-1")
    )
    seen = transport(
        monkeypatch,
        [
            {
                "content": f"<DescribeRegionsResponse><regionInfo>{regions}</regionInfo></DescribeRegionsResponse>".encode()
            },
            {"json": {"Events": [trail("e1", "2026-09-20T10:00:00Z")]}},
            {"json": {"Events": []}},
        ],
    )
    page = connectors.get("aws_cloudtrail").fetch({"region": "all"}, AWS, {}, 1000)
    assert query(seen[0]) == {"Action": "DescribeRegions", "Version": "2016-11-15"}
    assert seen[0].headers["authorization"].split("/")[3] == "ec2"
    assert [r.url.host for r in seen[1:]] == [
        "cloudtrail.eu-west-1.amazonaws.com",
        "cloudtrail.us-east-1.amazonaws.com",
    ]
    assert set(page.cursor["streams"]) == {"eu-west-1", "us-east-1"}
    assert [r["eventID"] for r in page.records] == ["e1"]


def test_cloudtrail_needs_both_keys():
    with pytest.raises(ConfigError, match="access_key_id"):
        connectors.get("aws_cloudtrail").fetch({}, {"access_key_id": "a"}, {}, 10)


def s3_list(keys: tuple[str, ...] = (), prefixes: tuple[str, ...] = ()) -> dict[str, Any]:
    body = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in keys) + "".join(
        f"<CommonPrefixes><Prefix>{p}</Prefix></CommonPrefixes>" for p in prefixes
    )
    xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
    return {"content": f'<ListBucketResult xmlns="{xmlns}">{body}</ListBucketResult>'.encode()}


def s3_file(*ids: str) -> dict[str, Any]:
    records = {"Records": [{"eventID": i} for i in ids]}
    return {"content": gzip.compress(json.dumps(records).encode())}


def test_cloudtrail_reads_the_trail_bucket_per_account_and_region(monkeypatch):
    account = "AWSLogs/o-exampleorg/111122223333/"
    east, west = f"{account}CloudTrail/us-east-1/", f"{account}CloudTrail/eu-west-3/"
    t = (datetime.now(UTC) - timedelta(hours=1)).replace(second=0, microsecond=0)

    def key(when: datetime, suffix: str) -> str:
        name = f"111122223333_CloudTrail_us-east-1_{when:%Y%m%dT%H%M}Z_{suffix}.json.gz"
        return f"{east}{when:%Y/%m/%d}/{name}"

    later = t + timedelta(minutes=5)
    k1, k2, k3 = key(t, "b"), key(later, "c"), key(later, "a")
    discover = [
        s3_list(prefixes=("AWSLogs/o-exampleorg/",)),
        s3_list(prefixes=(account,)),
        s3_list(prefixes=(east, west)),
    ]
    seen = transport(
        monkeypatch,
        [
            {"status": 301, "headers": {"x-amz-bucket-region": "eu-west-3"}},
            *discover,
            s3_list((k1, k2)),
            s3_file("e1"),
            s3_file("e2"),
            s3_list(),
            # k3 was delivered in k2's minute but sorts before it, after we listed.
            *discover,
            s3_list((k1, k3, k2)),
            s3_file("e3"),
            s3_list(),
        ],
    )
    connector = connectors.get("aws_cloudtrail")
    settings = {"bucket": "trail-bucket"}
    first = connector.fetch(settings, AWS, {}, 1000)
    assert seen[1].url.host == "trail-bucket.s3.eu-west-3.amazonaws.com", "followed to its region"
    assert "x-amz-content-sha256" in seen[1].headers
    assert query(seen[4])["prefix"] == east and query(seen[4])["start-after"] < k1
    assert [r["eventID"] for r in first.records] == ["e1", "e2"] and first.more is False
    assert set(first.cursor["prefixes"]) == {east, west}
    assert first.cursor["prefixes"][east]["seen"] == [k1, k2]

    second = connector.fetch(settings, AWS, first.cursor, 1000)
    assert seen[8].url.host == "trail-bucket.s3.eu-west-3.amazonaws.com", "the region is kept"
    assert [r["eventID"] for r in second.records] == ["e3"], "the overlap finds k3, not k1 or k2"
    assert sum(r.url.path.endswith(".json.gz") for r in seen[8:]) == 1


# -- AWS GuardDuty ---------------------------------------------------------


def ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def test_guardduty_pages_each_detector_with_its_own_window(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {"json": {"findingIds": ["f1"], "NextToken": "t2"}},
            {"json": {"findings": [{"id": "f1", "updatedAt": "2026-09-20T10:00:00Z"}]}},
            {"json": {"findingIds": []}},
            {"json": {"findingIds": ["f2"]}},
            {"json": {"findings": [{"id": "f2", "updatedAt": "2026-09-20T10:05:00Z"}]}},
            {"json": {"findingIds": []}},
        ],
    )
    connector = connectors.get("aws_guardduty")
    settings = {"detector_ids": ["d1", "d2"]}
    earlier = "2026-09-20T08:00:00+00:00"
    cursor = {"since": SINCE, "detectors": {"d2": {"since": earlier}}}
    first = connector.fetch(settings, AWS, cursor, 1000)
    listed_d1, got, listed_d2 = (json.loads(r.content) for r in seen[:3])
    assert seen[0].headers.get_list("content-type") == ["application/json"]
    assert listed_d1["FindingCriteria"]["Criterion"]["updatedAt"]["GreaterThan"] == ms(SINCE)
    assert listed_d2["FindingCriteria"]["Criterion"]["updatedAt"]["GreaterThan"] == ms(earlier)
    assert listed_d1["MaxResults"] == 50 and got == {"findingIds": ["f1"]}
    assert first.records[0]["detectorId"] == "d1"
    assert first.more is True, "a NextToken means there is more to read"
    assert first.cursor["detectors"]["d1"] == {
        "since": SINCE,
        "newest": "2026-09-20T10:00:00Z",
        "next_token": "t2",
    }

    second = connector.fetch(settings, AWS, first.cursor, 1000)
    again_d1 = json.loads(seen[3].content)
    assert again_d1["NextToken"] == "t2"
    assert again_d1["FindingCriteria"] == listed_d1["FindingCriteria"], "held while paging"
    assert second.more is False
    assert second.cursor["detectors"] == {
        "d1": {"since": "2026-09-20T10:05:00Z"},
        "d2": {"since": earlier},
    }


# -- Okta ------------------------------------------------------------------

OKTA_NEXT = '<https://acme.okta.com/api/v1/logs?after=abc&limit=1000>; rel="next"'


def test_okta_starts_at_the_cursor_then_follows_the_next_link(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": [{"uuid": "o1", "published": "2026-09-20T10:00:00.000Z"}],
                "headers": {"link": OKTA_NEXT},
            },
            {"json": [], "headers": {"link": OKTA_NEXT}},
        ],
    )
    connector = connectors.get("okta")
    settings, secret = {"org_url": "https://acme.okta.com/"}, {"api_token": "tok"}
    first = connector.fetch(settings, secret, {"since": SINCE}, 1000)
    assert str(seen[0].url).startswith("https://acme.okta.com/api/v1/logs")
    assert query(seen[0]) == {"limit": "1000", "since": SINCE}
    assert seen[0].headers["authorization"] == "SSWS tok"
    link = "https://acme.okta.com/api/v1/logs?after=abc&limit=1000"
    assert first.more and first.cursor == {
        "since": SINCE,
        "newest": "2026-09-20T10:00:00.000Z",
        "next": link,
    }

    second = connector.fetch(settings, secret, first.cursor, 1000)
    assert str(seen[1].url) == link, "the next link is followed as Okta handed it back"
    assert second.cursor["next"] == link and second.more is False
    assert second.cursor["since"] == SINCE, "polling goes on from the next link"


def test_okta_keeps_a_cursor_saved_as_after_and_ignores_a_foreign_link(monkeypatch):
    foreign = '<https://evil.example.net/api/v1/logs?after=x>; rel="next"'
    seen = transport(monkeypatch, [{"json": [], "headers": {"link": foreign}}])
    settings, secret = {"org_url": "https://acme.okta.com"}, {"api_token": "tok"}
    page = connectors.get("okta").fetch(settings, secret, {"since": SINCE, "after": "abc"}, 10)
    assert str(seen[0].url) == "https://acme.okta.com/api/v1/logs?after=abc&limit=10"
    assert "next" not in page.cursor


def test_okta_snapshot_lists_users_with_their_last_sign_in_and_zone_ranges(monkeypatch):
    users_next = '<https://acme.okta.com/api/v1/users?after=u1&limit=200>; rel="next"'
    seen = transport(
        monkeypatch,
        [
            {
                "json": [
                    {
                        "id": "u1",
                        "status": "ACTIVE",
                        "lastLogin": "2026-01-02T00:00:00.000Z",
                        "profile": {"login": "alice@example.com"},
                    }
                ],
                "headers": {"link": users_next},
            },
            {
                "json": [
                    {
                        "id": "u2",
                        "status": "SUSPENDED",
                        "lastLogin": None,
                        "profile": {"login": "bob@example.com"},
                    }
                ]
            },
            {
                "json": [
                    {
                        "name": "Office",
                        "type": "IP",
                        "usage": "POLICY",
                        "status": "ACTIVE",
                        "gateways": [{"type": "CIDR", "value": "198.51.100.0/24"}],
                    }
                ]
            },
        ],
    )
    settings, secret = {"org_url": "https://acme.okta.com"}, {"api_token": "tok"}
    assets = connectors.get("okta").snapshot(settings, secret)  # type: ignore[attr-defined]
    assert [a.entity for a in assets] == [
        "user:alice@example.com",
        "user:bob@example.com",
        "network:198.51.100.0/24",
    ]
    assert assets[0].last_active == "2026-01-02T00:00:00.000Z"
    assert assets[2].attributes["zone"] == "Office"
    assert str(seen[1].url) == "https://acme.okta.com/api/v1/users?after=u1&limit=200"
    assert str(seen[2].url) == "https://acme.okta.com/api/v1/zones"


def test_okta_needs_an_org_and_a_token():
    with pytest.raises(ConfigError, match="org_url"):
        connectors.get("okta").fetch({}, {"api_token": "t"}, {}, 10)


# -- GitHub ----------------------------------------------------------------

GH_NEXT = '<https://api.github.com/orgs/acme/audit-log?after=xyz&before=>; rel="next"'


def test_github_holds_the_phrase_while_following_after(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": [{"@timestamp": ms("2026-09-20T10:00:00+00:00")}],
                "headers": {"link": GH_NEXT},
            },
            {"json": [{"@timestamp": ms("2026-09-20T10:05:00+00:00")}]},
        ],
    )
    connector = connectors.get("github")
    settings, secret = {"org": "acme"}, {"token": "tok"}
    first = connector.fetch(settings, secret, {"since": SINCE}, 1000)
    assert str(seen[0].url).startswith("https://api.github.com/orgs/acme/audit-log")
    assert query(seen[0])["phrase"] == "created:>=2026-09-20T09:00:00"
    assert query(seen[0])["order"] == "asc" and query(seen[0])["per_page"] == "100"
    assert first.more is True and first.cursor["since"] == SINCE

    second = connector.fetch(settings, secret, first.cursor, 1000)
    assert query(seen[1])["phrase"] == query(seen[0])["phrase"]
    assert query(seen[1])["after"] == "xyz"
    assert second.cursor == {"since": "2026-09-20T10:05:00+00:00"} and second.more is False


def test_github_says_the_audit_log_needs_enterprise_cloud(monkeypatch):
    transport(monkeypatch, [{"status": 404, "json": {"message": "Not Found"}}])
    with pytest.raises(ConfigError, match="Enterprise Cloud"):
        connectors.get("github").fetch({"org": "acme"}, {"token": "tok"}, {}, 10)


# -- Google Workspace ------------------------------------------------------


def test_google_workspace_holds_start_time_while_following_a_page_token(monkeypatch):
    monkeypatch.setattr(
        "shoc.ingest.connectors.google_workspace.googleauth.access_token",
        lambda secret, scope, subject=None: "tok",
    )
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "items": [{"id": {"time": "2026-09-20T10:05:00.000Z"}}],
                    "nextPageToken": "p2",
                }
            },
            {"json": {"items": [{"id": {"time": "2026-09-20T10:00:00.000Z"}}]}},
        ],
    )
    connector = connectors.get("google_workspace")
    settings = {"admin_email": "admin@example.com", "application": "login"}
    first = connector.fetch(settings, {}, {"since": SINCE}, 1000)
    assert str(seen[0].url).startswith(
        "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
    )
    assert query(seen[0])["startTime"] == SINCE
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert first.records[0]["_application"] == "login" and first.more is True

    second = connector.fetch(settings, {}, first.cursor, 1000)
    assert query(seen[1])["startTime"] == SINCE and query(seen[1])["pageToken"] == "p2"
    assert query(seen[1])["endTime"] == query(seen[0])["endTime"], "the window holds too"
    # Reports answer newest first: the newest event came on page one.
    assert second.cursor == {"since": "2026-09-20T10:05:00.000Z"} and second.more is False


def test_a_poll_reads_only_what_has_settled_since_the_newest_event(monkeypatch):
    """Google delivers token events up to a few hours late, so a read stops that
    far behind now, and one that has nothing settled to read asks nothing (D154)."""
    monkeypatch.setattr(
        "shoc.ingest.connectors.google_workspace.googleauth.access_token",
        lambda secret, scope, subject=None: "tok",
    )
    seen = transport(monkeypatch, [{"json": {"items": []}}])
    connector = connectors.get("google_workspace")
    settings = {"admin_email": "admin@example.com", "application": "token"}
    recent = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    page = connector.fetch(settings, {}, {"since": recent}, 1000)
    assert not seen and page.cursor == {"since": recent} and not page.records

    page = connector.fetch(settings, {}, {"since": SINCE}, 1000)
    asked = query(seen[0])
    assert asked["startTime"] == SINCE, "the first event after the last one read, no overlap"
    behind = datetime.now(UTC) - datetime.fromisoformat(asked["endTime"])
    assert timedelta(hours=3) <= behind < timedelta(hours=3, minutes=1)
    assert page.cursor == {"since": SINCE}, "nothing read: the next poll starts at the same event"


def test_google_workspace_needs_an_admin_to_impersonate():
    with pytest.raises(ConfigError, match="admin_email"):
        connectors.get("google_workspace").fetch({}, {}, {}, 10)


# -- Microsoft Entra ID ----------------------------------------------------


def test_entra_filters_each_stream_then_replays_the_next_link(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.entra.access_token", lambda secret: "tok")
    link = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=s2"
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "value": [{"id": "d1", "activityDateTime": "2026-09-20T10:05:00Z"}],
                    "@odata.nextLink": link,
                }
            },
            {"json": {"value": [{"id": "d2", "activityDateTime": "2026-09-20T10:10:00Z"}]}},
            {"json": {"value": []}},
        ],
    )
    connector = connectors.get("entra")
    settings = {"stream": "directoryAudits"}
    first = connector.fetch(settings, {}, {"since": SINCE}, 5000)
    assert seen[0].url.path == "/v1.0/auditLogs/directoryAudits"
    assert query(seen[0]) == {
        "$filter": f"activityDateTime gt {SINCE}",
        "$orderby": "activityDateTime asc",
        "$top": "1000",
    }
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert first.records[0]["_stream"] == "directoryAudits" and first.more is True
    assert first.cursor == {"since": SINCE, "newest": "2026-09-20T10:05:00Z", "next_link": link}

    second = connector.fetch(settings, {}, first.cursor, 5000)
    assert query(seen[1]) == {"$skiptoken": "s2"}, "the link is replayed as issued"
    assert second.cursor == {"since": "2026-09-20T10:10:00Z"} and second.more is False

    connector.fetch({"stream": "signIns"}, {}, {"since": SINCE}, 10)
    assert seen[2].url.path == "/beta/auditLogs/signIns", "v1.0 leaves out the user agent"
    assert query(seen[2])["$filter"] == (
        f"createdDateTime gt {SINCE} and signInEventTypes/any(t: t eq 'interactiveUser')"
    )


def test_entra_reads_identity_protection_risk_by_its_last_update(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.entra.access_token", lambda secret: "tok")
    seen = transport(
        monkeypatch,
        [{"json": {"value": [{"id": "r1", "lastUpdatedDateTime": "2026-09-20T10:05:00Z"}]}}],
    )
    page = connectors.get("entra").fetch({"stream": "riskDetections"}, {}, {"since": SINCE}, 5000)
    assert seen[0].url.path == "/v1.0/identityProtection/riskDetections"
    assert query(seen[0]) == {"$filter": f"lastUpdatedDateTime gt {SINCE}", "$top": "500"}
    assert page.records[0]["_stream"] == "riskDetections"
    assert page.cursor == {"since": "2026-09-20T10:05:00Z"}


# -- Microsoft 365 ---------------------------------------------------------

M365_SECRET = {"tenant_id": "tid", "client_id": "c", "client_secret": "s"}
GENERAL = {"content_type": "Audit.General"}


def stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S")


def test_m365_lists_a_bounded_window_and_reads_every_blob(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.m365.access_token", lambda secret, scope: "tok")
    listing = "https://manage.office.com/api/v1.0/tid/activity/feed/subscriptions/content"
    page2 = f"{listing}?contentType=Audit.General&nextPage=p2"
    seen = transport(
        monkeypatch,
        [
            {
                "json": [
                    {"contentUri": "https://manage.office.com/blob/1"},
                    {"contentUri": "https://manage.office.com/blob/2"},
                ],
                "headers": {"NextPageUri": page2},
            },
            {"json": [{"Id": "r1", "CreationTime": "2026-09-20T10:00:00"}]},
            {"json": [{"Id": "r2", "CreationTime": "2026-09-20T10:01:00"}]},
            {"json": [{"contentUri": "https://manage.office.com/blob/3"}]},
            {"json": [{"Id": "r3", "CreationTime": "2026-09-20T10:02:00"}]},
        ],
    )
    since = (datetime.now(UTC) - timedelta(hours=30)).replace(microsecond=0)
    end = since + timedelta(hours=24)
    connector = connectors.get("m365")
    first = connector.fetch(GENERAL, M365_SECRET, {"since": since.isoformat()}, 10)
    assert str(seen[0].url).startswith(listing)
    assert query(seen[0]) == {
        "contentType": "Audit.General",
        "startTime": stamp(since),
        "endTime": stamp(end),
        "PublisherIdentifier": "tid",
    }, "the API refuses a startTime without an endTime, or a window over 24 hours"
    assert [r["Id"] for r in first.records] == ["r1", "r2"], "every blob listed is read"
    assert first.records[0]["_content_type"] == "Audit.General"
    assert first.more is True
    assert first.cursor == {"since": since.isoformat(), "end": end.isoformat(), "next_page": page2}

    second = connector.fetch(GENERAL, M365_SECRET, first.cursor, 10)
    assert str(seen[3].url).startswith(listing) and query(seen[3]) == {
        "contentType": "Audit.General",
        "nextPage": "p2",
        "PublisherIdentifier": "tid",
    }, "the next page is replayed as issued"
    assert query(seen[1]) == {"PublisherIdentifier": "tid"}, "blobs count on our own quota"
    assert [r["Id"] for r in second.records] == ["r3"]
    # The cursor follows when content became available, not CreationTime.
    assert second.cursor == {"since": end.isoformat()}
    assert second.more is True, "a window that closed hours ago is backfill: read the next one"


def test_m365_stays_inside_seven_days_and_stops_once_caught_up(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.m365.access_token", lambda secret, scope: "tok")
    seen = transport(monkeypatch, [{"json": []}, {"json": []}])
    connector = connectors.get("m365")
    stale = connector.fetch(GENERAL, M365_SECRET, {"since": "2026-01-01T00:00:00+00:00"}, 10)
    start = datetime.fromisoformat(query(seen[0])["startTime"]).replace(tzinfo=UTC)
    assert datetime.now(UTC) - start < timedelta(days=7), "older than 7 days is a 400"
    assert stale.more is True

    recent = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    caught_up = connector.fetch(GENERAL, M365_SECRET, {"since": recent}, 10)
    assert caught_up.more is False
    assert base.utc(caught_up.cursor["since"]) > datetime.now(UTC) - timedelta(minutes=1)


def test_a_second_account_runs_the_connector_its_name_starts_with():
    assert connectors.connector_of("cloudflare:acme") == "cloudflare"
    assert connectors.connector_of("cloudflare") == "cloudflare"
    assert connectors.get("cloudflare:acme") is connectors.get("cloudflare")
    assert connectors.accepts_push("github:acme")


@pytest.mark.parametrize(
    ("source", "tag"),
    [
        ("entra", "_stream"),
        ("google_workspace", "_application"),
        ("m365", "_content_type"),
    ],
)
def test_one_configuration_reads_every_stream_the_shipped_rules_need(source, tag):
    """Each rule's positive fixture names the stream its events come from; with no
    stream set, the connector reads all of them (ING-1)."""
    from shoc.detect import rules as ruleset
    from tests.support import fixture_source, load_fixture

    streams = connectors.get(source)
    assert isinstance(streams, base.Streams)
    needed = {
        str(record.get(tag) or (record.get("id") or {}).get("applicationName", ""))
        for rule in ruleset.load()
        if fixture_source(rule) == source
        for record in load_fixture(rule.id, "positive")
    } - {""}
    assert needed and needed <= set(streams.default), needed - set(streams.default)
