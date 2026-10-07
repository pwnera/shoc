"""AWS Signature Version 4, shared by the AWS connectors (ING-1).

No AWS SDK (decision D6): signing a request is about forty lines, and every AWS
audit API we pull is one signed HTTPS call. Credentials come from the tenant's
encrypted connector secret, never from the host environment.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
from typing import Any
from urllib.parse import quote

from shoc.ingest.connectors.base import FetchResult, Streams, client

ALGORITHM = "AWS4-HMAC-SHA256"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    key = _sign(f"AWS4{secret_key}".encode(), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    return _sign(key, "aws4_request")


def canonical_query(params: dict[str, str] | None) -> str:
    if not params:
        return ""
    return "&".join(
        f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(params.items())
    )


def headers(
    *,
    access_key: str,
    secret_key: str,
    session_token: str | None,
    region: str,
    service: str,
    host: str,
    method: str = "POST",
    path: str = "/",
    query: dict[str, str] | None = None,
    body: str = "",
    extra: dict[str, str] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Signed headers for one request. `extra` headers are signed as well."""
    now = now or dt.datetime.now(dt.UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode()).hexdigest()

    signed: dict[str, str] = {"host": host, "x-amz-date": amz_date}
    for key, value in (extra or {}).items():
        signed[key.lower()] = value
    if session_token:
        signed["x-amz-security-token"] = session_token

    names = sorted(signed)
    canonical_headers = "".join(f"{n}:{signed[n].strip()}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join(
        [
            method.upper(),
            path or "/",
            canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        [ALGORITHM, amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    signature = hmac.new(
        signing_key(secret_key, date_stamp, region, service), to_sign.encode(), hashlib.sha256
    ).hexdigest()
    out = {k: v for k, v in signed.items()}
    out["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return out


def enabled_regions(secret: dict[str, Any]) -> list[str]:
    """The regions the account has turned on, from EC2 DescribeRegions, which
    leaves out opt-in regions nobody enabled."""
    query = {"Action": "DescribeRegions", "Version": "2016-11-15"}
    host = "ec2.us-east-1.amazonaws.com"
    signed = headers(
        access_key=secret["access_key_id"],
        secret_key=secret["secret_access_key"],
        session_token=secret.get("session_token"),
        region="us-east-1",
        service="ec2",
        host=host,
        method="GET",
        query=query,
    )
    with client(signed) as http:
        resp = http.get(f"https://{host}/?{canonical_query(query)}")
        resp.raise_for_status()
    return sorted(set(re.findall(r"<regionName>([^<]+)</regionName>", resp.text)))


class Regions(Streams):
    """A per-region AWS source that reads every enabled region unless `region`
    names some (E9). Miners are launched where nobody looks, so one region by
    default missed them. A trail bucket already holds every region, and
    `detector_ids` belong to one region, so neither is expanded."""

    def __init__(self, inner: Any) -> None:
        super().__init__(inner, "region")

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        keys = secret.get("access_key_id") and secret.get("secret_access_key")
        if keys and settings.get("region") in (None, "", "all", ["all"]):
            pinned = settings.get("bucket") or settings.get("detector_ids")
            region: Any = "" if pinned else enabled_regions(secret)
            settings = {**settings, "region": region}
        # Without keys the connector itself says which one is missing.
        return super().fetch(settings, secret, cursor, limit)
