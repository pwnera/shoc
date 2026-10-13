"""AWS GuardDuty connector (ING-1): pull findings for every detector in a region,
in every enabled region unless `region` names some."""

from __future__ import annotations

import json
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors import awssig
from shoc.ingest.connectors.base import FetchResult, client, reached, since_default, utc

SERVICE = "guardduty"


def _request(
    secret: dict[str, Any], region: str, path: str, body: dict[str, Any]
) -> dict[str, Any]:
    access_key = secret.get("access_key_id")
    secret_key = secret.get("secret_access_key")
    if not access_key or not secret_key:
        raise ConfigError("aws_guardduty: secret needs access_key_id and secret_access_key")
    host = f"{SERVICE}.{region}.amazonaws.com"
    payload = json.dumps(body)
    headers = awssig.headers(
        access_key=access_key,
        secret_key=secret_key,
        session_token=secret.get("session_token"),
        region=region,
        service=SERVICE,
        host=host,
        method="POST",
        path=path,
        body=payload,
        extra={"content-type": "application/json"},
    )
    with client(headers) as http:
        resp = http.post(f"https://{host}{path}", content=payload)
        resp.raise_for_status()
        return resp.json()


class AwsGuardDutyConnector:
    source = "aws_guardduty"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        """One page of findings per detector, each detector with its own window.

        A detector's start holds while its NextToken is followed, and its
        `since` moves to the newest `updatedAt` read once its pages run out; a
        new walk starts `OVERLAP` before it (D164).
        """
        region = settings.get("region") or "us-east-1"
        start = since_default(cursor, settings)
        detectors = settings.get("detector_ids") or _detectors(secret, region)
        state = cursor.get("detectors") or {}

        records: list[dict[str, Any]] = []
        out: dict[str, Any] = {}
        more = False
        for detector_id in detectors:
            mine = state.get(detector_id) or {}
            since = since_default(mine, settings) if mine else start
            body: dict[str, Any] = {
                "MaxResults": min(int(limit), 50),
                "FindingCriteria": {"Criterion": {"updatedAt": {"GreaterThan": _epoch_ms(since)}}},
                "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "ASC"},
            }
            if mine.get("next_token"):
                body["NextToken"] = mine["next_token"]
            listed = _request(secret, region, f"/detector/{detector_id}/findings", body)
            ids = listed.get("findingIds") or []
            newest = reached(mine, since)
            if ids:
                detail = _request(
                    secret, region, f"/detector/{detector_id}/findings/get", {"findingIds": ids}
                )
                for finding in detail.get("findings", []):
                    finding["detectorId"] = detector_id
                    records.append(finding)
                    newest = max(newest, str(finding.get("updatedAt") or since))
            token = listed.get("NextToken")
            if token and ids:
                held = {**mine, "start": since, "newest": newest, "next_token": token}
                out[detector_id] = held
                more = True
            else:
                out[detector_id] = {"since": newest}
        # One detector a region is the rule; with more, the earliest `since` bounds
        # what counts as late.
        late = min((str(m["since"]) for m in state.values() if m.get("since")), key=utc, default="")
        return FetchResult(records=records, cursor={"detectors": out}, more=more, since=late)


def _detectors(secret: dict[str, Any], region: str) -> list[str]:
    return _request(secret, region, "/detector", {}).get("detectorIds", [])


def _epoch_ms(iso: str) -> int:
    import datetime as dt

    return int(dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp() * 1000)


CONNECTOR = awssig.Regions(AwsGuardDutyConnector())
