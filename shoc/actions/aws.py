"""AWS actions (RSP-4) and lookups (RFC 0014), each one signed HTTPS call.

Disable a key, revoke the sessions minted from it, take back a policy that was
just attached; turn CloudTrail, Config and GuardDuty back on; close a public
bucket, cancel a key deletion, unshare a snapshot; and read who owns a key, what
a user can do and which defences are off. The Splunk SOAR AWS connectors cover
the same calls with boto3.

The regions the restore actions look in are the credential's `regions`
setting, else its `region`, else us-east-1.
"""

from __future__ import annotations

import contextlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlencode

import httpx

from shoc.actions.base import ActionResult, BaseAction, BaseLookup, Credentials, seg
from shoc.errors import NotFound, StoreError, ValidationError
from shoc.ingest.connectors import awssig

IAM_HOST = "iam.amazonaws.com"
IAM_REGION = "us-east-1"  # IAM is a global service signed in us-east-1


FORM = "application/x-www-form-urlencoded; charset=utf-8"


def _signed(
    creds: Credentials,
    service: str,
    region: str,
    host: str,
    http: httpx.Client | None = None,
    *,
    method: str = "POST",
    path: str = "/",
    query: dict[str, str] | None = None,
    body: str = "",
    extra: dict[str, str] | None = None,
    allow: tuple[int, ...] = (),
) -> httpx.Response:
    """One SigV4-signed call. A status in `allow` is returned instead of raised."""
    access_key, secret_key = creds.require("access_key_id", "secret_access_key")
    headers = awssig.headers(
        access_key=str(access_key),
        secret_key=str(secret_key),
        session_token=creds.secret.get("session_token"),
        region=region,
        service=service,
        host=host,
        method=method,
        path=path,
        query=query,
        body=body,
        extra=extra,
    )
    client = http or httpx.Client(timeout=30.0)
    try:
        resp = client.request(
            method, f"https://{host}{path}", params=query, content=body, headers=headers
        )
        if resp.status_code not in allow:
            resp.raise_for_status()
        return resp
    except httpx.HTTPError as exc:
        raise StoreError(f"AWS {service} call failed: {exc}") from exc
    finally:
        if http is None:
            client.close()


def _iam(creds: Credentials, params: dict[str, str], http: httpx.Client | None = None) -> str:
    body = urlencode({**params, "Version": "2010-05-08"})
    extra = {"content-type": FORM}
    return _signed(creds, "iam", IAM_REGION, IAM_HOST, http, body=body, extra=extra).text


def _ec2(
    creds: Credentials, region: str, params: dict[str, str], http: httpx.Client | None = None
) -> str:
    body = urlencode({**params, "Version": "2016-11-15"})
    host = f"ec2.{region}.amazonaws.com"
    return _signed(creds, "ec2", region, host, http, body=body, extra={"content-type": FORM}).text


def _json(
    creds: Credentials,
    service: str,
    target: str,
    region: str,
    payload: dict[str, Any],
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """An AWS JSON 1.1 call: CloudTrail, Config, KMS."""
    extra = {"content-type": "application/x-amz-json-1.1", "x-amz-target": target}
    host = f"{service}.{region}.amazonaws.com"
    resp = _signed(creds, service, region, host, http, body=json.dumps(payload), extra=extra)
    return resp.json() if resp.content else {}


def _regions(creds: Credentials, params: dict[str, Any]) -> list[str]:
    if params.get("region"):
        return [str(params["region"])]
    raw = creds.settings.get("regions") or creds.settings.get("region") or "us-east-1"
    return [raw] if isinstance(raw, str) else [str(r) for r in raw]


def _arn_region(arn: str) -> str:
    """`arn:aws:kms:eu-west-1:…` → `eu-west-1`; '' for anything that is not an ARN."""
    parts = arn.split(":")
    return parts[3] if len(parts) > 5 and parts[0] == "arn" else ""


def _in_region(value: str, creds: Credentials, params: dict[str, Any]) -> tuple[str, str]:
    """A target written `region/name`, or a bare name in the first configured region."""
    region, _, name = value.rpartition("/")
    return region or _regions(creds, params)[0], name


class DisableAccessKey(BaseAction):
    type = "aws.disable_access_key"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "key"
    summary = "Disable an IAM access key"
    reversible = True
    # Without UserName, IAM looks the key up under shoc's own user, and a key
    # that belongs to anybody else is "not found" (RSP-4).
    required_params = ("access_key_id", "user_name")
    # The events where the key acted name its user; IAM answers when they do not.
    resolve: ClassVar = {
        "user_name": ("actor_session_uid", "actor_user_name", "aws.get_access_key"),
    }

    def plan(self, params: dict[str, Any]) -> str:
        return f"Set IAM access key {params.get('access_key_id')} to Inactive" + (
            f" for user {params['user_name']}" if params.get("user_name") else ""
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        call = {
            "Action": "UpdateAccessKey",
            "AccessKeyId": params["access_key_id"],
            "Status": "Inactive",
        }
        if params.get("user_name"):
            call["UserName"] = params["user_name"]
        _iam(creds, call, http)
        return ActionResult(
            ok=True,
            detail=f"access key {params['access_key_id']} is now Inactive",
            data={"access_key_id": params["access_key_id"]},
            undo={"access_key_id": params["access_key_id"], "user_name": params.get("user_name")},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        call = {
            "Action": "UpdateAccessKey",
            "AccessKeyId": undo["access_key_id"],
            "Status": "Active",
        }
        if undo.get("user_name"):
            call["UserName"] = undo["user_name"]
        _iam(creds, call, http)
        return ActionResult(ok=True, detail=f"access key {undo['access_key_id']} re-enabled")


REVOKE_POLICY = "AWSRevokeOlderSessions"


def _deny_older(creds: Credentials, kind: str, name: str, http: httpx.Client | None) -> str:
    """Deny everything to sessions issued before now, on a `User` or a `Role`.

    Long-term keys carry no aws:TokenIssueTime, so the condition never matches
    them; permissions are untouched, and a session issued after now works.
    """
    stamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["*"],
                "Resource": ["*"],
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": stamp}},
            }
        ],
    }
    _iam(
        creds,
        {
            "Action": f"Put{kind}Policy",
            f"{kind}Name": name,
            "PolicyName": REVOKE_POLICY,
            "PolicyDocument": json.dumps(document),
        },
        http,
    )
    return stamp


def _allow_older(creds: Credentials, kind: str, name: str, http: httpx.Client | None) -> None:
    _iam(
        creds,
        {"Action": f"Delete{kind}Policy", f"{kind}Name": name, "PolicyName": REVOKE_POLICY},
        http,
    )


class RevokeRoleSessions(BaseAction):
    """Attach the standard AWSRevokeOlderSessions policy to an IAM role.

    It invalidates every session issued before now without touching the role's
    permissions, which is the safe way to kick an attacker out of a role that
    production is still using.
    """

    type = "aws.revoke_role_sessions"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "role"
    summary = "Revoke every existing session for an IAM role"
    reversible = True
    required_params = ("role_name",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Revoke all sessions issued before now for IAM role {params.get('role_name')}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        stamp = _deny_older(creds, "Role", params["role_name"], http)
        return ActionResult(
            ok=True,
            detail=f"sessions issued before {stamp} revoked for role {params['role_name']}",
            data={"role_name": params["role_name"], "cutoff": stamp},
            undo={"role_name": params["role_name"]},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        _allow_older(creds, "Role", undo["role_name"], http)
        return ActionResult(ok=True, detail=f"revocation policy removed from {undo['role_name']}")


class RevokeSessions(BaseAction):
    """Revoke the temporary credentials behind an access key.

    Disabling a long-term key (AKIA…) leaves alive what it minted with
    GetSessionToken or GetFederationToken, and IAM cannot disable a session key
    (ASIA…) at all. Both stop here: a time-bounded deny on the IAM user behind
    the key, or on the role an ASIA key's session was assumed from.
    """

    type = "aws.revoke_sessions"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "key"
    summary = "Revoke every session issued before now for the user or role behind a key"
    reversible = True
    # `user_name` is CloudTrail's: the IAM user, or for an assumed-role session
    # the role (sessionIssuer.userName).
    required_params = ("access_key_id", "user_name")
    resolve: ClassVar = {
        "user_name": ("actor_session_uid", "actor_user_name", "aws.get_access_key"),
        "principal_type": ("actor_session_uid", "actor_user_type", None),
    }

    def _kind(self, params: dict[str, Any]) -> str:
        key, kind = str(params.get("access_key_id", "")), params.get("principal_type")
        if kind in ("IAMUser", "FederatedUser") or (not kind and key.startswith("AKIA")):
            return "User"
        if kind == "AssumedRole":
            return "Role"
        if kind:
            raise ValidationError(f"{self.type}: a {kind} session has no IAM user or role to deny")
        raise ValidationError(
            f"{self.type}: no event says whether session key {key} is a user's or a role's"
        )

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        self._kind(params)

    def plan(self, params: dict[str, Any]) -> str:
        kind = "role" if params.get("principal_type") == "AssumedRole" else "user"
        return (
            f"Deny every session issued before now to IAM {kind} {params.get('user_name')}, "
            f"behind key {params.get('access_key_id')}; long-term keys and new sessions still work"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        kind, name = self._kind(params), str(params["user_name"])
        stamp = _deny_older(creds, kind, name, http)
        return ActionResult(
            ok=True,
            detail=f"sessions issued before {stamp} revoked for {kind.lower()} {name}",
            data={"access_key_id": params["access_key_id"], kind.lower(): name, "cutoff": stamp},
            undo={"kind": kind, "name": name},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        _allow_older(creds, undo["kind"], undo["name"], http)
        return ActionResult(ok=True, detail=f"revocation policy removed from {undo['name']}")


class DetachUserPolicy(BaseAction):
    """Detach a managed policy. The role variant below differs only in its target,
    which matters: `role:prod-*` is a protected target and `user:prod-*` is not."""

    type = "aws.detach_user_policy"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "user"
    kind = "User"
    summary = "Detach a managed policy from an IAM user"
    reversible = True
    required_params = ("user_name", "policy_arn")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Detach {params.get('policy_arn')} from {self.target_kind} {self.target_of(params)}"

    def _call(
        self, creds: Credentials, verb: str, params: dict[str, Any], http: httpx.Client | None
    ) -> None:
        _iam(
            creds,
            {
                "Action": f"{verb}{self.kind}Policy",
                f"{self.kind}Name": str(params[self.required_params[0]]),
                "PolicyArn": str(params["policy_arn"]),
            },
            http,
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._call(creds, "Detach", params, http)
        kept = {p: params[p] for p in self.required_params}
        return ActionResult(
            ok=True,
            detail=f"{params['policy_arn']} detached from {self.target_of(params)}",
            data=kept,
            undo=kept,
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._call(creds, "Attach", undo, http)
        return ActionResult(ok=True, detail=f"{undo['policy_arn']} attached again")


class DetachRolePolicy(DetachUserPolicy):
    type = "aws.detach_role_policy"
    target_kind = "role"
    kind = "Role"
    summary = "Detach a managed policy from an IAM role"
    required_params = ("role_name", "policy_arn")


def _members(xml: str) -> list[dict[str, str]]:
    """Every `<member>` in an IAM response, as a flat dict of its children."""
    out = []
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == "member":
            out.append({c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in el})
    return out


def _field(xml: str, name: str) -> str:
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == name:
            return el.text or ""
    return ""


class GetAccessKey(BaseLookup):
    type = "aws.get_access_key"
    provider = "aws"
    platforms = ("aws",)
    summary = "Who owns an access key, and when, where and on what it was last used"
    required_params = ("access_key_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        xml = _iam(
            creds,
            {"Action": "GetAccessKeyLastUsed", "AccessKeyId": str(params["access_key_id"])},
            http,
        )
        return {
            name: _field(xml, tag)
            for name, tag in (
                ("user_name", "UserName"),
                ("last_used", "LastUsedDate"),
                ("service", "ServiceName"),
                ("region", "Region"),
            )
        }


class GetUser(BaseLookup):
    type = "aws.get_user"
    provider = "aws"
    platforms = ("aws",)
    summary = "An IAM user's policies, groups, access keys and MFA devices"
    required_params = ("user_name",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        user = str(params["user_name"])

        def ask(action: str) -> list[dict[str, str]]:
            return _members(_iam(creds, {"Action": action, "UserName": user}, http))

        return {
            "policies": [m.get("PolicyArn") for m in ask("ListAttachedUserPolicies")],
            "groups": [m.get("GroupName") for m in ask("ListGroupsForUser")],
            "access_keys": [
                {
                    "access_key_id": m.get("AccessKeyId"),
                    "status": m.get("Status"),
                    "created": m.get("CreateDate"),
                }
                for m in ask("ListAccessKeys")
            ],
            "mfa_devices": [m.get("SerialNumber") for m in ask("ListMFADevices")],
        }


# -- defences: CloudTrail, Config, GuardDuty ---------------------------------
CLOUDTRAIL = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."
CONFIG = "StarlingDoveService."


def _guardduty(
    creds: Credentials,
    region: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload) if payload is not None else ""
    host = f"guardduty.{region}.amazonaws.com"
    extra = {"content-type": "application/json"}
    resp = _signed(
        creds, "guardduty", region, host, http, method=method, path=path, body=body, extra=extra
    )
    return resp.json() if resp.content else {}


class GetDefences(BaseLookup):
    """What is switched off right now. The restore actions read their target here,
    so a playbook proposes only the one whose service is actually off."""

    type = "aws.get_defences"
    provider = "aws"
    platforms = ("aws",)
    summary = "Which CloudTrail trails, Config recorders and GuardDuty detectors are off"
    required_params = ("region",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        out: dict[str, list[dict[str, Any]]] = {"trails": [], "recorders": [], "detectors": []}

        def section(name: str, read: Any, region: str) -> None:
            # One missing permission costs that service, not the answer.
            try:
                out[name] += read(region)
            except StoreError as exc:
                out[name].append({"unavailable": str(exc)[:200]})

        def trails(region: str) -> list[dict[str, Any]]:
            found = _json(
                creds,
                "cloudtrail",
                CLOUDTRAIL + "DescribeTrails",
                region,
                {"includeShadowTrails": True},
                http,
            ).get("trailList", [])
            rows = []
            for t in found:
                arn = str(t.get("TrailARN", ""))
                home = _arn_region(arn) or region
                status = _json(
                    creds, "cloudtrail", CLOUDTRAIL + "GetTrailStatus", home, {"Name": arn}, http
                )
                rows.append({"trail": arn, "logging": bool(status.get("IsLogging"))})
            return rows

        def recorders(region: str) -> list[dict[str, Any]]:
            found = _json(
                creds, "config", CONFIG + "DescribeConfigurationRecorderStatus", region, {}, http
            ).get("ConfigurationRecordersStatus", [])
            return [
                {"recorder": f"{region}/{r.get('name')}", "recording": bool(r.get("recording"))}
                for r in found
            ]

        def detectors(region: str) -> list[dict[str, Any]]:
            ids = _guardduty(creds, region, "GET", "/detector", http=http).get("detectorIds", [])
            return [
                {
                    "detector_id": f"{region}/{d}",
                    "enabled": _guardduty(
                        creds, region, "GET", f"/detector/{seg(d)}", http=http
                    ).get("status")
                    == "ENABLED",
                }
                for d in ids
            ]

        for region in _regions(creds, params):
            section("trails", trails, region)
            section("recorders", recorders, region)
            section("detectors", detectors, region)
        # A multi-region trail shows in every region it covers.
        out["trails"] = list({t.get("trail") or str(t): t for t in out["trails"]}.values())

        def first_off(rows: list[dict[str, Any]], key: str, on: str) -> str:
            return next((str(r[key]) for r in rows if key in r and not r[on]), "")

        return {
            "trail": first_off(out["trails"], "trail", "logging"),
            "recorder": first_off(out["recorders"], "recorder", "recording"),
            "detector_id": first_off(out["detectors"], "detector_id", "enabled"),
            **out,
        }


TRAIL = re.compile(r"(arn:aws[\w-]*:cloudtrail:[a-z0-9-]+:\d{12}:trail/)?[\w.-]{3,128}")


class StartCloudTrailLogging(BaseAction):
    type = "aws.start_cloudtrail_logging"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Turn a stopped CloudTrail trail back on"
    reversible = True
    required_params = ("trail",)
    resolve: ClassVar = {"trail": (None, None, "aws.get_defences")}

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not TRAIL.fullmatch(str(params["trail"])):
            raise ValidationError(f"{self.type}: '{params['trail']}' is not a trail")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Start logging on CloudTrail trail {params.get('trail')}"

    def _call(self, creds: Credentials, op: str, trail: str, http: httpx.Client | None) -> None:
        # A multi-region trail is started and stopped in its home region.
        region = _arn_region(trail) or _regions(creds, {})[0]
        _json(creds, "cloudtrail", CLOUDTRAIL + op, region, {"Name": trail}, http)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._call(creds, "StartLogging", params["trail"], http)
        kept = {"trail": params["trail"]}
        return ActionResult(
            ok=True, detail=f"trail {params['trail']} is logging", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._call(creds, "StopLogging", undo["trail"], http)
        return ActionResult(ok=True, detail=f"trail {undo['trail']} stopped again")


class StartConfigRecorder(BaseAction):
    type = "aws.start_config_recorder"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Turn a stopped AWS Config recorder back on"
    reversible = True
    # `region/name`, as aws.get_defences lists it.
    required_params = ("recorder",)
    resolve: ClassVar = {"recorder": (None, None, "aws.get_defences")}

    def plan(self, params: dict[str, Any]) -> str:
        return f"Start AWS Config recorder {params.get('recorder')}"

    def _call(self, creds: Credentials, op: str, recorder: str, http: httpx.Client | None) -> None:
        region, name = _in_region(recorder, creds, {})
        _json(creds, "config", CONFIG + op, region, {"ConfigurationRecorderName": name}, http)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._call(creds, "StartConfigurationRecorder", params["recorder"], http)
        kept = {"recorder": params["recorder"]}
        return ActionResult(
            ok=True, detail=f"recorder {params['recorder']} is recording", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._call(creds, "StopConfigurationRecorder", undo["recorder"], http)
        return ActionResult(ok=True, detail=f"recorder {undo['recorder']} stopped again")


class EnableGuardDuty(BaseAction):
    """UpdateDetector Enable=true. A deleted detector has nothing to enable, and
    creating one where the company never ran GuardDuty is a human's call."""

    type = "aws.enable_guardduty"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Turn a suspended GuardDuty detector back on"
    reversible = True
    # `region/detector-id`, as aws.get_defences lists it.
    required_params = ("detector_id",)
    resolve: ClassVar = {"detector_id": (None, None, "aws.get_defences")}

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not re.fullmatch(r"[0-9a-f]{32}", str(params["detector_id"]).rpartition("/")[2]):
            raise ValidationError(f"{self.type}: '{params['detector_id']}' is not a detector id")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Enable GuardDuty detector {params.get('detector_id')}"

    def _set(self, creds: Credentials, detector: str, on: bool, http: httpx.Client | None) -> None:
        region, did = _in_region(detector, creds, {})
        _guardduty(creds, region, "POST", f"/detector/{seg(did)}", {"enable": on}, http)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._set(creds, params["detector_id"], True, http)
        kept = {"detector_id": params["detector_id"]}
        return ActionResult(
            ok=True, detail=f"detector {params['detector_id']} enabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(creds, undo["detector_id"], False, http)
        return ActionResult(ok=True, detail=f"detector {undo['detector_id']} suspended again")


# -- data exposure: S3, KMS, EBS ----------------------------------------------
BUCKET = re.compile(r"(?:arn:aws[\w-]*:s3:::)?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])")
PAB = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _pab_xml(flags: dict[str, bool]) -> str:
    inner = "".join(f"<{k}>{str(bool(flags.get(k))).lower()}</{k}>" for k in PAB)
    return (
        f'<PublicAccessBlockConfiguration xmlns="{S3_NS}">{inner}</PublicAccessBlockConfiguration>'
    )


class BlockS3PublicAccess(BaseAction):
    """Turn on all four Block Public Access settings on one bucket. The bucket's
    own block, if it had one, is kept for undo; without one, undo deletes it."""

    type = "aws.block_s3_public_access"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Block public access to an S3 bucket"
    reversible = True
    required_params = ("bucket",)
    resolve: ClassVar = {"region": ("resource_uid", "cloud_region", None)}

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not BUCKET.fullmatch(str(params["bucket"])):
            raise ValidationError(f"{self.type}: '{params['bucket']}' is not an S3 bucket")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Block all public access to S3 bucket {params.get('bucket')}; "
            "a website served from it goes dark"
        )

    def _call(
        self,
        creds: Credentials,
        where: dict[str, Any],
        method: str,
        body: str = "",
        http: httpx.Client | None = None,
    ) -> httpx.Response:
        import base64
        import hashlib

        extra = {"x-amz-content-sha256": hashlib.sha256(body.encode()).hexdigest()}
        if body:
            extra["content-md5"] = base64.b64encode(hashlib.md5(body.encode()).digest()).decode()
        region = where["region"]
        return _signed(
            creds,
            "s3",
            region,
            f"s3.{region}.amazonaws.com",
            http,
            method=method,
            path=f"/{where['bucket']}",
            query={"publicAccessBlock": ""},
            body=body,
            extra=extra,
            allow=(404,),
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        match = BUCKET.fullmatch(str(params["bucket"]))
        where = {
            "bucket": match.group(1) if match else "",
            "region": params.get("region") or _regions(creds, {})[0],
        }
        was = self._call(creds, where, "GET", http=http)
        prior = {k: _field(was.text, k) == "true" for k in PAB} if was.status_code == 200 else None
        put = self._call(creds, where, "PUT", _pab_xml(dict.fromkeys(PAB, True)), http)
        if put.status_code == 404:
            raise StoreError(f"AWS s3: bucket {where['bucket']} not found")
        return ActionResult(
            ok=True,
            detail=f"public access to {where['bucket']} is blocked",
            data={**where, "was": prior},
            undo={**where, "prior": prior},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        if undo.get("prior"):
            self._call(creds, undo, "PUT", _pab_xml(undo["prior"]), http)
        else:
            self._call(creds, undo, "DELETE", http=http)
        return ActionResult(ok=True, detail=f"{undo['bucket']}'s public access block restored")


KMS_KEY = re.compile(
    r"(arn:aws[\w-]*:kms:[a-z0-9-]+:\d{12}:key/)?"
    r"(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


class CancelKeyDeletion(BaseAction):
    """CancelKeyDeletion, then EnableKey: a cancelled deletion leaves the key
    disabled, and so does DisableKey. What the key was is kept for undo."""

    type = "aws.cancel_key_deletion"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Cancel a KMS key's scheduled deletion and enable it again"
    reversible = True
    required_params = ("key_id",)

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not KMS_KEY.fullmatch(str(params["key_id"])):
            raise ValidationError(f"{self.type}: '{params['key_id']}' is not a KMS key")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Cancel the deletion of KMS key {params.get('key_id')} and enable it"

    def _kms(
        self, creds: Credentials, key: str, op: str, http: httpx.Client | None, **kw: Any
    ) -> dict[str, Any]:
        region = _arn_region(key) or _regions(creds, {})[0]
        return _json(creds, "kms", f"TrentService.{op}", region, {"KeyId": key, **kw}, http)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        key = str(params["key_id"])
        state = (
            self._kms(creds, key, "DescribeKey", http).get("KeyMetadata", {}).get("KeyState", "")
        )
        if state == "PendingDeletion":
            self._kms(creds, key, "CancelKeyDeletion", http)
        if state in ("PendingDeletion", "Disabled"):
            self._kms(creds, key, "EnableKey", http)
        detail = (
            f"key {key} enabled (was {state})"
            if state != "Enabled"
            else f"key {key} was already enabled"
        )
        return ActionResult(
            ok=True,
            detail=detail,
            data={"key_id": key, "was": state},
            undo={"key_id": key, "was": state},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        key, was = undo["key_id"], undo.get("was")
        if was == "Disabled":
            self._kms(creds, key, "DisableKey", http)
        elif was == "PendingDeletion":
            # The original deletion date is gone; the longest window AWS allows.
            self._kms(creds, key, "ScheduleKeyDeletion", http, PendingWindowInDays=30)
        return ActionResult(ok=True, detail=f"key {key} is {was or 'unchanged'} again")


SHARED = re.compile(r"(snap|ami)-[0-9a-f]{8,17}")


def _grantees(xml: str, attr: str) -> list[dict[str, str]]:
    """The `<item>`s under a snapshot's or image's permission element."""
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == attr:
            return [
                {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in item}
                for item in el
                if item.tag.rsplit("}", 1)[-1] == "item"
            ]
    return []


class UnshareSnapshot(BaseAction):
    """Remove every account, organisation and `all` grant from an EBS snapshot's
    createVolumePermission or an AMI's launchPermission, keeping them for undo."""

    type = "aws.unshare_snapshot"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "resource"
    summary = "Stop sharing an EBS snapshot or AMI with other accounts"
    reversible = True
    required_params = ("snapshot_id",)
    resolve: ClassVar = {"region": ("resource_uid", "cloud_region", None)}

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not SHARED.fullmatch(str(params["snapshot_id"])):
            raise ValidationError(
                f"{self.type}: '{params['snapshot_id']}' is not a snapshot or AMI"
            )

    def plan(self, params: dict[str, Any]) -> str:
        return f"Remove every outside grant from {params.get('snapshot_id')}"

    def _modify(
        self,
        creds: Credentials,
        where: dict[str, Any],
        op: str,
        grantees: list[dict[str, str]],
        http: httpx.Client | None,
    ) -> None:
        sid = where["snapshot_id"]
        noun, attr = (
            ("Image", "launchPermission")
            if sid.startswith("ami-")
            else ("Snapshot", "createVolumePermission")
        )
        call = {"Action": f"Modify{noun}Attribute", f"{noun}Id": sid, "Attribute": attr}
        for i, grant in enumerate(grantees, 1):
            for k, v in grant.items():
                call[f"{attr[0].upper()}{attr[1:]}.{op}.{i}.{k[0].upper()}{k[1:]}"] = v
        _ec2(creds, where["region"], call, http)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        sid = str(params["snapshot_id"])
        where = {"snapshot_id": sid, "region": params.get("region") or _regions(creds, {})[0]}
        noun, attr = (
            ("Image", "launchPermission")
            if sid.startswith("ami-")
            else ("Snapshot", "createVolumePermission")
        )
        xml = _ec2(
            creds,
            where["region"],
            {"Action": f"Describe{noun}Attribute", f"{noun}Id": sid, "Attribute": attr},
            http,
        )
        grantees = _grantees(xml, attr)
        if grantees:
            self._modify(creds, where, "Remove", grantees, http)
        return ActionResult(
            ok=True,
            detail=f"{sid} is no longer shared ({len(grantees)} grant(s) removed)",
            data={**where, "removed": grantees},
            undo={**where, "grantees": grantees},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        if undo.get("grantees"):
            self._modify(creds, undo, "Add", undo["grantees"], http)
        return ActionResult(ok=True, detail=f"{undo['snapshot_id']} shared again as it was")


# -- a key's user and an instance, contained ----------------------------------
QUARANTINE_POLICY = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"


class QuarantineUser(BaseAction):
    """Attach AWS's own quarantine policy to the user behind a leaked key. AWS
    made it for this case: it denies the writes a stolen key is used for
    (new keys, users, roles, instances, functions, policy changes) and leaves
    reads, so the user's other work keeps running until a person looks."""

    type = "aws.quarantine_user"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "key"
    summary = "Attach AWS's quarantine policy to the IAM user behind an access key"
    reversible = True
    required_params = ("access_key_id", "user_name")
    # The same answer as disabling the key: the events where it acted, else IAM.
    resolve: ClassVar = {
        "user_name": ("actor_session_uid", "actor_user_name", "aws.get_access_key"),
    }

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Attach AWSCompromisedKeyQuarantineV3 to IAM user {params.get('user_name')}, whose "
            f"key {params.get('access_key_id')} leaked: it denies the writes a stolen key is "
            "used for until it is detached"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user_name"]
        _iam(
            creds,
            {"Action": "AttachUserPolicy", "UserName": user, "PolicyArn": QUARANTINE_POLICY},
            http,
        )
        return ActionResult(
            ok=True,
            detail=f"IAM user {user} is quarantined",
            data={"user_name": user, "policy_arn": QUARANTINE_POLICY},
            undo={"user_name": user},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        call = {"Action": "DetachUserPolicy", "UserName": undo["user_name"]}
        _iam(creds, {**call, "PolicyArn": QUARANTINE_POLICY}, http)
        return ActionResult(ok=True, detail=f"IAM user {undo['user_name']} is out of quarantine")


INSTANCE = re.compile(r"i-[0-9a-f]{8,17}")
ISOLATION = "shoc-isolation"


def _local(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _child(el: ET.Element | None, *path: str) -> ET.Element | None:
    for name in path:
        el = next((c for c in el if _local(c) == name), None) if el is not None else None
    return el


def _text(el: ET.Element | None, *path: str) -> str:
    found = _child(el, *path)
    return (found.text or "") if found is not None else ""


def _items(el: ET.Element | None, name: str) -> list[ET.Element]:
    found = _child(el, name)
    return list(found) if found is not None else []


def _find_instance(
    creds: Credentials, instance_id: str, region: str | None, http: httpx.Client | None
) -> tuple[str, ET.Element]:
    """The instance and its region: the one named, else each configured region in turn."""
    tried = [region] if region else _regions(creds, {})
    for where in tried:
        body = urlencode(
            {"Action": "DescribeInstances", "Version": "2016-11-15", "InstanceId.1": instance_id}
        )
        host = f"ec2.{where}.amazonaws.com"
        resp = _signed(
            creds, "ec2", where, host, http, body=body, extra={"content-type": FORM}, allow=(400,)
        )
        if resp.status_code == 400:
            if "InvalidInstanceID" in resp.text:
                continue
            raise StoreError(f"AWS ec2 call failed: {resp.text[:300]}")
        found = next(
            (el for el in ET.fromstring(resp.text).iter() if _local(el) == "instancesSet"), None
        )
        instance = next(iter(found), None) if found is not None else None
        if instance is not None:
            return where, instance
    raise NotFound(f"no EC2 instance {instance_id} in {', '.join(tried)}")


def _isolation_group(creds: Credentials, region: str, vpc: str, http: httpx.Client | None) -> str:
    """The VPC's `shoc-isolation` group, made once with no rule in or out."""
    xml = _ec2(
        creds,
        region,
        {
            "Action": "DescribeSecurityGroups",
            "Filter.1.Name": "vpc-id",
            "Filter.1.Value.1": vpc,
            "Filter.2.Name": "group-name",
            "Filter.2.Value.1": ISOLATION,
        },
        http,
    )
    if found := _field(xml, "groupId"):
        return found
    made = _ec2(
        creds,
        region,
        {
            "Action": "CreateSecurityGroup",
            "GroupName": ISOLATION,
            "GroupDescription": "shoc isolation: no traffic in or out",
            "VpcId": vpc,
        },
        http,
    )
    group = _field(made, "groupId")
    # A new group lets everything out; take that away, IPv6 too where the VPC has it.
    everything = {"Action": "RevokeSecurityGroupEgress", "GroupId": group}
    _ec2(
        creds,
        region,
        {
            **everything,
            "IpPermissions.1.IpProtocol": "-1",
            "IpPermissions.1.IpRanges.1.CidrIp": "0.0.0.0/0",
        },
        http,
    )
    with contextlib.suppress(StoreError):  # a VPC without IPv6 has no such rule
        _ec2(
            creds,
            region,
            {
                **everything,
                "IpPermissions.1.IpProtocol": "-1",
                "IpPermissions.1.Ipv6Ranges.1.CidrIpv6": "::/0",
            },
            http,
        )
    return group


def _set_groups(
    creds: Credentials, region: str, interface: str, groups: list[str], http: httpx.Client | None
) -> None:
    call = {"Action": "ModifyNetworkInterfaceAttribute", "NetworkInterfaceId": interface}
    call.update({f"SecurityGroupId.{i}": g for i, g in enumerate(groups, 1)})
    _ec2(creds, region, call, http)


class IsolateInstance(BaseAction):
    """Put every network interface of an EC2 instance behind a security group
    with no rule, keeping each interface's groups for undo. The instance keeps
    running, so its disk and memory stay there to be examined."""

    type = "aws.isolate_instance"
    provider = "aws"
    platforms = ("aws",)
    target_kind = "instance"
    summary = "Cut an EC2 instance off the network, keeping it running"
    reversible = True
    required_params = ("instance_id",)
    # GuardDuty and CloudTrail name the instance with the region it runs in.
    resolve: ClassVar = {"region": ("device_uid", "cloud_region", None)}

    def check(self, params: dict[str, Any]) -> None:
        super().check(params)
        if not INSTANCE.fullmatch(str(params["instance_id"])):
            raise ValidationError(f"{self.type}: '{params['instance_id']}' is not an EC2 instance")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Swap every security group of {params.get('instance_id')} for {ISOLATION}, which "
            "allows no traffic in or out; the instance keeps running"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        iid = str(params["instance_id"])
        region, instance = _find_instance(creds, iid, params.get("region"), http)
        vpc = _text(instance, "vpcId")
        interfaces = {
            _text(n, "networkInterfaceId"): [_text(g, "groupId") for g in _items(n, "groupSet")]
            for n in _items(instance, "networkInterfaceSet")
        }
        if not vpc or not interfaces:
            raise ValidationError(f"{iid} has no network interface in a VPC to isolate")
        group = _isolation_group(creds, region, vpc, http)
        for interface in interfaces:
            _set_groups(creds, region, interface, [group], http)
        return ActionResult(
            ok=True,
            detail=f"{iid} is isolated behind {group}; connections already open can last "
            "until they go idle",
            data={"instance_id": iid, "region": region, "security_group": group},
            undo={"instance_id": iid, "region": region, "interfaces": interfaces},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        for interface, groups in undo["interfaces"].items():
            _set_groups(creds, undo["region"], interface, groups, http)
        return ActionResult(ok=True, detail=f"{undo['instance_id']} has its security groups back")


class GetInstance(BaseLookup):
    type = "aws.get_instance"
    provider = "aws"
    platforms = ("aws",)
    summary = "An EC2 instance's state, type, addresses, security groups, role and tags"
    required_params = ("instance_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        iid = str(params["instance_id"])
        if not INSTANCE.fullmatch(iid):
            raise ValidationError(f"{self.type}: '{iid}' is not an EC2 instance")
        region, instance = _find_instance(creds, iid, params.get("region"), http)
        return {
            "instance_id": iid,
            "region": region,
            "state": _text(instance, "instanceState", "name"),
            "type": _text(instance, "instanceType"),
            "launched": _text(instance, "launchTime"),
            "vpc": _text(instance, "vpcId"),
            "subnet": _text(instance, "subnetId"),
            "private_ip": _text(instance, "privateIpAddress"),
            "public_ip": _text(instance, "ipAddress"),
            "security_groups": [_text(g, "groupId") for g in _items(instance, "groupSet")],
            "role": _text(instance, "iamInstanceProfile", "arn"),
            "key_name": _text(instance, "keyName"),
            "tags": {_text(t, "key"): _text(t, "value") for t in _items(instance, "tagSet")},
        }


ACTIONS = [
    DisableAccessKey(),
    QuarantineUser(),
    IsolateInstance(),
    RevokeSessions(),
    RevokeRoleSessions(),
    DetachUserPolicy(),
    DetachRolePolicy(),
    StartCloudTrailLogging(),
    StartConfigRecorder(),
    EnableGuardDuty(),
    BlockS3PublicAccess(),
    CancelKeyDeletion(),
    UnshareSnapshot(),
]
LOOKUPS = [GetAccessKey(), GetUser(), GetDefences(), GetInstance()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """Who the key is (STS GetCallerIdentity), a call no policy can deny."""
    body = urlencode({"Action": "GetCallerIdentity", "Version": "2011-06-15"})
    extra = {"content-type": FORM}
    resp = _signed(creds, "sts", "us-east-1", "sts.amazonaws.com", http, body=body, extra=extra)
    return f"signed in as {_field(resp.text, 'Arn')}"
