"""Tailscale configuration log: activity, class and device per action (ING-3)."""

from __future__ import annotations

import json

from shoc.ingest import ocsf
from tests.support import FIXTURES


def rows() -> dict[str, dict]:
    mapping = ocsf.load_mapping("tailscale")
    records = json.loads((FIXTURES / "mappings" / "tailscale.json").read_text())
    return {r["event"]: mapping.map_record(r, "t1") for r in records}


def test_each_action_gets_its_activity_and_type():
    got = rows()
    assert (got["API_KEY.CREATE"]["activity_name"], got["API_KEY.CREATE"]["type_uid"]) == (
        "Create",
        600301,
    )
    assert (got["NODE.APPROVE"]["activity_name"], got["NODE.APPROVE"]["type_uid"]) == (
        "Update",
        600303,
    )


def test_a_login_is_an_authentication():
    login = rows()["ADMIN_CONSOLE.LOGIN"]
    assert (login["class_uid"], login["activity_name"], login["type_uid"]) == (
        3002,
        "Logon",
        300201,
    )
    assert login["actor_user_name"] == "alice@example.com"
    assert login["device_uid"] is None


def test_a_node_event_names_the_device_and_the_oauth_client_by_id():
    node = rows()["NODE.LOGIN"]
    assert (node["device_uid"], node["device_hostname"]) == (
        "n888CNTRL",
        "build-edge.example-tailnet.ts.net",
    )
    assert node["actor_user_name"] == "k777CNTRL"
    assert {"name": "device.uid", "type": "Device", "value": "n888CNTRL"} in node["observables"]
