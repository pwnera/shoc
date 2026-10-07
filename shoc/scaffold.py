"""`shoc new connector|rule|mapping` — the contributor SDK (ING-4).

A new source should be one Python module plus one mapping file plus a fixture,
and a new rule should be one YAML plus two fixtures. These templates write
exactly those files, already wired into the tests that will judge them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from shoc.errors import ValidationError

SLUG = re.compile(r"^[a-z][a-z0-9_]{2,40}$")


@dataclass
class Written:
    paths: list[Path]

    def describe(self) -> str:
        return "\n".join(f"  {p}" for p in self.paths)


def _check(name: str) -> str:
    if not SLUG.match(name):
        raise ValidationError(
            f"'{name}' is not a usable name: lower case letters, digits and underscores, "
            "starting with a letter"
        )
    return name


def _write(path: Path, content: str, force: bool) -> Path:
    if path.exists() and not force:
        raise ValidationError(f"{path} already exists (pass --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


CONNECTOR_TEMPLATE = '''"""{title} connector (ING-1).

Fill in `fetch`: ask the API for everything after the cursor, and return the raw
records plus the next cursor. Mapping, batching, deduplication, cursor storage
and health accounting are handled for you in `base.py`.
"""

from __future__ import annotations

from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, since_default

API = "https://api.{name}.example/v1"


class {klass}Connector:
    source = "{name}"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        token = secret.get("api_token")
        if not token:
            raise ConfigError("{name}: the secret needs api_token")
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        params: dict[str, Any] = {{"since": since, "limit": min(int(limit), 1000)}}
        if cursor.get("page"):
            params["page"] = cursor["page"]
        headers = {{"Authorization": f"Bearer {{token}}", "Accept": "application/json"}}
        with client(headers) as http:
            resp = http.get(f"{{API}}/events", params=params)
            resp.raise_for_status()
            payload = resp.json()

        records = payload.get("items", [])
        newest = max(
            [str(r.get("timestamp", "")) for r in records] + [str(cursor.get("newest") or since)]
        )
        page = payload.get("next_page")
        if page and records:
            # A page token belongs to the filter it came from: hold `since` until
            # the pages run out. The run loop re-reads an overlap after that.
            held = {{"since": since, "newest": newest, "page": page}}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={{"since": newest}}, more=False)


CONNECTOR = {klass}Connector()
'''

MAPPING_TEMPLATE = """# {title} -> OCSF. ING-3. Every column below must exist in shoc/store/ocsf.py.
source: {name}
ocsf_version: "1.3.0"

constants:
  category_uid: 6
  class_uid: 6003
  class_name: API Activity
  type_uid: 600399
  activity_id: 99
  activity_name: Other
  severity_id: 1
  status: Success
  metadata_product: {title}
  api_service_name: {name}

fields:
  event_uid: {{ path: id }}
  time: {{ path: timestamp, transform: iso8601 }}
  api_operation: {{ path: action }}
  message: {{ path: description }}
  actor_user_name: {{ paths: [user.email, user.id] }}
  src_endpoint_ip: {{ path: ip_address }}
  resource_uid: {{ path: target.id }}

derive:
  - when: {{ outcome: failure }}
    set: {{ status: Failure, severity_id: 2 }}

observables:
  - {{ column: src_endpoint_ip, name: src_endpoint.ip, type: "IP Address" }}
  - {{ column: actor_user_name, name: actor.user.name, type: User }}
"""

MAPPING_FIXTURE = [
    {
        "id": "example-1",
        "timestamp": "2026-09-20T10:00:00Z",
        "action": "user.login",
        "description": "A user signed in",
        "user": {"email": "jane@example.com", "id": "u-1"},
        "ip_address": "198.51.100.5",
        "target": {"id": "app-1"},
        "outcome": "success",
    }
]

RULE_TEMPLATE = """id: {name}
title: {title}
description: >
  What this detects, and why someone should care. Write the sentence you would
  want to read at 3am.
status: experimental
severity: medium
confidence: 0.6
attack: [T1078]
logsource:
  product: {product}
  service: {service}
detection:
  selection:
    api.operation: ChangeMe
  condition: selection
  timeframe: 15m
entity: actor.user.name
fields: [actor.user.name, api.operation, src_endpoint.ip]
"""


def new_connector(name: str, root: Path = Path("."), force: bool = False) -> Written:
    _check(name)
    klass = "".join(part.capitalize() for part in name.split("_"))
    title = name.replace("_", " ").title()
    paths = [
        _write(
            root / "shoc" / "ingest" / "connectors" / f"{name}.py",
            CONNECTOR_TEMPLATE.format(name=name, klass=klass, title=title),
            force,
        ),
        _write(
            root / "shoc" / "ingest" / "mappings" / f"{name}.yaml",
            MAPPING_TEMPLATE.format(name=name, title=title),
            force,
        ),
        _write(
            root / "tests" / "fixtures" / "mappings" / f"{name}.json",
            json.dumps(MAPPING_FIXTURE, indent=2) + "\n",
            force,
        ),
    ]
    return Written(paths)


def new_mapping(name: str, root: Path = Path("."), force: bool = False) -> Written:
    _check(name)
    title = name.replace("_", " ").title()
    return Written(
        [
            _write(
                root / "shoc" / "ingest" / "mappings" / f"{name}.yaml",
                MAPPING_TEMPLATE.format(name=name, title=title),
                force,
            ),
            _write(
                root / "tests" / "fixtures" / "mappings" / f"{name}.json",
                json.dumps(MAPPING_FIXTURE, indent=2) + "\n",
                force,
            ),
        ]
    )


def new_rule(
    name: str,
    product: str = "aws",
    service: str = "cloudtrail",
    root: Path = Path("."),
    force: bool = False,
) -> Written:
    _check(name)
    title = name.replace("_", " ").capitalize()
    fixture = [{"eventName": "ChangeMe", "_repeat": 1}]
    return Written(
        [
            _write(
                root / "content" / "rules" / f"{name}.yaml",
                RULE_TEMPLATE.format(name=name, title=title, product=product, service=service),
                force,
            ),
            _write(
                root / "tests" / "fixtures" / "rules" / name / "positive.json",
                json.dumps(fixture, indent=2) + "\n",
                force,
            ),
            _write(
                root / "tests" / "fixtures" / "rules" / name / "negative.json",
                json.dumps([{"eventName": "SomethingHarmless"}], indent=2) + "\n",
                force,
            ),
        ]
    )
