"""The OCSF table layout, identical on every backend (STO-1, ING-3).

Flattened core columns cover what every source has in common; a field only one
product emits stays in `raw` (and, if no mapping read it, in `unmapped`) and is
addressed by its source path — `raw.debugContext.debugData.dtHash`. This list is
part of the public contract: adding a column is a minor release, removing one is
a major.
"""

from __future__ import annotations

import functools
import re
from typing import Any

# (column, portable type). Adapters translate the type to their dialect.
COLUMNS: list[tuple[str, str]] = [
    ("tenant_id", "TEXT"),
    ("event_uid", "TEXT"),
    ("time", "TIMESTAMPTZ"),
    ("class_uid", "INTEGER"),
    ("class_name", "TEXT"),
    ("category_uid", "INTEGER"),
    ("activity_id", "INTEGER"),
    ("activity_name", "TEXT"),
    ("type_uid", "INTEGER"),
    ("severity_id", "INTEGER"),
    ("status", "TEXT"),
    ("status_code", "TEXT"),
    ("message", "TEXT"),
    ("actor_user_name", "TEXT"),
    ("actor_user_uid", "TEXT"),
    ("actor_user_type", "TEXT"),
    ("actor_session_uid", "TEXT"),
    ("actor_invoked_by", "TEXT"),
    ("src_endpoint_ip", "TEXT"),
    ("src_endpoint_domain", "TEXT"),
    ("src_endpoint_location_country", "TEXT"),
    ("src_endpoint_asn", "TEXT"),
    ("src_endpoint_port", "INTEGER"),
    ("dst_endpoint_ip", "TEXT"),
    ("dst_endpoint_port", "INTEGER"),
    ("dst_endpoint_domain", "TEXT"),
    ("dns_query_hostname", "TEXT"),
    ("http_request_url", "TEXT"),
    ("http_user_agent", "TEXT"),
    ("api_operation", "TEXT"),
    ("api_service_name", "TEXT"),
    ("api_response_code", "INTEGER"),
    ("api_response_error", "TEXT"),
    ("cloud_provider", "TEXT"),
    ("cloud_account_uid", "TEXT"),
    ("cloud_region", "TEXT"),
    ("resource_type", "TEXT"),
    ("resource_uid", "TEXT"),
    ("device_hostname", "TEXT"),
    ("device_uid", "TEXT"),
    ("process_name", "TEXT"),
    ("process_pid", "INTEGER"),
    ("process_cmd_line", "TEXT"),
    ("process_hash_sha256", "TEXT"),
    ("process_parent_name", "TEXT"),
    ("process_file_path", "TEXT"),
    ("file_path", "TEXT"),
    ("file_hash_sha256", "TEXT"),
    ("metadata_product", "TEXT"),
    ("metadata_version", "TEXT"),
    ("metadata_profiles", "TEXT"),
    ("observables", "JSON"),
    ("unmapped", "JSON"),
    ("raw", "JSON"),
    ("ingested_at", "TIMESTAMPTZ"),
]

COLUMN_NAMES: list[str] = [c for c, _ in COLUMNS]
JSON_COLUMNS: set[str] = {c for c, t in COLUMNS if t == "JSON"}
INT_COLUMNS: set[str] = {c for c, t in COLUMNS if t == "INTEGER"}

EVENTS_TABLE = "ocsf_events"

# OCSF dotted paths used by rules, mapped to the flattened columns above.
FIELD_MAP: dict[str, str] = {
    "time": "time",
    "class_uid": "class_uid",
    "class_name": "class_name",
    "category_uid": "category_uid",
    "activity_id": "activity_id",
    "activity_name": "activity_name",
    "severity_id": "severity_id",
    "status": "status",
    "status_code": "status_code",
    "message": "message",
    "actor.user.name": "actor_user_name",
    "actor.user.uid": "actor_user_uid",
    "actor.user.type": "actor_user_type",
    "actor.session.uid": "actor_session_uid",
    "actor.invoked_by": "actor_invoked_by",
    "src_endpoint.ip": "src_endpoint_ip",
    "src_endpoint.domain": "src_endpoint_domain",
    "src_endpoint.location.country": "src_endpoint_location_country",
    "src_endpoint.asn": "src_endpoint_asn",
    "src_endpoint.port": "src_endpoint_port",
    "dst_endpoint.ip": "dst_endpoint_ip",
    "dst_endpoint.port": "dst_endpoint_port",
    "dst_endpoint.domain": "dst_endpoint_domain",
    "query.hostname": "dns_query_hostname",
    "http_request.url.url_string": "http_request_url",
    "http_request.user_agent": "http_user_agent",
    "api.operation": "api_operation",
    "api.service.name": "api_service_name",
    "api.response.code": "api_response_code",
    "api.response.error": "api_response_error",
    "cloud.provider": "cloud_provider",
    "cloud.account.uid": "cloud_account_uid",
    "cloud.region": "cloud_region",
    "resource.type": "resource_type",
    "resource.uid": "resource_uid",
    "device.hostname": "device_hostname",
    "device.uid": "device_uid",
    "process.name": "process_name",
    "process.pid": "process_pid",
    "process.cmd_line": "process_cmd_line",
    "process.file.hashes.sha256": "process_hash_sha256",
    "process.parent_process.name": "process_parent_name",
    "process.file.path": "process_file_path",
    "file.path": "file_path",
    "file.hashes.sha256": "file_hash_sha256",
    "metadata.product.name": "metadata_product",
    "metadata.version": "metadata_version",
    "event_uid": "event_uid",
}


# A rule's logsource narrows it to the products that can produce those events.
# Without this, `api.operation|contains: secret` written for GitHub would also
# match CloudTrail's GetSecretValue.
@functools.cache
def products() -> dict[tuple[str, str], tuple[str, ...]]:
    """(logsource product, service) -> the `metadata.product.name` values it
    covers, read from the mappings: each answers to every `product` or
    `product/service` it lists under `logsource`, or to its own source name when
    it lists none, so a new product is one mapping file (ING-4)."""
    from shoc.ingest import ocsf as mappings

    found: dict[tuple[str, str], list[str]] = {}
    for source in mappings.available_sources():
        mapping = mappings.load_mapping(source)
        name = str(mapping.constants.get("metadata_product") or "")
        for key in mapping.logsource or [source]:
            product, _, service = key.lower().partition("/")
            if name not in found.setdefault((product, service), []):
                found[product, service].append(name)
    return {key: tuple(names) for key, names in found.items()}


def products_for(product: str, service: str = "") -> tuple[str, ...]:
    """Which `metadata.product.name` values a logsource covers; none for a
    product no mapping answers to."""
    known = products()
    key = (product.lower(), service.lower())
    return known.get(key) or known.get((product.lower(), ""), ())


# `raw.<path>` and `unmapped.<path>` reach a source-specific field. The
# character class is the whole guard against injection: a path that could close
# the SQL string literal does not match, so it resolves to nothing.
JSON_FIELD = re.compile(r"^(raw|unmapped)((?:\.[A-Za-z0-9_@$-]+)+)$")


def column_for(field: str) -> str | None:
    """Resolve an OCSF dotted path, a column name, or a `raw.…` source path."""
    if field in FIELD_MAP:
        return FIELD_MAP[field]
    if field in COLUMN_NAMES:
        return field
    m = JSON_FIELD.match(field)
    if m:
        return f"JSON_EXTRACT_SCALAR({m.group(1)}, '${_json_path(m.group(2))}')"
    return None


def _json_path(path: str) -> str:
    """`.a.x-amz-acl` as `.a["x-amz-acl"]`: SQLGlot's JSON path reads a bare `-`,
    `@` or `$` as an operator, and the bracket form translates on every dialect."""
    return "".join(
        f".{key}" if re.fullmatch(r"\w+", key, re.ASCII) else f'["{key}"]'
        for key in path[1:].split(".")
    )


def alias_for(field: str) -> str | None:
    """The key a field lands under in a result row.

    Backends lower-case unquoted identifiers, so the alias is lower-cased here
    too and a row is read the same way on every adapter.
    """
    m = JSON_FIELD.match(field)
    if m:
        return re.sub(r"[^A-Za-z0-9_]", "_", m.group(1) + m.group(2)).lower()
    return column_for(field)


def blank_row(tenant_id: str) -> dict[str, Any]:
    row: dict[str, Any] = dict.fromkeys(COLUMN_NAMES)
    row["tenant_id"] = tenant_id
    row["observables"] = []
    row["unmapped"] = {}
    row["raw"] = {}
    return row
