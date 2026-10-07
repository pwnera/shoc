"""Dataclasses in, JSON Schema out (decision D6: no pydantic).

The capability registry derives every public schema from a dataclass, so REST
bodies, the OpenAPI document, MCP tool inputs and CLI flags all describe exactly
the same type. `coerce` is the inverse: an untrusted JSON object becomes a
validated dataclass instance, or raises ValidationError.
"""

from __future__ import annotations

import dataclasses
import functools
import operator
import types
import typing
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, Literal, Union, get_args, get_origin
from uuid import UUID

from shoc.errors import ValidationError

_PRIMITIVES: dict[type, dict[str, Any]] = {
    str: {"type": "string"},
    bool: {"type": "boolean"},
    int: {"type": "integer"},
    float: {"type": "number"},
    datetime: {"type": "string", "format": "date-time"},
}


def _is_optional(tp: Any) -> tuple[bool, Any]:
    origin = get_origin(tp)
    if origin is Union or origin is types.UnionType:
        args = [a for a in get_args(tp) if a is not type(None)]
        if len(args) != len(get_args(tp)):
            return True, args[0] if len(args) == 1 else functools.reduce(operator.or_, args)
    return False, tp


def schema_of(tp: Any) -> dict[str, Any]:
    """JSON Schema for a type annotation."""
    optional, tp = _is_optional(tp)
    out = _schema_of_required(tp)
    if optional:
        out = {"anyOf": [out, {"type": "null"}]}
    return out


def _schema_of_required(tp: Any) -> dict[str, Any]:
    if tp in _PRIMITIVES:
        return dict(_PRIMITIVES[tp])
    if tp is Any:
        return {}
    origin = get_origin(tp)
    if origin is list:
        (item,) = get_args(tp) or (Any,)
        return {"type": "array", "items": schema_of(item)}
    if origin is dict:
        args = get_args(tp)
        value = args[1] if len(args) == 2 else Any
        return {"type": "object", "additionalProperties": schema_of(value)}
    if origin is Literal:
        values = list(get_args(tp))
        kind = "string" if all(isinstance(v, str) for v in values) else "integer"
        return {"type": kind, "enum": values}
    if dataclasses.is_dataclass(tp):
        return dataclass_schema(tp)  # type: ignore[arg-type]
    return {}


def dataclass_schema(cls: type) -> dict[str, Any]:
    props: dict[str, Any] = {}
    required: list[str] = []
    hints = typing.get_type_hints(cls)
    for field in dataclasses.fields(cls):
        tp = hints.get(field.name, Any)
        sch = schema_of(tp)
        doc = (field.metadata or {}).get("doc")
        if doc:
            sch = {**sch, "description": doc}
        props[field.name] = sch
        if field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING:  # type: ignore[misc]
            required.append(field.name)
    out: dict[str, Any] = {
        "type": "object",
        "title": cls.__name__,
        "properties": props,
        "additionalProperties": False,
    }
    if required:
        out["required"] = required
    # Without a docstring, @dataclass writes the signature there
    # ("RemoveReport(removed: 'int' = 0)"): a repr, not a description.
    if cls.__doc__ and not cls.__doc__.startswith(cls.__name__ + "("):
        out["description"] = cls.__doc__.strip().splitlines()[0]
    return out


def field(default: Any = dataclasses.MISSING, *, doc: str = "", factory: Any = dataclasses.MISSING):
    """`dataclasses.field` with a `doc` that reaches the generated schema."""
    kw: dict[str, Any] = {"metadata": {"doc": doc}}
    if factory is not dataclasses.MISSING:
        kw["default_factory"] = factory
    elif default is not dataclasses.MISSING:
        kw["default"] = default
    return dataclasses.field(**kw)


def coerce(tp: Any, value: Any, path: str = "$", strict: bool = True) -> Any:
    """Validate and convert an untrusted JSON value into `tp`.

    `strict=False` drops object fields the type does not have instead of
    refusing them: for a model's answer, whose schema is the contract and whose
    extra field is noise, not for a caller's input.
    """
    optional, tp = _is_optional(tp)
    if value is None:
        if optional:
            return None
        raise ValidationError(f"{path}: must not be null")
    if tp is Any:
        return value
    origin = get_origin(tp)
    if tp is datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError(f"{path}: not an ISO-8601 timestamp") from exc
        raise ValidationError(f"{path}: expected a timestamp")
    if tp is bool:
        if isinstance(value, bool):
            return value
        raise ValidationError(f"{path}: expected a boolean")
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{path}: expected an integer")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{path}: expected a number")
        return float(value)
    if tp is str:
        if not isinstance(value, str):
            raise ValidationError(f"{path}: expected a string")
        return value
    if origin is Literal:
        if value not in get_args(tp):
            raise ValidationError(f"{path}: expected one of {list(get_args(tp))}")
        return value
    if origin is list:
        if not isinstance(value, list):
            raise ValidationError(f"{path}: expected an array")
        (item,) = get_args(tp) or (Any,)
        return [coerce(item, v, f"{path}[{i}]", strict) for i, v in enumerate(value)]
    if origin is dict:
        if not isinstance(value, dict):
            raise ValidationError(f"{path}: expected an object")
        args = get_args(tp)
        vt = args[1] if len(args) == 2 else Any
        return {str(k): coerce(vt, v, f"{path}.{k}", strict) for k, v in value.items()}
    if dataclasses.is_dataclass(tp):
        return coerce_dataclass(tp, value, path, strict)  # type: ignore[arg-type]
    return value


def coerce_dataclass(cls: type, value: Any, path: str = "$", strict: bool = True) -> Any:
    if isinstance(value, cls):
        return value
    if not isinstance(value, dict):
        raise ValidationError(f"{path}: expected an object")
    hints = typing.get_type_hints(cls)
    names = {f.name for f in dataclasses.fields(cls)}
    unknown = set(value) - names
    if unknown and strict:
        raise ValidationError(f"{path}: unknown field(s): {', '.join(sorted(unknown))}")
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        if f.name in value:
            kwargs[f.name] = coerce(
                hints.get(f.name, Any), value[f.name], f"{path}.{f.name}", strict
            )
        elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:  # type: ignore[misc]
            raise ValidationError(f"{path}: missing required field '{f.name}'")
    return cls(**kwargs)


def to_json(value: Any) -> Any:
    """Everything the database and the code produce, down to JSON values.

    Postgres hands back `Decimal` for `numeric` and for `sum()` over integers,
    and `date`/`UUID`/`Memoryview` for their own types. None of those survive
    `json.dumps`, and the response envelope is a public contract, so they are
    converted here rather than at each call site.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: to_json(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        # A count or a cost. float is what a JSON client expects; the exact
        # value is still in the database for anything that needs it.
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, dict):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json(v) for v in value]
    return value
