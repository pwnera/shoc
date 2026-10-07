"""Typed errors. Every surface (REST, MCP, CLI) maps these to its own idiom."""

from __future__ import annotations

from typing import Any


class ShocError(Exception):
    """Base error. `status` is the HTTP status the REST surface should use.

    `code` is what a client branches on; a raise may name a narrower one than
    its class's.
    """

    status = 500
    code = "internal_error"

    def __init__(self, message: str = "", *, code: str = "") -> None:
        super().__init__(message)
        if code:
            self.code = code

    def to_json(self) -> dict[str, Any]:
        """The `error` object REST and MCP answer with."""
        return {"code": self.code, "message": str(self)}


class ValidationError(ShocError):
    status = 400
    code = "validation_error"


class GateRefused(ValidationError):
    """A merge gate refused (D48, RFC 0032, RFC 0033).

    A gate stops at the first step that fails, `stage`, and `reasons` holds
    every reason within it, one per entry, for a client to list.
    """

    code = "gate_refused"

    def __init__(self, reasons: list[str], stage: str = "") -> None:
        super().__init__("not merged: " + "; ".join(reasons))
        self.reasons, self.stage = reasons, stage

    @classmethod
    def unparsed(cls, what: str, exc: Exception) -> GateRefused:
        """`what` does not parse. A missing key is named, not quoted bare."""
        why = f"it has no {exc}" if isinstance(exc, KeyError) else str(exc)
        return cls([f"{what} does not parse: {why}"], "parse")

    def to_json(self) -> dict[str, Any]:
        stage = {"stage": self.stage} if self.stage else {}
        return super().to_json() | {"reasons": self.reasons} | stage


class NotFound(ShocError):
    status = 404
    code = "not_found"


class Conflict(ShocError):
    """What the call would create exists already."""

    status = 409
    code = "conflict"


class Denied(ShocError):
    """Scope, principal or autonomy check failed (SEC-1, principle 5)."""

    status = 403
    code = "denied"


class ConfigError(ShocError):
    status = 500
    code = "config_error"


class StoreError(ShocError):
    status = 502
    code = "store_error"


class UpstreamError(ShocError):
    """A source we pull from refused, failed or could not be reached.

    Ours to report, not ours to fix. It is an error rather than a quiet field on
    a successful answer so that a failed pull exits non-zero in a shell and
    returns a failing status over HTTP.
    """

    status = 502
    code = "upstream_error"


class Unauthenticated(ShocError):
    """No live credential (SEC-1, SEC-3, RFC 0028).

    401 rather than 403, so a client knows to sign in or send a token again
    instead of reporting a missing permission. A session cookie that names no
    live session is `signed_out`; no credential at all, or a bearer token that
    is unknown, expired or revoked, is `unauthenticated`.
    """

    status = 401
    code = "signed_out"


class SignInError(ShocError):
    """An answer from the /auth/* routes, whose code the browser client shows (RFC 0028).

    bad_credentials and bad_code (401), link_expired (410), cross_site (403),
    slow_down (429), payload_too_large (413), sign_in_not_configured (503), and the
    codes an SSO callback redirects with.
    """

    def __init__(
        self, code: str, status: int = 401, message: str = "", retry_after: int = 0
    ) -> None:
        super().__init__(message or code.replace("_", " "), code=code)
        self.status = status
        # Seconds until a 429 is worth trying again, sent as Retry-After.
        self.retry_after = retry_after
