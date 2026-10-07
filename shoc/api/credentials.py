"""Passwords, authenticator codes and random secrets for people signing in (SEC-3, RFC 0028).

Standard library only: `hashlib.scrypt` for passwords and RFC 6238 over `hmac`
for the authenticator, so sign-in costs no dependency. Nothing here touches the
database; `shoc.api.people` stores what these functions produce.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import quote, urlencode

from shoc.capabilities.tokens import digest as digest  # sessions and links are hashed like tokens
from shoc.errors import ConfigError, SignInError

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD, MAX_PASSWORD = 12, 256
STEP_SECONDS = 30

# An unknown email is checked against this, so it costs the same scrypt as a known one.
_DUMMY = f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${'00' * 16}${'00' * 32}"


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=32
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${key.hex()}"


def check_password(password: str, stored: str | None) -> bool:
    """Whether `password` matches `stored`; None (no account) still costs one hash."""
    if len(password) > MAX_PASSWORD:
        return False
    _, n, r, p, salt, key = (stored or _DUMMY).split("$")
    match = hmac.compare_digest(
        _scrypt(password, bytes.fromhex(salt), int(n), int(r), int(p)), bytes.fromhex(key)
    )
    return match and stored is not None


def password_problem(password: str, email: str) -> str | None:
    """Why a new password is refused, or None."""
    if len(password) < MIN_PASSWORD:
        return f"a password needs at least {MIN_PASSWORD} characters"
    if len(password) > MAX_PASSWORD:
        return f"a password has at most {MAX_PASSWORD} characters"
    if password.strip().lower() == email.strip().lower():
        return "a password cannot be the email"
    return None


# Password hashing has two threads of its own, so a burst of sign-ins waits
# here instead of taking the threads every other request runs on.
_hashers = ThreadPoolExecutor(max_workers=2, thread_name_prefix="shoc-scrypt")
_waiting = 0
_waiting_lock = threading.Lock()
MAX_WAITING = 16


async def hashing[T](fn: Callable[..., T], *args: Any) -> T:
    """Run `fn` on the hashing threads; 429 when too many are already waiting."""
    global _waiting
    with _waiting_lock:
        if _waiting >= MAX_WAITING:
            raise SignInError("slow_down", 429, "too many sign-ins at once; try again shortly", 5)
        _waiting += 1
    try:
        return await asyncio.get_running_loop().run_in_executor(_hashers, fn, *args)
    finally:
        with _waiting_lock:
            _waiting -= 1


def new_seed() -> bytes:
    return secrets.token_bytes(20)


def link_seed(master_key: str, link: str) -> bytes:
    """The authenticator an enrolling link offers, derived so it is never stored."""
    if not master_key:
        raise ConfigError("SHOC_MASTER_KEY is not set; an authenticator cannot be offered")
    key = hashlib.sha256(b"shoc authenticator\0" + master_key.encode()).digest()
    return hmac.new(key, link.encode(), hashlib.sha256).digest()[:20]


def otpauth(seed: bytes, email: str, issuer: str = "shoc") -> str:
    """The URI an authenticator app reads from the QR code."""
    secret = base64.b32encode(seed).decode().rstrip("=")
    query = urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30}
    )
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?{query}"


def _code(seed: bytes, step: int) -> str:
    mac = hmac.new(seed, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[offset : offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_step(seed: bytes, code: str, now: float, last_step: int) -> int | None:
    """The step `code` belongs to, one step either side of now and above `last_step`.

    The caller stores the step in the same UPDATE that checks it is still above
    the stored one, so a code works once even under concurrent requests.
    """
    if not (len(code) == 6 and code.isascii() and code.isdigit()):
        return None
    current = int(now // STEP_SECONDS)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(_code(seed, step), code):
            return step
    return None


def new_secret(prefix: str) -> str:
    """32 random bytes for a session or a link; only its SHA-256 is kept."""
    return prefix + secrets.token_urlsafe(32)
