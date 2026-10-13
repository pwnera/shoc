"""What an audit row says it was about: identifiers, never secrets or free text (SEC-1)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from shoc.db.audit import GENESIS, chain_hash, hash_payload, subject_of

KEY = b"k" * 32
NOW = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


@dataclass
class Change:
    email: str = "ann@example.com"
    role: str = "reader"
    disabled: bool | None = None
    api_key: str = "sk-not-for-the-log"
    signing_secret: str = "also-not"
    base_url: str = "https://hooks.example.com/services/T0/B0/the-key-is-here?x=1"
    note: str = "rotating because Bob said so"
    domains: list[str] = field(default_factory=lambda: ["example.com", "example.net"])
    settings: dict[str, str] = field(default_factory=lambda: {"anything": "x"})


def test_a_subject_names_identifiers_and_masks_secrets_and_free_text():
    said = subject_of(Change(), ["usr_1a2b3c", "a long citation with spaces"])
    assert said is not None
    assert json.loads(said) == {
        "email": "ann@example.com",
        "role": "reader",
        "api_key": "(hidden)",
        "signing_secret": "(hidden)",
        "base_url": "https://hooks.example.com",
        "domains": ["example.com", "example.net"],
        "cites": ["usr_1a2b3c"],
    }
    for leaked in ("sk-not-for-the-log", "also-not", "the-key-is-here", "Bob", "anything"):
        assert leaked not in said


def test_a_sign_in_subject_carries_the_client_address():
    said = subject_of({"method": "password", "from": "203.0.113.7"})
    assert said is not None and json.loads(said) == {"method": "password", "from": "203.0.113.7"}


def test_nothing_to_say_is_no_subject():
    assert subject_of({}) is None
    assert subject_of({"note": "free text only"}) is None


def test_a_row_without_a_subject_hashes_as_rows_did_before_058():
    row = (KEY, GENESIS, "t", NOW, "human:u", "user.update", hash_payload({"x": 1}), None, None)
    before = chain_hash(*row)
    assert chain_hash(*row, None) == before
    # A subject is covered: changing or dropping it changes the hash.
    assert len({before, chain_hash(*row, '{"a": 1}'), chain_hash(*row, '{"a": 2}')}) == 3


def test_a_defanged_url_is_no_subject_and_no_error():
    """`evil[.]example[.]test` reads as a bad IPv6 host and once failed intel.remove."""
    assert subject_of({"value": "hxxps://evil[.]example[.]test/login"}) is None
