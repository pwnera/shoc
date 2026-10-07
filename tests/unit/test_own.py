"""shoc's own footprint (RFC 0021): the parts that need no database."""

from __future__ import annotations

from shoc.cases import own


def test_a_tailnet_address_is_not_the_internet():
    assert not own.routable("100.64.0.1")
    assert not own.routable("10.0.0.1")
    assert own.routable("198.51.100.7"), "documentation ranges stand for the internet here"


def test_an_entity_key_and_the_account_are_the_same_value():
    assert own.bare("user:alice@example.com") == "alice@example.com"
    assert own.bare("ip:203.0.113.5") == "203.0.113.5"
    assert own.bare("https://example.com") == "https://example.com"


def test_scopes_are_read_from_named_parameters_and_keys():
    raw = {
        "events": [
            {
                "parameters": [
                    {"name": "client_id", "value": "1"},
                    {"name": "scope", "multiValue": ["https://mail.google.com/", "openid"]},
                ]
            }
        ],
        "token": {"scopes": "read write"},
    }
    assert own.scopes_of(raw) == {"https://mail.google.com/", "openid", "read", "write"}
