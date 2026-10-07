"""Which credentials an action acts with: the platform and the tenant (RSP-4, RFC 0025)."""

from __future__ import annotations

import pytest

from shoc.cases.credentials import Instance, accounts_of, check_name, choose, overlap
from shoc.errors import ValidationError

PROD = Instance.of("aws", {"accounts": ["111111111111"]})
STAGING = Instance.of("aws:staging", {"accounts": "222222222222"})


def test_one_credential_answers_wherever_it_can_act():
    # The install every company starts with: one credential, no accounts named.
    alone = [Instance.of("aws", {})]
    assert choose(alone, "aws", {("aws", "111111111111")}) == (["aws"], [])
    assert choose(alone, "aws", set()) == (["aws"], [])


def test_a_legacy_credential_is_renamed_after_the_vendor_it_spoke_to():
    """Migration 043 (RFC 0031) reads the vendor as the old `idp` and `edr` code did."""
    from shoc.cases.credentials import _legacy_vendor

    assert _legacy_vendor("idp", {"org_url": "https://acme.okta.com"}) == "okta"
    assert _legacy_vendor("idp", {}) == "entra"
    assert _legacy_vendor("idp", {"flavour": "entra", "org_url": "x"}) == "entra"
    assert _legacy_vendor("edr", {"flavour": "SentinelOne"}) == "sentinelone"
    assert _legacy_vendor("edr", {}) == ""  # never worked: left for a person
    assert _legacy_vendor("waf", {"account_id": "a"}) == "cloudflare"


def test_the_account_the_target_was_seen_in_decides_the_tenant():
    both = [PROD, STAGING]
    assert choose(both, "aws", {("aws", "222222222222")}) == (["aws:staging"], [])
    assert choose(both, "aws", {("aws", "111111111111")}) == (["aws"], [])


def test_a_target_seen_in_two_tenants_is_answered_in_both():
    chosen, gaps = choose(
        [PROD, STAGING], "aws", {("aws", "111111111111"), ("aws", "222222222222")}
    )
    assert chosen == ["aws", "aws:staging"] and gaps == []


def test_an_account_no_credential_names_goes_to_the_one_that_names_none():
    default = Instance.of("aws", {})
    assert choose([default, STAGING], "aws", {("aws", "333333333333")}) == (["aws"], [])
    assert choose([default, STAGING], "aws", {("aws", "222222222222")}) == (["aws:staging"], [])


def test_shoc_never_acts_in_an_account_it_has_no_credential_for():
    chosen, gaps = choose([PROD, STAGING], "aws", {("aws", "333333333333")})
    assert chosen == [] and gaps == ["no aws credentials act in aws account 333333333333"]


def test_a_place_it_cannot_tell_apart_is_said_not_guessed():
    # Two credentials, and events that never named an account.
    chosen, gaps = choose([PROD, STAGING], "aws", {("aws", "")})
    assert chosen == [] and "aws, aws:staging could each act in aws" in gaps[0]


def test_an_unknown_account_is_dropped_when_the_platform_has_a_known_one():
    # A hunt's finding that carried no account does not make a known one ambiguous.
    chosen, gaps = choose([PROD, STAGING], "aws", {("aws", ""), ("aws", "222222222222")})
    assert chosen == ["aws:staging"] and gaps == []


def test_a_named_credential_narrows_and_never_widens():
    assert choose([PROD, STAGING], "aws", {("aws", "")}, "aws:staging") == (["aws:staging"], [])
    # A name written into a log cannot send the action to the other tenant.
    chosen, gaps = choose([PROD, STAGING], "aws", {("aws", "111111111111")}, "aws:staging")
    assert chosen == [] and gaps


def test_two_credentials_that_could_both_claim_a_target_are_refused():
    assert overlap([Instance.of("aws", {}), Instance.of("aws:b", {})])
    assert overlap([PROD, Instance.of("aws:b", {"accounts": ["111111111111"]})])
    assert not overlap([PROD, STAGING])
    assert not overlap([Instance.of("aws", {}), STAGING])  # a default and a named one


def test_accounts_are_read_as_a_list_of_strings():
    assert accounts_of({"accounts": "123"}) == ("123",)
    assert accounts_of({"accounts": [123, " 456 ", ""]}) == ("123", "456")
    assert accounts_of({}) == ()


def test_a_credential_is_named_like_a_source():
    check_name("aws")
    check_name("aws:staging")
    check_name("okta")
    with pytest.raises(ValidationError, match="unknown provider"):
        check_name("idp")  # the provider is the vendor (RFC 0031)
    with pytest.raises(ValidationError, match="provider:label"):
        check_name("aws:Prod Account")


def test_every_connector_names_the_credential_that_acts_on_what_it_reads():
    # A platform shoc can see and not act on is an incomplete integration (D56).
    from shoc.actions import load
    from shoc.actions.base import NEEDS, RESPONDS
    from shoc.ingest import connectors

    for name in [*connectors.available(), *connectors.push_sources()]:
        assert name in RESPONDS, f"{name}: say which response credential acts on it"
        for provider in RESPONDS[name]:
            assert provider in NEEDS, f"{name}: no {provider} in NEEDS"
    for action in load().values():
        assert action.provider in NEEDS, f"{action.type}: say what {action.provider} needs"
        assert NEEDS[action.provider].secret and NEEDS[action.provider].grant


def test_what_a_credential_still_lacks():
    from shoc.cases.credentials import missing

    assert missing("aws", {}, {"access_key_id": "a", "secret_access_key": "b"}) == []
    assert missing("aws:prod", {}, {"access_key_id": "a"}) == ["secret_access_key"]
    assert missing("okta", {}, {"api_token": "t"}) == ["org_url"]
    assert missing("entra:emea", {}, {}) == ["tenant_id", "client_id", "client_secret"]
    assert missing("sentinelone", {}, {"api_token": "t"}) == ["console_url"]
    # A static key stands in for an OAuth client.
    assert missing("tailscale", {}, {"api_key": "k"}) == []
