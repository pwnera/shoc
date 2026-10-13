"""Which failed model calls still mean the provider answered (AGT-1, OPS-1)."""

from __future__ import annotations

import pytest

from shoc.agents.ops import SCHEMA_FAILURE


@pytest.mark.parametrize(
    "reason",
    [
        "ValidationError: $.verdict: expected one of ['malicious', 'benign']",
        "Hunter: ValidationError: $.outcomes: expected an array",
        "ValueError: the model did not return JSON: Expecting value",
    ],
)
def test_a_reply_that_did_not_fit_its_schema_came_back(reason):
    assert SCHEMA_FAILURE.search(reason)


@pytest.mark.parametrize(
    "reason",
    [
        "ConfigError: https://gateway.example returned no completion: code 500",
        "UpstreamError: code 402 after 2s",
        "Investigator: ReadTimeout: timed out",
        "ValueError: invalid literal for int()",
    ],
)
def test_a_call_that_never_came_back_is_a_failure(reason):
    assert not SCHEMA_FAILURE.search(reason)
