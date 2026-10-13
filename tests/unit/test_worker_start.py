"""What the worker holds itself to before it claims a job (OPS-1, AGT-1)."""

from __future__ import annotations

import pytest

from shoc import worker
from shoc.agents.llm import CALL_SECONDS
from shoc.agents.openspace import Budget
from shoc.cases.engine import SEVERITY_ORDER
from shoc.config import Config
from shoc.errors import ConfigError


def test_the_longest_crew_job_fits_the_time_a_hung_worker_may_go_unnoticed():
    """The watchdog is the longest crew job plus its calls, so it grows with
    them. Past an hour and a half a hung worker holds the cron lock and its job
    for longer than an absent operator's pages can afford: a budget or
    CALL_SECONDS that grows this far needs the bound reconsidered, not raised."""
    longest = max(Budget.for_case(s, reports=1).max_seconds for s in SEVERITY_ORDER)
    assert longest + 3 * CALL_SECONDS <= worker.HUNG_AFTER_SECONDS <= 90 * 60


@pytest.mark.parametrize("provider", ["none", "", "anthropic", "openai-compatible"])
def test_a_provider_a_client_speaks_starts(provider):
    Config(llm_provider=provider).check_llm_provider()


def test_a_mistyped_provider_stops_the_worker_at_start():
    """It used to raise in the hourly check, only when a source was down (sre-10)."""
    with pytest.raises(ConfigError, match="antropic"):
        Config(llm_provider="antropic").check_llm_provider()
