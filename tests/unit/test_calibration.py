"""The eval harness calibrates the policy's confidence floor (RFC 0020, AGT-6)."""

from __future__ import annotations

from evals.run import act_threshold


def test_too_few_runs_promise_nothing():
    assert act_threshold([(0.9, True)] * 5, alpha=0.1) is None, "1/(n+1) > alpha"


def test_the_floor_sits_above_the_confident_mistakes():
    right = [(0.95, True)] * 30
    wrong = [(0.6, False), (0.7, False)]
    assert act_threshold(right + wrong, alpha=0.05) == 0.95
    # The risk is of acting and being wrong across all cases, so a looser alpha
    # tolerates the two mistakes rather than raising the floor above them.
    assert act_threshold(right + wrong, alpha=0.1) == 0.6


def test_a_crew_that_is_confidently_wrong_is_never_automatic():
    points = [(0.9, False)] * 10 + [(0.9, True)] * 10
    assert act_threshold(points, alpha=0.1) == 1.01
