"""The name every worker session carries, which `jobs.requeue_stale` reads (D147)."""

from __future__ import annotations

import subprocess
import sys

from tests.support import ROOT

# A restarted container: the same hostname, and shoc as PID 1 again.
RESTARTED = (
    "import os, socket\n"
    "os.getpid = lambda: 1\n"
    "socket.gethostname = lambda: 'shoc-worker-' + 'x' * 60\n"
    "from shoc.db.pool import PROCESS\n"
    "print(PROCESS)\n"
)


def _name() -> str:
    run = subprocess.run(
        [sys.executable, "-c", RESTARTED], capture_output=True, text=True, check=True, cwd=ROOT
    )
    return run.stdout.strip()


def test_a_restarted_worker_does_not_pass_for_the_one_that_died():
    """hostname:pid repeated, so the dead worker's jobs looked held for half an hour."""
    first, second = _name(), _name()
    assert first != second


def test_the_name_fits_in_an_application_name():
    """Postgres cuts application_name at 63 bytes; a cut name never matches its jobs."""
    assert len(_name().encode()) <= 63
