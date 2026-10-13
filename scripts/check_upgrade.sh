#!/bin/sh
# Upgrade test, a release gate (Phase 0). Migrates an empty database to the
# previous release's schema with that release's own code and fills it the way
# a deployment would (a replayed attack and one worker pass: events, findings,
# a case, schedules, audit rows), so a migration that rewrites rows (025's
# audit seal, 043's credential split) runs against populated tables. Then it
# migrates to this checkout's schema and runs `shoc migrate` once more, failing
# unless the second run applies nothing. Before the first release no tag
# exists, so the test starts from the empty database.
#
# The old release fills tenant `evalupgrade`, which the test suite's live-
# database guard ignores, so the unit and conformance steps that run next on
# the same database are not refused. Needs SHOC_DSN on a database with no
# other tenant's data, `shoc` installed from this checkout, and the tags
# fetched (actions/checkout with fetch-depth: 0).
set -eu

previous=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)
if [ -n "$previous" ]; then
    work=$(mktemp -d)
    git worktree add --detach "$work/src" "$previous"
    python -m venv "$work/venv"
    "$work/venv/bin/pip" install -q "$work/src"
    echo "migrating to the schema of $previous"
    SHOC_TENANT=evalupgrade "$work/venv/bin/shoc" migrate
    echo "filling it with $previous's own code"
    SHOC_TENANT=evalupgrade "$work/venv/bin/shoc" replay --scenario leaked_aws_key
    SHOC_TENANT=evalupgrade SHOC_LLM_PROVIDER=none "$work/venv/bin/shoc" worker --once
    git worktree remove --force "$work/src"
else
    echo "no release before this one: upgrading from an empty database"
fi
shoc migrate
shoc migrate | tee /dev/stderr | grep -q "migrations applied: none"
echo "upgrade test passed"
