#!/bin/sh
# Upgrade test, a release gate (Phase 0). Migrates an empty database to the
# previous release's schema with that release's own code, then to this
# checkout's schema, then runs `shoc migrate` once more and fails unless the
# second run applies nothing. Before the first release no tag exists, so the
# test starts from the empty database.
#
# Needs SHOC_DSN on an empty database, `shoc` installed from this checkout,
# and the tags fetched (actions/checkout with fetch-depth: 0).
set -eu

previous=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)
if [ -n "$previous" ]; then
    work=$(mktemp -d)
    git worktree add --detach "$work/src" "$previous"
    python -m venv "$work/venv"
    "$work/venv/bin/pip" install -q "$work/src"
    echo "migrating to the schema of $previous"
    "$work/venv/bin/shoc" migrate
    git worktree remove --force "$work/src"
else
    echo "no release before this one: upgrading from an empty database"
fi
shoc migrate
shoc migrate | tee /dev/stderr | grep -q "migrations applied: none"
echo "upgrade test passed"
