"""Every documented command runs as written, and the prose's numbers are the code's (OPS-G8).

Each KNOWN holds what breaks its rule today, and why. A new violation fails,
and so does an entry that no longer breaks the rule, so a list only shrinks.
"""

from __future__ import annotations

import contextlib
import io
import re
import shlex
from collections.abc import Iterator
from functools import cache

import pytest

from tests.support import ROOT

DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
SHELL = {"bash", "sh", "shell", "console"}
FENCE = re.compile(r"^\s*```\s*([\w-]*)")
OPERATOR = re.compile(r"^[();<>|&]+$")
SERVICES = {"shoc", "migrate"}
# `docker compose run` and `exec` options that take a value.
VALUED = {"-e", "--env", "-v", "--volume", "-w", "--workdir", "-u", "--user", "--name", "-p"}


def _ratchet(found: dict[str, str], known: dict[str, str], rule: str) -> None:
    new = sorted(set(found) - set(known))
    assert not new, f"{rule}:\n" + "\n".join(f"  {found[key]}" for key in new)
    gone = sorted(set(known) - set(found))
    assert not gone, f"no longer breaks '{rule}'; take out of KNOWN: {', '.join(gone)}"


def _blocks(lang: set[str]) -> Iterator[tuple[str, int, list[str]]]:
    """Each fenced block of one of these languages: file, first line, its lines."""
    for path in DOCS:
        rel = path.relative_to(ROOT).as_posix()
        block: list[str] | None = None
        start, kind = 0, ""
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if m := FENCE.match(line):
                if block is not None and kind in lang:
                    yield rel, start, block
                if block is None:
                    block, start, kind = [], number + 1, m.group(1).lower()
                else:
                    block = None
            elif block is not None:
                block.append(line)


def _commands() -> Iterator[tuple[str, int, list[str]]]:
    """Each shell line of the docs, continuations joined, as words cut at the
    first pipe or redirection."""
    for rel, start, lines in _blocks(SHELL):
        index = 0
        while index < len(lines):
            number, line = start + index, lines[index]
            while line.rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                line = line.rstrip()[:-1] + " " + lines[index].strip()
            index += 1
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            try:
                words = list(lexer)
            except ValueError:  # an unclosed quote: not a command line
                continue
            cut = next((i for i, w in enumerate(words) if OPERATOR.match(w)), len(words))
            if words[:cut]:
                yield rel, number, words[:cut]


def _shoc_args(words: list[str]) -> list[str] | None:
    """What a line hands `shoc`: bare, through `docker compose run <service>`, or
    `docker compose exec <service> shoc`. None for any other command."""
    if words[0] == "shoc":
        return words[1:]
    if words[:2] != ["docker", "compose"] or len(words) < 4 or words[2] not in ("run", "exec"):
        return None
    index = 3
    while index < len(words) and words[index].startswith("-"):
        if words[index] == "--entrypoint":
            return None  # runs another program in the image
        index += 2 if words[index] in VALUED else 1
    if index >= len(words) or words[index] not in SERVICES:
        return None
    rest = words[index + 1 :]
    if words[2] == "run":
        # The image's entrypoint is `shoc`; with no words, the service's own command runs.
        return rest or None
    return rest[1:] if rest[:1] == ["shoc"] else None


def _documented() -> Iterator[tuple[str, int, list[str]]]:
    for rel, number, words in _commands():
        args = _shoc_args(words)
        if args is not None:
            yield rel, number, args


def _key(rel: str, args: list[str]) -> str:
    """`docs/x.md:shoc case get`: the file and the command's words, its flags left out."""
    rest = list(args)
    while rest and (rest[0] in ("--tenant", "--json") or rest[0].startswith("--tenant=")):
        rest = rest[2:] if rest[0] == "--tenant" else rest[1:]
    words: list[str] = []
    for word in rest:
        if word.startswith("-") or len(words) == 2:
            break
        words.append(word)
    return f"{rel}:shoc {' '.join(words)}"


@cache
def _parser():
    from shoc.cli import build_parser

    return build_parser()


KNOWN_UNPARSED = {
    "docs/agents.md:shoc memory add-fact": "found by this test: the CLI word is add_fact",
    "docs/connectors.md:shoc source push-key": "found by this test: the CLI word is push_key",
    "docs/response.md:shoc playbook run": "found by this test: --dry-run takes no value "
    "(--dry-run or --no-dry-run)",
}


def test_every_documented_command_parses():
    """OPS-G8: every shoc command in README.md and docs/ parses with shoc.cli.build_parser."""
    found = {}
    seen = 0
    for rel, number, args in _documented():
        seen += 1
        said = io.StringIO()
        try:
            with contextlib.redirect_stderr(said):
                _parser().parse_args(args)
        except SystemExit as exc:
            if exc.code:
                error = said.getvalue().strip().splitlines()[-1:] or ["no message"]
                found[_key(rel, args)] = f"{rel}:{number} shoc {' '.join(args)}: {error[0]}"
    assert seen > 50, "the docs' shell blocks were not read"
    _ratchet(found, KNOWN_UNPARSED, "a documented command parses")


KNOWN_TENANTLESS_REPLAYS = {
    "README.md:shoc replay": "the showcase above the quick start; replay refuses a tenant "
    "that reads live sources without --force",
    "docs/index.md:shoc replay": "the same showcase",
}


def test_a_demo_replay_names_its_tenant():
    """OPS-G8: a documented replay names its own --tenant, never the production one."""
    found = {
        _key(rel, args): f"{rel}:{number} shoc {' '.join(args)} names no --tenant"
        for rel, number, args in _documented()
        if "replay" in args and not any(w == "--tenant" or w.startswith("--tenant=") for w in args)
    }
    _ratchet(found, KNOWN_TENANTLESS_REPLAYS, "a demo replay names its tenant")


SECRET_FLAGS = {"--secret", "--bot-token", "--signing-secret", "--api-key", "--password"}


def test_no_secret_on_a_documented_command_line():
    """OPS-G8: no documented command puts a credential on its command line."""
    for rel, number, args in _documented():
        for index, word in enumerate(args):
            flag, eq, _ = word.partition("=")
            if flag in SECRET_FLAGS and (eq or index + 1 < len(args)):
                pytest.fail(
                    f"{rel}:{number} passes {flag} on the command line, where it lands in "
                    f"shell history and the process list; use {flag}-file - or secret_env"
                )


SECRET_ENV = ("SHOC_MASTER_KEY", "SHOC_LLM_API_KEY", "SHOC_TOKENS")
DSN_PASSWORD = re.compile(r"://[^:/@\s\"]+:[^@\s\"]+@")

KNOWN_MCP_SECRETS = {
    "docs/quickstart.md:SHOC_MASTER_KEY": "the checkout variant runs shoc mcp itself, which "
    "needs the key to write the audit log; the Compose variant above carries none",
    "docs/quickstart.md:SHOC_DSN": "the same checkout variant, with the runtime role's password",
}


def test_no_secret_in_a_documented_mcp_client_config():
    """OPS-G8: an MCP client config in the docs carries no secret."""
    found = {}
    for rel, start, lines in _blocks({"json", "jsonc", ""}):
        text = "\n".join(lines)
        if "mcpServers" not in text:
            continue
        for name in SECRET_ENV:
            if f'"{name}"' in text:
                found[f"{rel}:{name}"] = f"{rel}:{start} puts {name} in an MCP client's config"
        if DSN_PASSWORD.search(text):
            found[f"{rel}:SHOC_DSN"] = f"{rel}:{start} puts a database password in an MCP config"
    _ratchet(found, KNOWN_MCP_SECRETS, "an MCP client config carries no secret")


def _counts(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    from shoc.cases import playbooks
    from shoc.config import Config
    from shoc.detect import rules
    from shoc.ingest import connectors

    monkeypatch.delenv("SHOC_CYCLE_SECONDS", raising=False)
    monkeypatch.delenv("SHOC_CONTENT_DIR", raising=False)
    cycle = Config().cycle_seconds
    return {
        "cycle_seconds": cycle,
        "cycle_minutes": cycle // 60,
        "rules": len(rules.load()),
        "playbooks": len(playbooks.load()),
        "connectors": len(connectors.available()),
    }


# (file, the sentence with the number as its group, which code count it states)
FACTS = [
    ("README.md", r"a detection cycle every (\d+) minutes by default", "cycle_minutes"),
    ("README.md", r"(\d+) rules mapped to ATT&CK", "rules"),
    ("README.md", r"a playbook for every rule \((\d+) ship", "playbooks"),
    ("docs/operations.md", r"\| (\d+) minutes \(`SHOC_CYCLE_SECONDS`\) \|", "cycle_minutes"),
    ("docs/deploy.md", r"\| `SHOC_CYCLE_SECONDS` \|[^|]*\(default (\d+)\) \|", "cycle_seconds"),
    ("docs/deploy.md", r"suits the (\d+)-minute cycle", "cycle_minutes"),
    ("docs/ontology.md", r"once a detection cycle \((\d+) minutes by default\)", "cycle_minutes"),
    ("docs/ontology.md", r"one playbook\. (\d+) ship\.", "rules"),
    ("docs/ontology.md", r"response steps \(RFC 0013\)\. (\d+) ship\.", "playbooks"),
    ("docs/ontology.md", r"(\d+) connectors ship", "connectors"),
]

KNOWN_STALE_NUMBERS = {
    "docs/ontology.md:rules": "found by this test: says 268",
    "docs/ontology.md:playbooks": "found by this test: says 38",
}


def test_documented_numbers_match_the_code(monkeypatch: pytest.MonkeyPatch):
    """OPS-G8: each count, cadence or default the prose states is the code's."""
    counts = _counts(monkeypatch)
    found = {}
    for rel, pattern, fact in FACTS:
        text = " ".join((ROOT / rel).read_text().split())
        m = re.search(pattern, text)
        assert m, f"{rel} no longer says /{pattern}/; update FACTS to where it says it now"
        if int(m.group(1)) != counts[fact]:
            found[f"{rel}:{fact}"] = f"{rel} says {m.group(1)} {fact}; the code has {counts[fact]}"
    _ratchet(found, KNOWN_STALE_NUMBERS, "a documented number is the code's")
