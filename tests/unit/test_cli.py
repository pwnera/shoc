"""The CLI is generated, so these tests check the generation, not each command."""

from __future__ import annotations

import pytest

from shoc.capabilities.registry import get
from shoc.cli import _payload, build_parser


def test_every_capability_gets_a_command():
    parser = build_parser()
    args = parser.parse_args(["events", "query", "--since=-1h", "--limit", "5"])
    payload = _payload(get("events.query"), args, ["since"])
    assert payload["since"] == "-1h" and payload["limit"] == 5


def test_a_single_required_field_can_be_positional():
    args = build_parser().parse_args(["ask", "what happened?"])
    assert _payload(get("ask"), args, ["question"])["question"] == "what happened?"


def test_the_flag_wins_over_an_absent_positional():
    args = build_parser().parse_args(["source", "configure", "--source", "okta"])
    assert _payload(get("source.configure"), args, ["source"])["source"] == "okta"


def test_dict_flags_take_json():
    args = build_parser().parse_args(
        ["source", "configure", "--source", "okta", "--settings", '{"org_url": "https://x"}']
    )
    payload = _payload(get("source.configure"), args, ["source"])
    assert payload["settings"] == {"org_url": "https://x"}


def test_a_dict_read_from_a_file_may_be_yaml(tmp_path):
    """A playbook in content/ is YAML; `--playbook-file` takes it as it is (RFC 0033)."""
    book = tmp_path / "ours.yaml"
    book.write_text("id: ours\nrules:\n  - okta_mfa_push_fatigue\n")
    args = build_parser().parse_args(["playbook", "merge", "--playbook-file", str(book)])
    payload = _payload(get("playbook.merge"), args, [])
    assert payload["playbook"] == {"id": "ours", "rules": ["okta_mfa_push_fatigue"]}


def test_a_bool_flag_has_a_no_form_that_help_shows(capsys):
    args = build_parser().parse_args(
        ["user", "update", "--email", "b@example.com", "--no-disabled"]
    )
    assert _payload(get("user.update"), args, ["email"])["disabled"] is False
    unset = build_parser().parse_args(["user", "update", "--email", "b@example.com"])
    assert "disabled" not in _payload(get("user.update"), unset, ["email"])
    with pytest.raises(SystemExit):
        build_parser().parse_args(["user", "update", "--help"])
    assert "--no-disabled" in capsys.readouterr().out


def test_json_input_is_merged_under_the_flags():
    args = build_parser().parse_args(
        ["events", "query", "--json-input", '{"since": "-2h", "limit": 9}', "--limit", "3"]
    )
    payload = _payload(get("events.query"), args, ["since"])
    assert payload == {"since": "-2h", "limit": 3}


def test_unknown_command_exits():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["nope"])


def test_every_capability_command_parses():
    """The CLI is generated, so a bad schema shows up as a parser that cannot run."""
    import dataclasses

    from shoc.capabilities.registry import all_capabilities

    parser = build_parser()
    for cap in all_capabilities():
        words = list(cap.cli_words)
        flags: list[str] = []
        for field in dataclasses.fields(cap.input):
            required = (
                field.default is dataclasses.MISSING
                and field.default_factory is dataclasses.MISSING  # type: ignore[misc]
            )
            if required:
                flags += [f"--{field.name.replace('_', '-')}", "x"]
        args = parser.parse_args([*words, *flags])
        assert args.func is not None, f"{cap.name} has no runner"


def test_the_process_commands_exist():
    parser = build_parser()
    for words in (
        ["migrate"],
        ["serve"],
        ["worker", "--once"],
        ["mcp"],
        ["keygen"],
        ["rotate-key"],
        ["grant-readonly"],
        ["rules", "check"],
        ["plan"],
        ["apply", "-y"],
        ["init-config"],
        ["new", "rule", "x"],
        ["replay", "okta", "f.json"],
        ["replay", "--scenario", "leaked_aws_key", "--force"],
    ):
        assert parser.parse_args(words).func is not None


def test_help_mentions_the_generated_groups(capsys):
    parser = build_parser()
    parser.print_help()
    text = capsys.readouterr().out
    for group in ("events", "finding", "case", "action", "playbook", "intel"):
        assert group in text


def test_json_and_tenant_go_before_or_after_the_command():
    """The quick start says `--json` gives the full envelope; after the command it was refused."""
    parser = build_parser()
    after = parser.parse_args(["finding", "list", "--json", "--tenant", "lab"])
    assert after.json is True and after.tenant == "lab"
    before = parser.parse_args(["--json", "--tenant", "lab", "replay", "--scenario", "x"])
    assert before.json is True and before.tenant == "lab", "a flag left out after keeps it"
    neither = parser.parse_args(["finding", "list"])
    assert neither.json is False and neither.tenant is None


def test_the_audit_log_names_whoever_runs_the_cli(monkeypatch):
    from shoc.cli import cli_caller

    monkeypatch.delenv("SHOC_CLI_USER", raising=False)
    assert cli_caller().id == "cli"
    monkeypatch.setenv("SHOC_CLI_USER", "sam@example.com")
    assert cli_caller().id == "cli:sam@example.com"


def test_an_unreachable_database_is_one_line_without_the_password(monkeypatch, capsys):
    import psycopg

    from shoc.cli import main
    from shoc.db import secrets

    def refused():
        # psycopg 3.2 on a name with several addresses: the first line names no host.
        raise psycopg.OperationalError(
            "Multiple connection attempts failed. All failures were:\n"
            "- host: 'db.example', port: '5432', hostaddr: '192.0.2.10': "
            "connection failed: Connection refused"
        )

    monkeypatch.setenv("SHOC_DSN", "postgresql://shoc:hunter2@192.0.2.10:5432/shoc")
    monkeypatch.setattr(secrets, "generate_key", refused)
    assert main(["keygen"]) == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Traceback" not in err
    assert "192.0.2.10:5432" in err and "Connection refused" in err and "SHOC_DSN" in err
    assert "hunter2" not in err


def test_one_host_names_the_cause_not_libpqs_hint(monkeypatch, capsys):
    import psycopg

    from shoc.cli import main
    from shoc.db import secrets

    def refused():
        raise psycopg.OperationalError(
            'connection to server at "192.0.2.10", port 5432 failed: Connection refused\n'
            "\tIs the server running on that host and accepting TCP/IP connections?"
        )

    monkeypatch.setenv("SHOC_DSN", "postgresql://shoc:hunter2@192.0.2.10:5432/shoc")
    monkeypatch.setattr(secrets, "generate_key", refused)
    assert main(["keygen"]) == 1
    err = capsys.readouterr().err
    assert "(Connection refused)" in err and "Is the server running" not in err
