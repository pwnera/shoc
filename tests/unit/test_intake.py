"""Which reports CTI reads, decided without a model (DET-7, RFC 0029)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shoc.detect import intake

COMPANY = intake.Profile(
    connectors=["entra", "m365", "okta", "github"],
    products=["Microsoft 365", "Entra ID", "Okta", "GitHub"],
    identities=41,
)
NOW = datetime(2026, 10, 5, 12, tzinfo=UTC)


def score(title: str, summary: str = "", categories=(), days: float = 0, grade: int = 0):
    return intake.score(
        title, summary, list(categories), NOW - timedelta(days=days), grade, COMPANY, now=NOW
    )


def test_a_report_about_what_the_company_runs_is_read():
    points, reason = score("AiTM phishing kit steals Microsoft 365 session tokens")
    assert points >= intake.READ
    assert "Microsoft 365" in reason and "adversary-in-the-middle" in reason


def test_a_product_the_company_does_not_run_scores_nothing():
    points, reason = score("New Salesforce login page clone")
    assert points < intake.TRIAGE and "no product we run" in reason


def test_reporting_about_other_targets_is_skipped():
    points, reason = score("PLC firmware backdoor at a water utility", "Industrial ICS espionage")
    assert points < intake.TRIAGE and "about" in reason and "PLC" in reason


def test_a_threat_class_alone_is_the_middle_band():
    points, _ = score("Ransomware affiliate shifts tactics")
    assert intake.TRIAGE <= points < intake.READ


def test_categories_and_grade_count_and_age_costs():
    fresh, _ = score("Weekly notes", categories=["okta", "infostealer"], grade=2)
    stale, reason = score("Weekly notes", categories=["okta", "infostealer"], grade=2, days=6)
    assert fresh - stale == 3 and "6 days old" in reason


def test_the_same_story_from_another_vendor_is_linked():
    earlier = [("RPT-1", "Akira ransomware abuses SonicWall SSL VPN accounts", "")]
    assert intake.same_as("SonicWall SSL VPN flaw exploited by Akira", "", earlier) == "RPT-1"
    two_cves = [("RPT-2", "Patch Tuesday", "CVE-2026-1111 and CVE-2026-2222")]
    assert intake.same_as("Exchange chain", "CVE-2026-1111, CVE-2026-2222", two_cves) == "RPT-2"


def test_short_or_generic_titles_are_not_the_same_story():
    earlier = [("RPT-1", "Post 1", ""), ("RPT-2", "Threat report: new campaign analysis", "")]
    assert intake.same_as("Post 2", "", earlier) == ""
    assert intake.same_as("New campaign analysis of a threat", "", earlier) == ""


def test_the_profile_is_said_in_one_line():
    line = COMPANY.describe()
    assert "41 identities" in line and "Okta" in line
