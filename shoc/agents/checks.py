"""The confidence an action is gated on, measured rather than asked for (RFC 0020).

A model's own confidence is the number the policy used to act on, and it is the
least trustworthy number in the case: verbalised confidence runs high, and it
runs higher after an agent has gathered evidence with tools. So the number the
policy reads is built from two checks that do not ask the Investigator anything:

- **Agreement.** Independent reads of the same dossier, on the cheap model and
  without the Investigator's reasoning, each reach a disposition. So did the
  Investigator before the Challenger spoke. The share that lands on the same
  side as the final verdict — attack or benign — is how settled the case is.
- **Support.** Each claim is shown, with only the events it cites, to a checker
  that does not know the verdict. The share it finds shown by those events is
  how well the verdict stands on its evidence. A claim citing events that do not
  exist is unsupported without asking anybody.

The confidence is the smaller of the Investigator's own number and agreement
times support: a model can lower it, and only the checks can raise it. A check
that cannot run counts as a check that failed, because an action waiting a few
hours for its fallback is cheaper than one run on a verdict nobody checked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from shoc.agents import roles, safety
from shoc.agents.llm import Completion, LLMClient, complete_typed, for_hint

ATTACK = ("malicious", "suspicious")
log = logging.getLogger("shoc.checks")

# What one check call may carry: enough claims to cover a verdict, and every
# event a claim counts. Five events per claim made "twenty reads in two minutes"
# unshowable whatever the reads said; near-identical events are quoted once with
# all their ids (`safety.quote_events`), so a hundred cost little more than one.
MAX_CLAIMS = 12
MAX_EVENTS_PER_CLAIM = 100
# And at most this much of them per claim: twelve claims each quoting the same
# forty distinct discovery calls made one request the provider timed out on (524)
# three times, and a check that does not run counts no claim as shown.
CLAIM_CHARS = 12_000

CHECKER = safety.system_prompt(
    "You check claims against log records for a small company's SOC. Each claim "
    "is shown with the events it cites and nothing else: you do not know what the "
    "case concluded and you must not guess. A claim is supported only when those "
    "events on their own show it. When they do not show it, it is unsupported, "
    "even if it may be true. When they show otherwise, it is contradicted. Judge "
    "every claim, and judge each one only on its own events. Events that differ "
    "only in their id, time and some raw values are shown once, with every id in "
    "`event_uids`, the first and last time, and a sample of the values that differ: "
    "count them from that list."
)


def side(verdict: str) -> str:
    return "attack" if verdict in ATTACK else "benign"


@dataclass
class Confidence:
    value: float = 0.0
    stated: float = 0.0
    agree: int = 0
    reads: int = 0
    supported: int = 0
    checked: int = 0
    struck: list[str] = field(default_factory=list)
    # What each struck claim cited, in the same order: a claim citing the wrong
    # event and a checker refusing a true one read the same without it.
    struck_cited: list[list[str]] = field(default_factory=list)
    check_failed: bool = False
    usage: Completion = field(default_factory=Completion)

    def note(self, verdict: str) -> str:
        """What the number is made of, for the openspace."""
        shown = (
            "the claim check could not run, so no claim counts as shown"
            if self.check_failed
            else f"{self.supported} of {self.checked} claim(s) are shown by the events they cite"
        )
        said = (
            f"Confidence {self.value:.2f}: {self.agree} of {self.reads} read(s), the "
            f"Investigator's own included, reach the {side(verdict)} side; {shown}; the "
            f"Investigator said {self.stated:.2f}."
        )
        if self.struck:
            said += (
                " Not shown by their events: "
                + "; ".join(
                    f"{says} [cited: {', '.join(self._cited(i)[:4]) or 'nothing'}]"
                    for i, says in enumerate(self.struck[:3])
                )
                + "."
            )
        return said

    def _cited(self, i: int) -> list[str]:
        return self.struck_cited[i] if i < len(self.struck_cited) else []


def reads(
    client: LLMClient, dossier: str, samples: int, config: Any, hint: str = "cheap"
) -> tuple[list[str], Completion]:
    """Independent dispositions from the dossier alone, on the cheap model by default."""
    cheap = for_hint(client, hint, config)
    bill = Completion(model=getattr(cheap, "model", ""))
    out: list[str] = []
    prompt = (
        f"{dossier}\n\nRead this case on your own. You have no tools in this read "
        "and nobody else's view of it: give the disposition the evidence above "
        "supports."
    )
    system = safety.system_prompt(roles.INVESTIGATOR.prompt)
    for _ in range(max(0, samples)):
        try:
            read, usage = complete_typed(
                cheap,
                system,
                prompt,
                roles.ReadOutput,
                int(getattr(config, "llm_max_tokens", 16000) or 16000),
            )
        except Exception:  # a read that failed is not a vote either way
            continue
        bill = bill.plus(usage)
        if read.verdict:  # a read that names no disposition is not a vote
            out.append(read.verdict)
    return out, bill


def check_claims(
    client: LLMClient, store: Any, tenant_id: str, claims: list[Any], config: Any
) -> tuple[list[bool | None], Completion]:
    """For each claim, whether the events it cites show it; None when the check failed."""
    from shoc.agents.dossier import _events

    claims = claims[:MAX_CLAIMS]
    shown: list[list[dict[str, Any]]] = []
    for claim in claims:
        cited = [str(c) for c in (getattr(claim, "citations", None) or [])][:MAX_EVENTS_PER_CLAIM]
        try:
            shown.append(
                _events(store, tenant_id, cited, raw=True, limit=MAX_EVENTS_PER_CLAIM)
                if cited
                else []
            )
        except Exception:
            shown.append([])
    verdicts: list[bool | None] = [False] * len(claims)
    asked = [i for i, events in enumerate(shown) if events]
    if not asked:
        return verdicts, Completion()
    parts = []
    for i in asked:
        parts += [
            f"Claim {i}:",
            safety.quote("claim", str(getattr(claims[i], "says", ""))),
            f"Events cited by claim {i}:",
            safety.quote_events(shown[i], limit=MAX_EVENTS_PER_CLAIM, chars=CLAIM_CHARS),
            "",
        ]
    cheap = for_hint(client, "cheap", config)
    try:
        answer, usage = complete_typed(
            cheap,
            CHECKER,
            "\n".join(parts),
            roles.ClaimChecks,
            int(getattr(config, "llm_max_tokens", 16000) or 16000),
        )
    except Exception as exc:
        # The check did not run: that is not "0 of 12 shown", and saying so
        # matters because the number becomes the case's confidence.
        log.warning("the claim check could not run: %s: %s", type(exc).__name__, exc)
        return [None] * len(claims), Completion()
    for check in answer.checks:
        if 0 <= check.claim < len(verdicts) and check.claim in asked:
            verdicts[check.claim] = check.support == "supported"
    return verdicts, usage


def derive(
    client: LLMClient,
    store: Any,
    tenant_id: str,
    dossier: str,
    investigation: Any,
    earlier: list[str],
    config: Any,
) -> Confidence:
    """The confidence the policy acts on, and what it is made of."""
    verdict = str(investigation.verdict)
    samples = int(getattr(config, "crew_samples", 2) or 0)
    sampled, bill = reads(client, dossier, samples, config)
    votes = [*earlier, verdict, *sampled]
    claims = list(getattr(investigation, "claims", None) or [])
    shown, usage = check_claims(client, store, tenant_id, claims, config)
    agree = sum(1 for v in votes if side(v) == side(verdict))
    failed = bool(shown) and all(ok is None for ok in shown)
    supported = sum(1 for ok in shown if ok)
    checked = 0 if failed else len(shown)
    stated = max(0.0, min(1.0, float(investigation.confidence or 0.0)))
    measured = (agree / len(votes)) * (supported / checked if checked else 0.0)
    return Confidence(
        value=round(min(stated, measured), 2),
        stated=stated,
        agree=agree,
        reads=len(votes),
        supported=supported,
        checked=checked,
        check_failed=failed,
        struck=[str(c.says) for c, ok in zip(claims, shown, strict=False) if ok is False],
        struck_cited=[
            [str(u) for u in (c.citations or [])]
            for c, ok in zip(claims, shown, strict=False)
            if ok is False
        ],
        usage=bill.plus(usage),
    )
