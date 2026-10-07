"""The autonomy policy (RSP-3).

YAML, evaluated in code, no policy engine (decision D6). The policy answers one
question — *may this action run now, and who has to say yes?* — and it answers
it the same way for an agent, a human and a playbook.

The rules it enforces:

- every action has an autonomy level: L0 notify, L1 automatic, L2 human
- an agent can never exceed its principal ceiling, and never approves L2
- an L0 action, or any action from a principal whose ceiling is L0, is refused
- an L1 action must be reversible, confident enough and severe enough
- guarded targets (admins, production roles) are never automatic
- a case with no cited evidence gets no automatic action at all
- an action that blocks an address, a domain, a URL or a hash, or one marked
  `research_before_action`, may not run automatically until the target has been
  researched, and never against shared infrastructure or our own egress (RSP-5)
- the same blocking actions, and any marked `review_before_action`, may not run
  automatically until the crew has reviewed it and nobody objected (RSP-6)
- a crew proposal whose blast radius is unanswered, uncited or shared
  infrastructure may not run automatically (D45)

These gates only ever make an action harder to take. None can raise an action's
autonomy or approve an L2, and on an L2 their objections are put in front of
the human who decides.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shoc.errors import ConfigError

LEVELS = ("L0", "L1", "L2")


def _rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")

# What a block is aimed at. An action on one of these is researched and reviewed
# unless its rule turns the gate off: a wrong block takes the company offline.
BLOCKS = ("ip", "domain", "url", "hash")


@dataclass
class Research:
    """What research found about an action's target (RSP-5).

    `shoc.detect.osint.Research` converts into this; the policy stays free of
    the lookup machinery so it can be reasoned about — and tested — on its own.
    """

    done: bool = False
    verdict: str = "unknown"
    owner: str = ""
    shared_infrastructure: bool = False
    summary: str = ""

    @classmethod
    def of(cls, research: Any) -> Research:
        if research is None:
            return cls()
        return cls(
            done=True,
            verdict=str(getattr(research, "verdict", "unknown")),
            owner=str(getattr(research, "owner", "")),
            shared_infrastructure=bool(getattr(research, "shared_infrastructure", False)),
            summary=str(getattr(research, "summary", "")),
        )


@dataclass
class Review:
    """What the crew said about the action (RSP-6). See `shoc.cases.review`."""

    done: bool = False
    approved: bool = False
    reason: str = ""

    @classmethod
    def of(cls, review: Any) -> Review:
        if review is None:
            return cls()
        return cls(
            done=bool(getattr(review, "done", False)),
            approved=bool(getattr(review, "approved", False)),
            reason=str(getattr(review, "reason", "")),
        )


@dataclass
class Decision:
    """What the policy says about one proposed action."""

    allowed: bool
    autonomy: str = "L2"
    needs_approval: bool = True
    dry_run: bool = True
    reason: str = ""
    escalated_by: list[str] = field(default_factory=list)
    # How long the action stays in force before it is undone, from its rule.
    ttl_minutes: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "autonomy": self.autonomy,
            "needs_approval": self.needs_approval,
            "dry_run": self.dry_run,
            "reason": self.reason,
            "escalated_by": self.escalated_by,
        }


@dataclass
class Policy:
    version: int = 1
    defaults: dict[str, Any] = field(default_factory=dict)
    principals: dict[str, str] = field(default_factory=dict)
    actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    guards: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> Policy:
        data = yaml.safe_load(path.read_text()) or {}
        policy = cls(
            version=int(data.get("version", 1)),
            defaults=data.get("defaults", {}) or {},
            principals=data.get("principals", {}) or {},
            actions=data.get("actions", {}) or {},
            guards=data.get("guards", {}) or {},
            path=path,
        )
        policy.validate()
        return policy

    @classmethod
    def load(cls, config: Any = None) -> Policy:
        from shoc.config import Config

        cfg = config or Config.load()
        path = Path(cfg.content_dir) / "policy.yaml"
        if not path.exists():
            raise ConfigError(f"no autonomy policy at {path}")
        return cls.from_file(path)

    def validate(self) -> None:
        for name, rule in self.actions.items():
            level = rule.get("autonomy", self.defaults.get("autonomy", "L2"))
            if level not in LEVELS:
                raise ConfigError(f"policy: action '{name}' has autonomy '{level}'")
            if level == "L1" and not rule.get("reversible", False):
                raise ConfigError(
                    f"policy: '{name}' is L1 but not reversible — only reversible actions "
                    "may run automatically"
                )
        for name in self.guards.get("known_egress", []) or []:
            if not isinstance(name, str):
                raise ConfigError("policy: guards.known_egress must be a list of addresses")
        for principal, level in self.principals.items():
            if level not in LEVELS:
                raise ConfigError(f"policy: principal '{principal}' has autonomy '{level}'")

    # -- evaluation ------------------------------------------------------
    def rule_for(self, action_type: str) -> dict[str, Any]:
        rule = dict(self.defaults)
        rule.update(self.actions.get(action_type, {}))
        return rule

    def ceiling(self, principal_kind: str) -> str:
        return self.principals.get(principal_kind, "L0")

    def gated(self, action_type: str, target_kind: str) -> tuple[bool, bool]:
        """Whether this action is researched first, and whether it is reviewed first."""
        rule = self.actions.get(action_type, {})
        block = target_kind in BLOCKS
        return (
            bool(rule.get("research_before_action", block)),
            bool(rule.get("review_before_action", block)),
        )

    def is_protected(self, kind: str, target: str) -> bool:
        subject = f"{kind}:{target}".lower()
        return any(
            fnmatch.fnmatch(subject, pattern.lower())
            for pattern in self.guards.get("protected_targets", [])
        )

    def decide(
        self,
        action_type: str,
        *,
        principal_kind: str = "agent",
        target_kind: str = "",
        target: str = "",
        confidence: float = 0.0,
        severity: str = "medium",
        has_citations: bool = True,
        grounded: bool = True,
        auto_actions_so_far: int = 0,
        dry_run_default: bool | None = None,
        research: Any = None,
        review: Any = None,
        blast_radius: dict[str, Any] | None = None,
        egress: tuple[str, ...] = (),
    ) -> Decision:
        """Decide whether this action may run, and whether a human must approve it.

        `blast_radius` is the Commander's count of who else the action touches;
        None means nobody was asked, as for a playbook step. `egress` adds the
        tenant's own recorded addresses to `guards.known_egress`.
        """
        if action_type not in self.actions:
            return Decision(
                allowed=False,
                reason=f"'{action_type}' is not in the policy; add it before proposing it",
            )
        rule = self.rule_for(action_type)
        level = str(rule.get("autonomy", "L2"))
        reversible = bool(rule.get("reversible", False))
        dry_run = bool(
            dry_run_default if dry_run_default is not None else rule.get("dry_run", True)
        )

        # L0 takes no action: not automatically, and not after an approval either.
        # A principal whose ceiling is L0 may notify, so its proposal is refused
        # rather than turned into an L2 a human could approve on its behalf.
        ceiling = self.ceiling(principal_kind)
        if "L0" in (level, ceiling):
            return Decision(
                allowed=False,
                autonomy="L0",
                dry_run=dry_run,
                reason=f"{action_type} is notify-only (L0)"
                if level == "L0"
                else f"a {principal_kind or 'caller'} may notify but never act (L0)",
            )
        if _rank(level) > _rank(ceiling):
            level = "L2"  # the principal cannot act at this level; a human must

        reasons: list[str] = []
        escalated: list[str] = []
        if self.guards.get("require_citations", True) and not has_citations:
            return Decision(
                allowed=False,
                autonomy="L2",
                dry_run=dry_run,
                reason="the case cites no events, so no action may be taken on it",
            )
        if self.is_protected(target_kind, target):
            reasons.append(f"{target_kind}:{target} is a protected target")
            level = "L2"
        if level == "L1":
            # A target the case's evidence never showed is one a log line could
            # have supplied. It may still be the right target; a person says so.
            if not grounded:
                reasons.append(
                    f"{target or 'the target'} does not appear in the evidence this case cites"
                )
                level = "L2"
            floor = float(rule.get("min_confidence", 0.0))
            if confidence < floor:
                reasons.append(f"confidence {confidence:.2f} is below {floor:.2f}")
                level = "L2"
            least = str(rule.get("severity_at_least", "informational"))
            if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(least):
                reasons.append(f"severity {severity} is below {least}")
                level = "L2"
            if not reversible:
                reasons.append("the action is not reversible")
                level = "L2"
            # A notification tells a person; it changes nothing in the world, so it
            # is not what the cap on automatic actions is counting. Capping it put
            # the page itself behind an approval, which is a page nobody receives.
            cap = int(self.guards.get("max_auto_actions_per_case", 3))
            if auto_actions_so_far >= cap and not action_type.startswith("notify."):
                reasons.append(f"this case already ran {auto_actions_so_far} automatic action(s)")
                level = "L2"
        # The gates run on an L2 too: a human deciding it sees the objections.
        researched, reviewed = self.gated(action_type, target_kind)
        gates = self._gates(researched, reviewed, target, research, review, egress)
        gates += _blast(blast_radius, target)
        if gates:
            reasons.extend(gates)
            escalated = [
                name
                for name, on in (
                    ("research", researched),
                    ("review", reviewed),
                    ("blast_radius", blast_radius is not None),
                )
                if on
            ]
            level = "L2"

        return Decision(
            allowed=True,
            autonomy=level,
            needs_approval=level == "L2",
            dry_run=dry_run,
            reason="; ".join(reasons) or ("automatic" if level == "L1" else "needs a human"),
            escalated_by=escalated,
            ttl_minutes=int(rule.get("ttl_minutes") or 0),
        )

    def _gates(
        self,
        researched: bool,
        reviewed: bool,
        target: str,
        research: Any,
        review: Any,
        own: tuple[str, ...] = (),
    ) -> list[str]:
        """RSP-5 and RSP-6: what must be true before this runs on its own."""
        out: list[str] = []
        if researched:
            found = Research.of(research)
            egress = [str(e) for e in (self.guards.get("known_egress", []) or [])] + list(own)
            if not found.done:
                out.append(
                    f"{target or 'the target'} has not been researched, and this action "
                    "may not run automatically against an unresearched target"
                )
            elif any(fnmatch.fnmatch(target.lower(), e.lower()) for e in egress):
                out.append(
                    f"{target} is one of our own known egress addresses; acting on it "
                    "would cut off our own people"
                )
            elif found.shared_infrastructure:
                out.append(
                    f"{target} is shared infrastructure"
                    + (f" ({found.owner})" if found.owner else "")
                    + ", so acting on it affects everyone behind it, not just the attacker"
                )
            elif found.verdict not in ("malicious", "suspicious"):
                out.append(
                    f"research came back '{found.verdict}' for {target}, which is not "
                    "enough to act on it automatically"
                )
        if reviewed:
            said = Review.of(review)
            if not said.done:
                out.append(said.reason or "the crew has not reviewed this action")
            elif not said.approved:
                out.append(said.reason or "the crew did not approve this action")
        return out


def _blast(blast: dict[str, Any] | None, target: str) -> list[str]:
    """D45: a crew proposal's blast radius, counted and cited, or it does not run alone."""
    if blast is None:
        return []
    counted = blast.get("principals")
    count = -1 if counted is None else int(counted)
    if count < 0:
        return [
            f"nobody counted who else is behind {target or 'the target'}, "
            "and an unanswered blast radius refuses the action"
        ]
    if count and not blast.get("citations"):
        return [f"the blast radius of {target} ({count} principal(s)) cites no events"]
    shared = str(blast.get("shared_infrastructure") or "").strip()
    if shared:
        return [f"{target} is shared infrastructure ({shared}), by the crew's own count"]
    return []
