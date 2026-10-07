# Governance

shoc is maintainer-led. This document says who decides what, and how someone
becomes one of those people.

## Roles

| Role | How you get it | What you can do |
| --- | --- | --- |
| Contributor | Open a PR or an issue | Propose changes, review informally |
| Reviewer | Sustained, good-quality work in one area, proposed by a maintainer | Review and approve PRs in that area; listed in `CODEOWNERS` |
| Maintainer | A track record of merged work and review, plus a majority vote of existing maintainers | Merge rights, release rights, a vote on RFCs |

Maintainers are listed in [`MAINTAINERS.md`](MAINTAINERS.md). A maintainer who
has been inactive for six months moves to emeritus and can return on request.

## How decisions get made

- **Day to day: lazy consensus.** A PR that satisfies its checks and gets one
  maintainer approval (two in security-sensitive paths) can merge. Anyone may
  ask for more time before a merge.
- **Design changes: an RFC.** Changes to an architecture principle, the public
  contract, the security model or the dependency budget need an RFC in
  [`rfcs/`](rfcs/), open for at least 7 days. Maintainers accept it by majority;
  a maintainer may block with a written technical reason.
- **Disagreements** are resolved in the PR or RFC thread. If that fails, a
  simple majority of maintainers decides, and the reasoning is recorded in
  `docs/decisions.md`.

## Scope control

The architecture principles in `CLAUDE.md` and `docs/architecture.md` are
binding. In particular, adding a required service or exceeding the core
dependency budget always needs an RFC.

## Project direction

The roadmap lives in `docs/prd.md` and on the public project board. Maintainers
review it at the start of each release cycle. Anyone may propose a change to it
in Discussions.

## Foundation

We aim to have maintainers from at least two organisations by v1.0. Moving to a
neutral foundation will be considered after v1.0, and decided by an RFC.
