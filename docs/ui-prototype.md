# shoc console prototype (optional client)

The console is not part of the kernel. It lives in [`console/`](https://github.com/pwnera/shoc/tree/main/console/) as an independent project inside this repository: a React + Tailwind client of the public REST API, its `/auth/*` sign-in (RFC 0028) and the event stream, with its own Node toolchain and CI job. It must never call anything the API doesn't expose.

The prototype covers 5 screens. Style: a dense layout with a left sidebar grouped Operate / Program / Platform, a "Search or jump" bar that opens the ⌘K palette (`search`, no model; questions for the crew go to the "Ask the crew ⌘J" chat window, which calls `ask` on every screen) and flat panels on hairlines. The built console follows edition three of its design system, which extends edition two: light by default with a dark mode, four indigo-tinted grounds plus a float ground whose surfaces (palette, chat, menus, dialogs) take the one elevation, Geist for prose and Geist Mono for every label, id and count, 4px corners on controls and 8px on panels. Severity colours are critical red, high orange, medium amber, low zinc; blue marks anything an agent said. The tokens live in [`console/src/tokens/`](https://github.com/pwnera/shoc/tree/main/console/src/tokens/) and the component rules in [`console/src/components/ui/shoc.css`](https://github.com/pwnera/shoc/blob/main/console/src/components/ui/shoc.css), a copy of the design system's `bundle.css`.

The built console has replaced these five. Its rule is that each screen answers one question and each fact has one home: a number or a list is never shown on two screens, and a screen sends you elsewhere for what it does not own. The current list is in [`console/README.md`](https://github.com/pwnera/shoc/blob/main/console/README.md).

## The original five screens

1. **Overview**: the exception report, once the kernel builds one (D52); KPI row (open cases, MTTD, MTTR, % handled by the crew); stacked bar chart "Alerts handled, last 14 days" (closed by crew vs escalated); "Needs you" list (approvals, escalations, source gaps); crew on shift with live status; source health; live activity feed.
2. **Cases**: tabs Open / Needs you / Contained / Closed today with counts; filter bar; table with ID, title, severity, status, crew verdict + confidence bar, owner agent, source, updated.
3. **Case detail**: header (severity, status, rule, ATT&CK technique); Investigator summary with inline evidence citations [E1]…; timeline; **approval card** (Approve and run / Reject / Undo) for an L2 action; playbook progress (7 steps); entities; paging info.
4. **Hunts**: hunt library (scheduled, from CTI brief, saved); plain-language question box; generated query with dialect tabs **Canonical / Databricks SQL / Postgres / Snowflake** (shows the composable backend); results table with the Hunter's read per row; "Save as detection", "Schedule weekly", "Suppress".
5. **Sources and health (MCO)**: KPIs (sources healthy, ingest lag p95, rules healthy, cost vs budget); sources table with last event, events/hour sparkline, parse errors, status and Ops note; rule health (noisy/silent, and what the Detection Engineer merged or reverted); event store card (backend, region, retention, spend, conformance); crew quality (eval scores).

## Rules for building it later

- Every screen maps to capabilities; list them in the component's docstring.
- Live updates come from the SSE event stream, not polling.
- Every agent statement shows its citations and links to the openspace transcript.
- Approvals in the console call the same `action.approve` capability as Slack.
