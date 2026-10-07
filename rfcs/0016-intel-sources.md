---
rfc: 0016
title: Poll reports and indicator lists, and take indicators by hand
status: accepted
authors: ["@Rettila"]
created: 2026-09-28
requirements: ["DET-4", "DET-7", "API-1"]
supersedes: null
---

# RFC 0016: Poll reports and indicator lists, and take indicators by hand

## Summary

Threat intel reaches shoc in three ways, for reports and for indicators alike: a
platform's API polled on the intel schedule, a feed URL polled on the same
schedule, and a single URL or value somebody hands in. Reports gain polled
sources (`rss`, `otx_pulses`, `misp_events`). Indicators gain `list`, a URL
whose page names indicators, and `intel.add` / `intel.remove` for the ones a
person or an assistant hands in or withdraws. An MCP client can hand in
indicators and reports and withdraw indicators without being a human principal;
configuring a source still needs one.

## Motivation

Before this RFC, the ways in were uneven:

| | Polled platform API | Polled feed URL | One URL or value, once |
| --- | --- | --- | --- |
| Indicators | abuse.ch, OTX, MISP | none | none |
| Reports | none | none | `intel.digest` |

An operator who follows a vendor blog had to paste every post into
`intel.digest` by hand. That work only happens while somebody is at the
keyboard, and the operator is usually not there. An indicator from a vendor
email or a peer had no way in at all, short of an SQL insert. And the source
table was keyed by parser, so a tenant could follow one feed of each kind and
never two RSS feeds.

## Guide-level explanation

```bash
# a report source: every new post is read by the CTI role
shoc intel configure --feed vendor-blog --parser rss \
  --settings '{"url": "https://blog.example.com/feed", "max_items": 5}'

# OTX pulses and MISP events as reports, not only as indicator lists
shoc intel configure --feed otx-reports --parser otx_pulses --secret '{"api_key": "…"}'

# an indicator list: any page that names indicators
shoc intel configure --feed partner-blocklist --parser list \
  --settings '{"url": "https://partner.example.com/iocs.txt", "severity": "high"}'

# once, by hand
shoc intel add --values 'hxxps://login-portal.example[.]net/o365' 203.0.113.9
shoc intel add --url https://advisory.example.com/2026-17
shoc intel digest --url https://blog.example.com/2026/09/campaign

# withdraw
shoc intel remove --source manual:human:ana
shoc intel remove --report-uid RPT-4f1a…
```

The same calls are MCP tools (`intel_add`, `intel_remove`, `intel_digest`,
`intel_refresh`, `intel_list`) for the default MCP client. `intel_configure`
appears for a client running as a human principal (`SHOC_MCP_PRINCIPAL=human`).

## Reference-level explanation

**Sources.** `shoc.intel_feeds` gains `parser` (migration 024). The row's `feed`
is now the source's name and `parser` says what it is; an empty parser means the
name is the parser, which is how every existing row reads. `intel.refresh`
polls each enabled source and sends it to one of two tables of parsers:

- `intel.FEEDS` returns indicators: `abuse_ch_feodo`, `abuse_ch_urlhaus`, `otx`,
  `misp`, `list`.
- `intel.REPORT_FEEDS` returns `ReportItem(url, title, text)`: `rss`,
  `otx_pulses`, `misp_events`. An item with text (a pulse, an event) is read
  as it is; an item without (an RSS entry) is fetched first.

A report item whose URL is already in `shoc.intel_reports` is skipped, and at
most `max_items` (default 5) are read per poll, so a busy feed cannot spend
the model budget in one go. A report whose text matches one already read under
another URL is not read again. The retro-hunt runs once after every source.

A default feed that somebody configured as disabled now stays off. Before this
RFC the default list was merged in regardless of the row.

**Precision.** `list` and `intel.add --url` extract with
`report.extract(standalone=True)`: an address or domain that only appears as the
host of a URL is not stored. The URL is stored as a URL. `intel.add` types each
value with `osint.classify` and rejects untyped and internal values.

**Hand-in.** `intel.add` stores under `manual:<kind>:<id>`, or `import:<host>`
for a URL. A human's confidence is taken as given (default 0.8). Any other
caller's is capped at 0.55, below every action floor in `content/policy.yaml`,
on D33's reasoning: an agent may be relaying what log content asked for, so what
it adds is a lead. `intel.remove` deletes by value, by source or by `report_uid`;
findings already raised stay, and a source still polled brings its indicators
back.

**Scopes.** `intel.configure` moves to its own scope, `intel:configure`, and
stays human-only (the v0.4 contract freezes human-only capabilities). The MCP
external agent gains `intel:write`, and `intel.add`, `intel.remove`,
`intel.digest` and `intel.refresh` declare `external_agent`, so the declaration
and the MCP gate agree (`tests/unit/test_permissions.py`).

## Drawbacks

An RSS feed of general security news produces posts that have nothing to do
with the tenant, and each one read costs model tokens. `max_items` bounds the
cost; it does not make the posts relevant.

`list` trusts that the page is a list of bad things. A page that mentions
benign infrastructure in passing is stored as indicators at the source's
confidence.

## Alternatives

- **One capability per source kind** (`intel.rss_add`, …). Seven capabilities
  for what one row with a `parser` column holds.
- **Let an MCP external agent configure sources.** The contract freezes
  human-only capabilities, and a source is standing configuration with
  credentials. An assistant can still hand in the same URL once through
  `intel.add` or `intel.digest`.
- **STIX/TAXII.** A protocol client would be the largest parser here, and the
  platforms our users run (OTX, MISP) are already covered by their own APIs.
  It can come later as another parser.

## Dependency and scope impact

- New dependencies: none. RSS and Atom are parsed with `xml.etree`.
- New required services: none.
- Public contract changes: `intel.add` and `intel.remove` are new;
  `intel.configure` gains optional `parser` and `remove` and moves from
  `intel:write` to `intel:configure`; `intel.refresh` and `intel.digest` add
  `external_agent`. An API token scoped to `intel:write` alone loses
  `intel.configure`; one scoped `intel:*` does not.

## Security considerations

Every fetch goes through `report.guard`: http(s) only, no internal host. RSS is
parsed by ElementTree, which resolves no external entity, on Python 3.12's
expat, which refuses entity-expansion bombs; the body is capped at 8 MB. Report
text reaches the model only inside `safety.quote()`, as it did for a pasted
report. A hostile report source gets what a hostile pasted report gets: its
indicators at 0.35–0.55 under `report:<host>`, removable by `report_uid`. An
MCP client can plant indicators at up to 0.55 and withdraw any indicator; both
are audited, and a withdrawn feed indicator returns on the next poll.

## Unresolved questions

- Whether a report source should be told the tenant's stack so it skips
  irrelevant posts before they reach the model.

## Adoption and migration

Migration 024 adds two columns and an index. Existing sources keep working
under their names. Nothing new is polled until somebody configures it.
