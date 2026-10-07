---
rfc: 0029
title: Pick threat reports before reading them, under a daily budget
status: accepted
authors: ["@Rettila"]
created: 2026-10-05
requirements: ["DET-7", "DET-4", "OPS-1"]
supersedes: null
---

# RFC 0029: Pick threat reports before reading them, under a daily budget

## Summary

A report source still queues every new post, but the CTI role no longer reads
the queue front to back. Each item is scored on what the feed already says about
it (title, summary, categories, publication date) against the products this
company has connected, without a model. Items about something the company does
not run are skipped with the reason recorded. Items that repeat a story already
read are linked to it. What remains is read best-first until the tenant's daily
cap is reached: `intel_reports_per_day` (default 5) and `intel_tokens_per_day`
(default 100,000), set with `llm.configure` next to `hunt_tokens_per_day`. Items
in a middle band get a short triage call on the cheap model before the full
read. The full read sees the report's prose with its indicator tables folded
into the pattern list, and no longer calls the Surveyor. shoc also ships a list
of free report sources a person can switch on by name; none is on by default.

## Motivation

RFC 0016 made report sources poll themselves, and bounded each poll at
`max_items` (default 5). There is no bound across sources or across a day. The
worker polls every six hours, so one RSS source can hand the strong model 20
reports a day, and ten sources 200.

On the main instance on 2026-10-05, the four reports read cost 9,844, 10,007,
20,340 and 38,463 tokens (`shoc.intel_reports.tokens`). Three of the four say in
their `relevance` field that the report does not apply here. Two of those were
discarded after the full read: a municipal IIS webshell intrusion (38,463
tokens, part of it spent asking the Surveyor what the company runs until the
peer budget ran out) and a DPRK organisation paper (20,340 tokens). At about
20,000 tokens a report, ten sources at the current cap would spend some 4M
tokens a day, more than the whole crew spent on six of the previous seven days
(0.7M to 7.1M tokens a day on `deepseek-v4-1-flash`). The deployment ran out of
model credit once already (2026-10-04), which stopped case work as well.

Both discarded reports could have been dropped from their titles and feed
summaries. The CTI prompt already says a report about an industrial control
actor "is discarded unread", but nothing runs before the model, so it is read
in full and then discarded.

The third, the Star Blizzard digest, stored 16 domains while its own
`relevance` field says the report does not apply. In `CtiDigestOutput` the model
writes `indicators` and `keep` before it writes `relevance`, so it commits to
keeping before it reasons about it.

Human CTI teams filter first. They keep five to ten priority intelligence
requirements and expand each into search terms: products, adversary types,
techniques (FIRST CTI SIG PIR module; Red Hat's open PIR method). Stirparo
splits requirements into the actors and assets a company cares about, the
systems it runs, and the logs it can see (SANS ISC, "Defining Threat
Intelligence Requirements", 2016). shoc knows the second and third from its
connected sources. We found no published figure for how many reports a small
team reads a day; three to five read properly, out of dozens of headlines, is
our working estimate and the reason for the default cap.

## Guide-level explanation

```bash
# switch on a source from the shipped list, or any RSS/Atom URL
shoc intel configure --preset the_dfir_report
shoc intel configure --feed vendor-blog --parser rss --settings '{"url": "https://blog.example.com/feed"}'

# the daily cap, beside the hunt budget
shoc llm configure --intel-reports-per-day 5 --intel-tokens-per-day 100000

# today's budget, each source's queue, and the presets not yet on
shoc intel list
# what was not read, and why
shoc intel reports --state queue
```

`intel.list` shows the day's budget and, per report source, how many items were
read today and the tokens they cost, and how many wait, were skipped, were
linked to a story already read, or were dropped. `intel.reports --state` lists
the unread items with their reason:

```
skipped     "PLC firmware backdoor in water utilities"   about ICS, PLC
same_story  "Akira affiliate abuses SonicWall SSL VPN"   same story as RPT-91c2…
waiting     "Infostealer logs sold with Okta sessions"   names Okta; infostealer
skipped     "Ransomware webinar next week"               triage: an event announcement
```

In the console, the Intel screen gains "Add source" (a preset or a feed URL, with
the host it will contact), and the feed dialog shows today's counts. The two
budget numbers sit on Health → Spend with the hunt budget.

A person who runs `intel.digest` on a URL is never refused for budget; the read
counts toward the day. Polled items wait when the cap is reached, and so does a
digest an agent or an MCP client asks for: it is queued under `handed-in` with
a score of 10 and `queued: true` in the answer.

## Reference-level explanation

### Polling

`rss` keeps, per entry, `description` or Atom `summary`, `content:encoded` or
Atom `content`, `pubDate` or `published`/`updated`, and `category`. When the
content runs past 6,000 characters it is taken as the report text, so the page
is not fetched a second time. URLs are canonicalised before the URL check:
lower-case host, no fragment, no `utm_*`, `fbclid`, `gclid` or `mc_*` parameters.

An item published more than 7 days ago is not queued. Without that, a new
source listing 50 old posts would take the budget for ten days.

`otx_pulses` and `misp_events` pass their structured fields (OTX `tags`,
`industries`, `targeted_countries`, `adversary`, `malware_families`,
`attack_ids`; MISP tags and galaxies) into scoring.

### Scoring, no model

Each queued item gets a `score` and a `reason` from its title, summary,
categories and structured fields:

- +3 for each product the company has connected that the item names, up to +9.
  The words come from a table beside the connectors (`okta`; `entra`, `azure ad`,
  `microsoft 365`, `office 365`, `exchange online`, `sharepoint`; `google
  workspace`, `gmail`; `aws`, `cloudtrail`, `iam`; `github`, `github actions`;
  and so on for every connector), read from `source.list`.
- +2 for each threat class that hits companies of this size, up to +4:
  infostealer, business email compromise, adversary-in-the-middle, phishing kit,
  OAuth consent, MFA fatigue, session or token theft, ransomware, initial access
  broker, package supply chain.
- −4 for each term that marks reporting about other targets: ICS, SCADA, PLC,
  satellite, telecom core, mobile spyware, embassy, ministry, election.
- +0 to +2 for the source, from its preset grade (primary research 2, CERT
  advisory 1, anything configured by URL 0).
- −1 for every two days since publication.

An item at 3 or more is read. An item at 1 or 2 is triaged. An item at 0 or below
is skipped, and stays in the queue as `skipped` with its reason, so the next poll
does not score it again. These thresholds are starting values; per-item scores
are logged so they can be tuned after two weeks on the main instance.

### Same story, no model

An item is linked rather than read when its title has three or more words in
common with a report read in the last 14 days, and they are at least half of
the shorter title's words (stop words such as "threat" and "campaign" do not
count), or when the two name two or more of the same CVE identifiers. It is
stored as `same_story` with `same_as` set to that report's uid. The check runs
when an item is queued and again just before it is read, so of two items of
the same story waiting together the better-scored one is read and the other is
linked. After the fetch, the existing `raw_sha256` check still catches the same
text under another URL.

### Triage, small model call

For an item in the middle band, the cheap model (`llm_model_cheap`) is given the
title, at most 300 words of summary, the scoring reason and the company profile
below, and answers `read` or `skip` with one sentence why. Input is about 1,500
tokens, most of it the fixed prompt. A skip is recorded like a scoring skip, with
the call's tokens on the queue row; for an item then read, they are added to its
report's tokens. Both count toward the day.

### Reading, full model call

Before the model sees a report:

- `nav`, `header`, `footer`, `aside` and `form` elements are removed with the
  existing `script` and `style`.
- A line where most of the words are values the pattern extraction found (an IOC
  table, a hash list) is dropped from the prose. The values still reach the
  model in `values_found_by_pattern`, which today repeats them.
- The prose is cut at 48,000 characters (about 12,000 tokens) and marked
  truncated.

The digest prompt gains a company profile, computed by query: the connected
products, the number of identities in the last posture snapshot, and the cloud
providers seen. The Surveyor is no longer a peer of the digest; it stays a peer
of CTI's opinion in a case. `CtiDigestOutput` moves `relevance` and `keep`
directly after `summary`, and a report with `keep` false returns no indicators,
techniques or hunts, which also shortens its output.

The model still produces the indicator list, and values it returns that are not
in the report text are still stored `unverified` (D33).

### The daily cap

`agents.llm.BUDGETS` gains `intel_reports_per_day` (5) and
`intel_tokens_per_day` (100,000), stored in the `llm` row like
`hunt_tokens_per_day`. The day is `current_date`. What has been spent today is
the sum of `shoc.intel_reports.tokens` digested today plus the triage tokens on
`shoc.intel_queue`; reports read today are the `intel_reports` rows with a
`source`, plus any digest asked for by an agent or an external agent.

Each `intel.refresh` takes waiting items across all report sources, ordered by
score, and reads each one whose estimated cost (characters / 4 plus 3,000) fits
in the tokens left, until the report count is reached. Per-source `max_items`
stays as a cap per poll, so one busy source cannot take a whole day.

A waiting item not read after 7 days, or that failed three times, is dropped
(today: 30 days). Skipped, linked and dropped rows keep their reason for 30
days, so the next poll neither scores nor reads them again. When an item that
scored 5 or more is dropped for budget, Ops raises `intel.budget_short` with the
count; it goes to the weekly report, not a page (D58).

### Data

Migration 040 adds to `shoc.intel_queue`: `published_at`, `summary`, `score`,
`reason`, `state` (`waiting`, `skipped`, `same_story`, `dropped`), `same_as`,
`tokens`, `triaged_at` and `changed_at`. No new table.

### Report sources shipped by name

`intel.PRESETS` names free sources with a parser, URL and grade.
`intel.configure --preset <name>` fills in the parser and settings, and the
source's name when none is given. None is enabled by default: each is an
outbound connection, and `intel.configure` prints the host it will contact
(D57). `intel.list` names the presets and whether each is configured. The list
is in the appendix.

## Drawbacks

Keyword scoring misses a report that is relevant but does not name a product or
a threat class in its title or summary. The triage band and the source grade
narrow that gap; a skipped item can still be read by hand with `intel.digest`.

Reading best-first means a weaker report can wait days behind stronger ones, and
the 7-day drop loses it. That is the intent, and `intel.budget_short` says when
it happens to items that scored well.

The term tables need upkeep as connectors are added. A connector without terms
scores like a product the company does not run.

## Alternatives

- **A model call on every item's title.** About 1,500 tokens each, on 20 to 30
  items a day, to decide what keyword scoring decides for most of them.
- **A per-source cap only (today).** Ten sources multiply it by ten.
- **SimHash or MinHash for same-story detection.** Catches reworded copies
  better, at the cost of more code; title overlap and shared CVEs cover the
  case of several vendors writing up one campaign, and `raw_sha256` covers
  exact copies.
- **Regex extraction with the model only labelling each value's role** (the
  approach the LANCE and CTINexus papers measure). Removes the planted-indicator
  path and more tokens, but reverses D33. It can be its own RFC.
- **Batch APIs at half price.** The main instance reaches its model through
  kie.ai, and it is not known whether batch pricing passes through.

## Dependency and scope impact

- New dependencies: none. HTML trimming, URL canonicalisation and title overlap
  are standard library.
- New required services: none.
- Public contract changes: `intel.configure` gains optional `preset`, and `feed`
  is no longer required; `llm.configure` and `llm.show` gain
  `intel_reports_per_day` and `intel_tokens_per_day`; `intel.list` gains
  per-source counts, `presets` and `budget`; `intel.reports` gains `state` and
  returns unread items with their reason; `intel.digest` gains `queued`;
  `CtiDigestOutput` field order changes (field names do not); a new stream event
  type, `health.intel.budget_short`.

## Security considerations

Scoring reads feed text, which an attacker can write. The worst a hostile feed
can do with it is score its own items high and spend the day's budget, which the
cap bounds, or score them low, which means they are not read. Feed text reaches
the model only in the triage and digest prompts, inside `safety.quote()`, as
today. Dropping the Surveyor peer removes one place where report text could
steer a call into the company's own data.

## Unresolved questions

- The default cap. Five reports and 100,000 tokens is under 5% of what the main
  instance spends on a typical day; it may be too low for a tenant with many
  connected products.
- Whether the triage band earns its call. If scoring alone gets the read set
  right on the main instance for two weeks, triage can go.
- The abuse.ch terms of use changed on 2025-11-04: free access is "for
  not-for-profit purposes", and "commercial or for-profit needs" may need a
  Spamhaus subscription. The Feodo page still says CC0, commercial use included.
  Whether URLhaus can stay a default feed for a business needs an answer from
  abuse.ch before v0.3.
- OTX's EULA makes it "free to end users for non-commercial use". The `otx` and
  `otx_pulses` parsers should say so where they are configured.

## Adoption and migration

Migration 040 adds columns with defaults; existing queued items are scored on
the next poll. Existing sources keep their names and settings. A tenant that
wants the old behaviour can raise the two budgets.

## Appendix A: report sources shipped by name

Feeds fetched and measured on 2026-10-05 (volume from item dates over 90 days;
"full" means the feed carries the post's text, "teaser" means the page is
fetched). Grade 2 is primary research, 1 a CERT.

| Preset | Feed | Posts a week | Text | Grade | Why it is here |
| --- | --- | --- | --- | --- | --- |
| `microsoft_ti` | microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/ | 2.5 | full | 2 | Entra and Microsoft 365 attacks (AiTM, device-code phishing, ransomware crews); IOCs and KQL in every post sampled; `<category>` tags help scoring |
| `the_dfir_report` | thedfirreport.com/feed/ | 0.25 | teaser | 2 | Whole ransomware intrusions with timelines, IOCs, ATT&CK and Sigma |
| `huntress` | huntress.com/blog/rss.xml | 8, about half marketing | teaser | 2 | Written about companies this size: Microsoft 365 BEC, ransomware |
| `proofpoint` | proofpoint.com/us/threat-insight-blog.xml | 1 | full | 2 | BEC, account takeover, password spraying |
| `push_security` | pushsecurity.com/rss.xml | 1 | full | 2 | Identity and browser attacks: AiTM kits, consent phishing |
| `datadog_security_labs` | securitylabs.datadoghq.com/rss/feed.xml | 1 | teaser | 2 | AWS and GitHub attacks with log-level detail |
| `google_gtig` | cloudblog.withgoogle.com/topics/threat-intelligence/rss/ | 1.1 | full | 2 | SaaS data theft, CI/CD; some nation-state |
| `wiz_research` | wiz.io/feed/tag/research/rss.xml | 2 | teaser | 2 | Cloud and supply-chain incidents |
| `stepsecurity` | stepsecurity.io/blog/rss.xml | 2 | teaser | 2 | GitHub Actions, npm and PyPI compromises, with IOCs |
| `talos` | blog.talosintelligence.com/rss/ | 4.6 | full | 2 | Broad; newsletters and nation-state mixed in, which scoring drops |
| `cert_fr_alerts`, `cert_fr_cti` | cert.ssi.gouv.fr/alerte/feed/ and /cti/feed/ | 0.8 | teaser (PDF) | 1 | Exploited vulnerabilities and ransomware-group reports; Licence Ouverte 2.0 |

With all twelve on, about 26 items a week arrive, under four a day, before
scoring. The cap matters for sources added by URL (a news site posts about eight
a day) and for OTX and MISP.

Left out:

- Unit 42, Elastic Security Labs, Sophos X-Ops, eSentire: lower fit, or the feed
  does not fit the reader (Elastic's feed carries its whole archive, 8 MB, which
  `report.MAX_BYTES` cuts before it parses; Sophos timed out). The others can be
  added by URL.
- Securelist, SentinelLabs, Volexity, Check Point, Zscaler, NCSC UK, CERT-EU:
  mostly nation-state or advisory work for other audiences.
- OTX (EULA: "free to end users for non-commercial use"), Malpedia (CC BY-NC-SA),
  ransomware.live free API ("personal use only"), ORKL (no licence published).
  OTX and MISP stay as parsers a person configures with their own account.
- News aggregators. They rewrite primary research, so reading them spends the
  budget on a second copy of a story.

Vendor blogs mostly publish no licence. shoc stores what it extracts and a link,
and does not republish the text.

## Appendix B: indicator feeds

The same survey checked the indicator side:

- Feodo Tracker's blocklist is close to empty since the Emotet and QakBot
  takedowns: the main instance holds 6 indicators from it. It costs one request
  and stays.
- More than 70% of URLhaus entries are Mirai and Mozi payloads for IoT devices,
  which a company of this size never fetches. The `urlhaus` parser should read
  `csv_recent`, which carries tags, and drop those families. The main instance
  holds 6,661 URLhaus indicators today.
- abuse.ch now says authentication is mandatory for "any Platform services,
  including APIs and feeds". Anonymous downloads still worked on 2026-10-05.
  ThreatFox (`/export/json/recent/`) and MalwareBazaar (`/export/csv/recent/`)
  would be good indicator parsers for infostealers, loaders and C2 frameworks,
  behind the same key and the commercial-use question in Unresolved questions.
- Free, commercial use allowed, worth a `list` source: Emerging Threats
  compromised IPs (GPL-2.0, ET confirms commercial use) and IPsum filtered to
  addresses three or more lists agree on (Unlicense).
- Vendor IOC repositories on GitHub (Cisco-Talos/IOCs CC0, eset/malware-ioc
  BSD-2, DataDog/indicators-of-compromise Apache-2.0, microsoft/mstic, sophoslabs/IoCs)
  publish a report's indicators as files. Fetching the file a report links to
  gives typed indicators without spending model tokens; that is a follow-up.
- Dead or unusable today: C2-Tracker (archived 2026-04), DigitalSide, Botvrij,
  the CIRCL OSINT MISP feed (nothing since 2026-08), the SSLBL IP list, PhishTank
  (registrations closed), ThreatView (junk entries such as `0.0.0.2`), and the
  OpenPhish community feed (non-commercial).
- Tor exits and Spamhaus DROP belong in lookups rather than in the indicator
  store: Tor is context for a sign-in, and DROP lists networks, which the
  indicator matcher does not match. `intel.lookup` already checks Tor exits, and
  RFC 0030 adds DROP.
