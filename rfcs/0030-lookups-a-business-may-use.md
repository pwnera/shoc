---
rfc: 0030
title: Look indicators up in sources a business may use, and fix the lookups that fail
status: accepted
authors: ["@Rettila"]
created: 2026-10-05
requirements: ["DET-6", "DET-4", "RSP-5"]
supersedes: null
---

# RFC 0030: Look indicators up in sources a business may use, and fix the lookups that fail

## Summary

`intel.lookup` answers most questions from lists shoc downloads once a day and
keeps in memory: who routes an address (ASN and country), whether it is a cloud,
CDN, VPN or hosting range, whether Spamhaus lists its network, and whether a
value is on a known-benign list. None of these sends the value anywhere.
Sources that need an account become opt-in, with a key the company configures,
a daily quota shoc keeps under, and a run only for a case's observables. Three
lookups that give wrong answers today are fixed: ThreatFox and URLhaus fail on
every call, a URL is judged by its host's record, and RDAP can report an old
domain as registered last week. Sources whose free tier forbids business use are
not offered.

## Motivation

On the main instance on 2026-10-05, `intel.lookup` on any value records
`threatfox` and `urlhaus` as failed with `401 Unauthorized`. abuse.ch has
required an `Auth-Key` header on its APIs since 2025-06-30; `osint.py` sends
none. Its bulk downloads still answer without one, which is why the Feodo and
URLhaus feeds look healthy while the lookups behind every case are blind.

`threatfox()` and `urlhaus_host()` query `host_of(value, kind)`. For a URL that
is its host, and a hit on the host makes the URL `malicious` at weight 4. A
payload on a shared host or a compromised site then condemns every URL there,
which is the derivation DET-4 forbids for indicators.

`rdap()` takes the first of `registration` or `last changed` as the registration
date. When a registry lists `last changed` first, a ten-year-old domain updated
last week scores `suspicious, registered 6 day(s) ago`. It also calls rdap.org,
which allows "a maximum of 10 requests in 10 seconds".

`cloud_ranges()` knows AWS, GCP and Cloudflare. It does not know Azure, where a
company on Microsoft 365 sees most of its shared addresses, nor Oracle, Fastly,
GitHub or DigitalOcean. D35 relies on this answer to stop an automatic block on
shared infrastructure.

`report.NOISE_DOMAINS` is 22 hand-picked domains doing the job the MISP
warninglists (CC0, over 120 lists of resolvers, CDNs, cloud ranges and common
false positives) already do.

The keyed platforms the module's docstring names as next (VirusTotal,
AbuseIPDB, GreyNoise, Shodan, urlscan) mostly forbid business use on their free
tiers. A survey of terms on 2026-10-05 found:

| Service | Free tier says |
| --- | --- |
| VirusTotal public API | "must not be used in commercial products or services" |
| AbuseIPDB free | "You may not use Free plans for commercial purposes" |
| urlscan.io | commercial use "requires express written permission" |
| Shodan InternetDB | "free for non-commercial use" |
| Google Safe Browsing | "for non-commercial use only" |
| AlienVault OTX | "free to end users for non-commercial use" |
| GreyNoise Community | 50 lookups a week with a business email |

Every company running shoc is a business, so shipping these as free defaults
would put the company in breach of terms it never read.

## Guide-level explanation

```bash
shoc intel lookup 20.190.151.7
# nothing conclusive is known about 20.190.151.7: it is shared infrastructure (Azure); …
# [9 source(s) answered, 5 from downloaded lists]

# a keyed source, configured once by a person
shoc intel configure --lookup abuse_ch --secret '{"auth_key": "…"}'
shoc intel configure --lookup ipapi_is --secret '{"key": "…"}' --settings '{"per_day": 800}'
```

Each observation in an `intel.lookup` answer says whether it came from a
downloaded list (`listed`). `intel.list` lists each keyed source, whether it is
configured, and today's calls against its quota.

## Reference-level explanation

### Local lists

Each list is one download, refreshed daily (DB-IP weekly, for a monthly file,
and Tor every six hours), held per process like the Tor and cloud lists were.
The worker's intel job starts loading them in a background thread, so the job
queue never waits on a download and the digest can hold back warninglisted
values once they are in; any process that has not loaded one loads it on its
first lookup. Networks are found by longest prefix; DB-IP's ranges are kept as
sorted integer arrays (`array` and `bisect`), about 10 MB per process for the
ASN and country tables.

| List | Answers | Refresh | Licence |
| --- | --- | --- | --- |
| DB-IP IP-to-ASN Lite and IP-to-Country Lite (CSV) | ASN, AS name, country; with ASN-DROP, a criminal AS | monthly | CC BY 4.0 |
| Cloud ranges: AWS, GCP, Cloudflare (today), Azure Service Tags, Oracle, Fastly, GitHub `meta`, DigitalOcean | provider, region, service | daily | published by each provider |
| X4BNet `lists_vpn` (vpn, datacenter) | VPN or hosting range | daily | MIT |
| Spamhaus DROP and ASN-DROP (JSON) | hijacked or criminal netblock | daily | free for any business, keep the header |
| Tor bulk exit list (today) | Tor exit | 6 hours | Tor Project |
| MISP warninglists, selected lists | known-benign value | daily | CC0 |
| disposable-email-domains | disposable mail domain | daily | CC0 |

A cloud, CDN, VPN or datacenter match sets `shared_infrastructure`, so D35 keeps
an automatic block on it at L2. A cloud range says the address is someone's
tenant, not that it is benign; the observation's verdict stays
`informational`.

The warninglists are a lookup source of their own (`benign`, weight -1.5) and
are checked in two more places, from whatever copy the process holds and never
by downloading: a report-derived indicator on one is held back with the list's
name as the reason, and `intel.add` refuses one from a caller who is not a
human. `report.NOISE_DOMAINS` stays: it lists the hosts reports cite
(sandboxes, ATT&CK, the vendors' own sites), which is a different job. A URL is
never matched by its host against a warninglist.

Each list's host is named in `deploy/.env.example` and in the worker's log line
on the first refresh (D57).

### Fixes

- **abuse.ch.** ThreatFox and URLhaus lookups, and a new MalwareBazaar lookup
  for hashes, run only with an `Auth-Key`. The same key is sent by the abuse.ch
  feeds. Without one, the lookup is not attempted and the answer says so; it is
  no longer a failure on every call.
- **URLs are asked as URLs.** URLhaus `/v1/url/` and ThreatFox `search_ioc` with
  the whole URL decide a URL's verdict. What the host has is returned as context
  with `relation: host_of` at weight 0.
- **RDAP.** Only a `registration` event is a registration date. Lookups go to the
  registry named in the IANA bootstrap files instead of rdap.org, and a domain's
  answer is cached for 7 days.

### Keyed sources

A keyed source is configured by a person with `intel.configure --lookup <name>`
(scope `intel:configure`, human-only, as for feeds). Its secret is encrypted
under the master key like a feed's. It runs only for observables of a case or a
direct `intel.lookup`, never on every event, never for an internal value (D34),
and only against the hosts it declares (DET-6). Each has a `per_day` quota,
counted per tenant; at the quota the source is skipped with "daily quota
reached", and a `429` with `Retry-After` pauses it until then.

| Source | Answers | Terms for a business |
| --- | --- | --- |
| abuse.ch (ThreatFox, URLhaus, MalwareBazaar) | reported IOC, malware family | free key; ToS since 2025-11-04 points for-profit use to a Spamhaus subscription |
| ipapi.is | VPN, proxy, Tor, datacenter, abuser flags; abuse contact | 1,000 a day with a free key; terms allow commercial products; cache at most 30 days |
| AbuseIPDB | abuse reports and confidence for an address | paid plan from $25 a month |
| GreyNoise | internet scanner or business service | paid plan |
| Shodan or Netlas | open ports and services on an address | paid plans from $69 or $49 a month |
| VirusTotal, urlscan.io | engine verdicts, page scans | only under a commercial licence the company already holds |

Configuring VirusTotal or urlscan asks the person to confirm the key is under a
commercial licence. Only lookup endpoints are called; nothing is submitted or
scanned, because a public scan publishes the URL.

Each source returns the `Observation` it does today: a summary under 200
characters and at most eight data fields. The model sees those, never a vendor
payload.

Considered and not added: abuse.ch SSLBL (no certificate column to match), OTX
indicator lookups (non-commercial EULA), crt.sh (5 requests a minute, often
502), LeakIX (free tier bars commercial use, and it returns leaked
credentials), and people-search sources such as GitHub profiles or username
probes, which describe people rather than events.

### Data

Migration 041 adds `shoc.lookup_sources` (the sealed key, `per_day`, enabled)
and `shoc.lookup_usage (tenant_id, day, source, calls, paused_until)` for the
quotas. Local lists are not stored in Postgres.

## Drawbacks

The local lists add download hosts a deployment contacts (DB-IP, Microsoft,
Oracle, Fastly, GitHub, DigitalOcean, Spamhaus, GitHub raw for X4BNet,
warninglists and disposable domains). Each is announced, but the list of
outbound connections grows from five hosts to about fifteen.

Without a key, ThreatFox and URLhaus answer nothing, and a fresh install gets no
"reported as malicious" signal from a lookup. The Feodo and URLhaus feeds still
match forward and retro-hunt.

DB-IP Lite is monthly and less precise than paid databases for small ranges.

## Alternatives

- **MaxMind GeoLite2.** Needs an account per install, its EULA limits use to
  "internal business purposes" and requires deleting copies older than 30 days,
  and reading `.mmdb` needs a library.
- **IPinfo Lite.** Daily and commercial-friendly (CC BY-SA 4.0), but needs a
  token and allows 10 downloads a day per IP. A reasonable swap for DB-IP if the
  monthly refresh proves too slow.
- **Team Cymru IP-to-ASN.** Free and current, but every lookup sends the address
  to Team Cymru, and the TXT query needs a DNS library or a hand-written packet.
- **Ship the free tiers anyway and document the terms.** The company is the one
  in breach, and it never read them.
- **Do nothing.** Every case's lookups keep reporting two failed sources, and
  D35's shared-infrastructure gate misses Azure.

## Dependency and scope impact

- New dependencies: none. CSV and JSON parsing, `ipaddress`, `array` and
  `bisect` are standard library.
- New required services: none.
- Public contract changes: `intel.configure` gains `lookup`; `intel.lookup`
  observations carry `listed`, and host context carries `relation: host_of`;
  `intel.list` gains `lookups`.

## Security considerations

A keyed lookup discloses an observable from the company's logs to a vendor. The
existing guards stay: no internal value leaves (D34), and a source only calls
the hosts it declares, so a value from a log cannot steer a lookup. Keyed
sources run per case observable, not per event, which bounds what is disclosed.

A local list is downloaded data. A poisoned warninglist could hide a malicious
domain behind "known benign", and a poisoned DROP list could mark a benign
address malicious. Each list is fetched over HTTPS from its publisher, and a
list that halves or grows by half in one refresh, or fails to download, is kept
at the previous copy; the worker logs it and the next intel job names it in its
result.

## Unresolved questions

- Whether "commercial or for-profit needs" in the abuse.ch terms covers a
  business defending its own network. The terms do not define it. If it does,
  the URLhaus default feed and the abuse.ch lookups need a Spamhaus subscription
  or have to go.
- Exposure checks for the company's own people: HIBP's verified domain search
  (from $4.39 a month) and Hudson Rock's free infostealer search by domain. Both
  answer "which of our accounts are in a breach or a stealer log", which bears
  on account takeover, the most common incident at this size. They are a daily
  Surveyor check rather than a lookup, and belong in their own RFC. Hudson
  Rock's terms could not be read.
- CIRCL hashlookup, to drop known-good hashes (signed installers, dual-use tools)
  from report-derived indicators. Its commercial terms could not be confirmed.

## Adoption and migration

The fixes ship without a flag. Local lists start on upgrade and are announced in
the release notes and the first-refresh log line. Keyed sources stay off until
configured; a deployment that had abuse.ch lookups working before 2025-06-30
needs a key to get them back.
