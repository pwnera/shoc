/**
 * Words for the Intel screen: feed, report source and lookup names as their
 * publishers write them, the entity key an indicator or a lead opens
 * EntityDialog with, and a URL as it is shown.
 */
import { parseEntity } from "@/lib/entity";
import type { IntelFeed } from "@/types";

const NAMES: Record<string, string> = {
  abuse_ch_feodo: "Feodo",
  abuse_ch_urlhaus: "URLhaus",
  abuse_ch_threatfox: "ThreatFox",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  abuse_ch_malwarebazaar: "MalwareBazaar",
  otx: "OTX",
  otx_pulses: "OTX pulses",
  misp: "MISP",
  misp_events: "MISP events",
  // Report sources shoc knows by name (`intel.list` presets).
  microsoft_ti: "Microsoft Threat Intelligence",
  the_dfir_report: "The DFIR Report",
  huntress: "Huntress",
  proofpoint: "Proofpoint",
  push_security: "Push Security",
  datadog_security_labs: "Datadog Security Labs",
  google_gtig: "Google Threat Intelligence",
  wiz_research: "Wiz Research",
  stepsecurity: "StepSecurity",
  talos: "Cisco Talos",
  cert_fr_alerts: "CERT-FR alerts",
  cert_fr_cti: "CERT-FR CTI",
  // Lookup sources that need an account (`intel.list` lookups).
  abuse_ch: "abuse.ch",
  ipapi_is: "ipapi.is",
  abuseipdb: "AbuseIPDB",
  greynoise: "GreyNoise",
  shodan: "Shodan",
  netlas: "Netlas",
  virustotal: "VirusTotal",
  urlscan: "urlscan.io",
};

/** A feed, preset or lookup id (`abuse_ch_urlhaus`), or an indicator's source as the kernel stores it (`abuse.ch/urlhaus`). */
export const feedName = (feed: string) => NAMES[feed] ?? NAMES[feed.replace(/[./]/g, "_")] ?? feed.replace(/_/g, " ");

/** Parsers whose items are reports the CTI role reads, not indicators. */
const REPORT_PARSERS = new Set(["rss", "otx_pulses", "misp_events"]);

export const isReportSource = (feed: IntelFeed) => REPORT_PARSERS.has(feed.parser ?? feed.feed);

/** The host a feed URL reaches, or "" while it is not one. */
export function hostOf(url: string): string {
  if (!/^https?:\/\/\S+$/i.test(url.trim())) return "";
  try {
    return new URL(url.trim()).hostname;
  } catch {
    return "";
  }
}

/** The newest successful pull among enabled feeds, or null when none has pulled. */
export function lastPull(feeds: IntelFeed[]): string | null {
  return feeds.reduce<string | null>(
    (newest, f) => (f.enabled && f.last_ok_at && (!newest || f.last_ok_at > newest) ? f.last_ok_at : newest),
    null,
  );
}

/**
 * What EntityDialog opens for a value: its typed key, or the kind a field
 * names; null when neither says. An email searched as an actor is a person,
 * keyed `user:` as the events and Posture key them.
 */
export function entityKey(value: string, field = ""): string | null {
  const typed = parseEntity(value);
  if (typed?.kind === "email" && (field === "actor" || field === "auto")) return `user:${typed.value}`;
  if (typed) return typed.key;
  const kind = { src_ip: "ip", domain: "domain", actor: "user" }[field];
  return kind ? `${kind}:${value}` : null;
}

/** A URL indicator as it is shown, "hxxp://…", so it never reads as a link; copying and sweeping keep the value. */
export const defang = (type: string, value: string) => (type === "url" ? value.replace(/^http/i, "hxxp") : value);
