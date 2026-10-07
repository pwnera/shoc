/**
 * ATT&CK tactics, in kill-chain order, and the tactics of each technique the
 * shipped rules, hunts and playbooks cite. A sub-technique takes its parent's
 * tactics. A technique missing here simply has no tactic to filter on.
 */
export const TACTICS = [
  ["reconnaissance", "Reconnaissance"],
  ["resource-development", "Resource development"],
  ["initial-access", "Initial access"],
  ["execution", "Execution"],
  ["persistence", "Persistence"],
  ["privilege-escalation", "Privilege escalation"],
  ["defense-evasion", "Defense evasion"],
  ["credential-access", "Credential access"],
  ["discovery", "Discovery"],
  ["lateral-movement", "Lateral movement"],
  ["collection", "Collection"],
  ["command-and-control", "Command and control"],
  ["exfiltration", "Exfiltration"],
  ["impact", "Impact"],
] as const;

export type Tactic = (typeof TACTICS)[number][0];

/** Two letters per tactic, for the 14-cell strip. */
export const TACTIC_SHORT: Record<Tactic, string> = {
  reconnaissance: "RC",
  "resource-development": "RD",
  "initial-access": "IA",
  execution: "EX",
  persistence: "PE",
  "privilege-escalation": "PV",
  "defense-evasion": "DE",
  "credential-access": "CA",
  discovery: "DI",
  "lateral-movement": "LM",
  collection: "CO",
  exfiltration: "EF",
  "command-and-control": "C2",
  impact: "IM",
};

const RA = "resource-development";
const IA = "initial-access";
const EX = "execution";
const PE = "persistence";
const PR = "privilege-escalation";
const DE = "defense-evasion";
const CA = "credential-access";
const DI = "discovery";
const LM = "lateral-movement";
const CO = "collection";
const C2 = "command-and-control";
const XF = "exfiltration";
const IM = "impact";

const BY_TECHNIQUE: Record<string, Tactic[]> = {
  T1021: [LM],
  T1027: [DE],
  T1033: [DI],
  T1040: [CA, DI],
  T1048: [XF],
  T1056: [CO, CA],
  T1059: [EX],
  T1069: [DI],
  T1070: [DE],
  T1071: [C2],
  T1078: [IA, PE, PR, DE],
  T1087: [DI],
  T1090: [C2],
  T1098: [PE, PR],
  T1105: [C2],
  T1110: [CA],
  T1111: [CA],
  T1114: [CO],
  T1119: [CO],
  T1133: [IA, PE],
  T1136: [PE],
  T1176: [PE],
  T1195: [IA],
  T1199: [IA],
  T1204: [EX],
  T1213: [CO],
  T1218: [DE],
  T1219: [C2],
  T1484: [DE, PR],
  T1485: [IM],
  T1486: [IM],
  T1490: [IM],
  T1496: [IM],
  T1526: [DI],
  T1528: [CA],
  T1530: [CO],
  T1531: [IM],
  T1535: [DE],
  T1537: [XF],
  T1539: [CA],
  T1543: [PE, PR],
  T1546: [PE, PR],
  T1548: [PR, DE],
  T1550: [DE, LM],
  T1552: [CA],
  T1555: [CA],
  T1556: [CA, DE, PE],
  T1557: [CA, CO],
  T1561: [IM],
  T1562: [DE],
  T1564: [DE],
  T1565: [IM],
  T1566: [IA],
  T1567: [XF],
  T1568: [C2],
  T1572: [C2],
  T1578: [DE],
  T1580: [DI],
  T1583: [RA],
  T1584: [RA],
  T1585: [RA],
  T1586: [RA],
  T1609: [EX],
  T1621: [CA],
  T1651: [EX],
  T1657: [IM],
  T1666: [DE],
};

export function tacticsOf(techniques: readonly string[]): Tactic[] {
  const out = new Set<Tactic>();
  for (const technique of techniques)
    for (const tactic of BY_TECHNIQUE[technique.slice(0, 5).toUpperCase()] ?? []) out.add(tactic);
  return TACTICS.map(([id]) => id).filter((id) => out.has(id));
}

/** The techniques under each tactic, in kill-chain order, for a cell's tip. A technique may sit under several. */
export function byTactic(techniques: readonly string[]): Map<Tactic, string[]> {
  const out = new Map<Tactic, string[]>();
  for (const [tactic] of TACTICS)
    for (const technique of techniques)
      if ((BY_TECHNIQUE[technique.slice(0, 5).toUpperCase()] ?? []).includes(tactic))
        out.set(tactic, [...(out.get(tactic) ?? []), technique]);
  return out;
}

/** Whether the map knows a technique, for the test that keeps it complete. */
export const knownTechnique = (technique: string) => technique.slice(0, 5).toUpperCase() in BY_TECHNIQUE;

export const tacticLabel = (tactic: string) => TACTICS.find(([id]) => id === tactic)?.[1] ?? tactic;

export const attackUrl = (technique: string) =>
  `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`;
