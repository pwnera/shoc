const SEVERITY = ["informational", "low", "medium", "high", "critical"];
/** Severity as a number, so a list sorts by weight rather than by name. */
export const severityRank = (severity: string) => SEVERITY.indexOf(severity);
