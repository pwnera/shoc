/** The two reports the Export menu builds; the console never asks for a shift or exception report. */
export type Kind = "weekly" | "exec";
export const KIND_LABEL: Record<Kind, string> = { weekly: "Weekly report", exec: "Board report" };
