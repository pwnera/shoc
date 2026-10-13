/** Whether shoc sees anything, from Connections' delivery words; Overview's heading says it. */
export type Blind = { word: "Nothing connected" | "Sources down"; tone: "bad" | "warn" };

/** shoc sees nothing: no source connected, or none delivering (bad when one fails); null while one delivers. */
export function blindness(words: string[]): Blind | null {
  if (!words.length) return { word: "Nothing connected", tone: "bad" };
  if (words.includes("delivering")) return null;
  return { word: "Sources down", tone: words.includes("failing") ? "bad" : "warn" };
}
