/** A rule as YAML tokens, so the logic panel inks them and Copy YAML gets the same text. */
type Ink = "name" | "key" | "mod" | "value";
export type Tok = { text: string; ink?: Ink };

export const INK: Record<Ink, string> = {
  name: "text-fg-1",
  key: "text-fg-2",
  mod: "text-fg-3",
  value: "text-series-3",
};

export const scalar = (value: unknown) => (typeof value === "string" ? value : JSON.stringify(value));

/** Enough YAML to read a rule back, as tokens: selection names, field keys, |modifiers, values. */
export function yaml(value: Record<string, unknown>, depth = 0): Tok[][] {
  const out: Tok[][] = [];
  const pad = (d: number) => "  ".repeat(d);
  for (const [key, v] of Object.entries(value)) {
    if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
    const [field = key, ...mods] = key.split("|");
    const head: Tok[] = [
      { text: pad(depth) },
      { text: field, ink: depth === 0 ? "name" : "key" },
      ...mods.map((m): Tok => ({ text: `|${m}`, ink: "mod" })),
      { text: ":" },
    ];
    if (Array.isArray(v) && v.some((item) => item && typeof item === "object")) {
      out.push(head);
      for (const item of v) {
        if (item && typeof item === "object") {
          const sub = yaml(item as Record<string, unknown>, depth + 2);
          if (sub[0]) sub[0][0] = { text: `${pad(depth + 1)}- ` };
          out.push(...sub);
        } else out.push([{ text: `${pad(depth + 1)}- ` }, { text: scalar(item), ink: "value" }]);
      }
    } else if (Array.isArray(v)) {
      out.push([
        ...head,
        { text: " [" },
        ...v.flatMap((item, i): Tok[] => [...(i ? [{ text: ", " }] : []), { text: scalar(item), ink: "value" }]),
        { text: "]" },
      ]);
    } else if (typeof v === "object") {
      out.push(head, ...yaml(v as Record<string, unknown>, depth + 1));
    } else out.push([...head, { text: " " }, { text: scalar(v), ink: "value" }]);
  }
  return out;
}

export const yamlText = (value: Record<string, unknown>) =>
  yaml(value)
    .map((line) => line.map((t) => t.text).join(""))
    .join("\n");
