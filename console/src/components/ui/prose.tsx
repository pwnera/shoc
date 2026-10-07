/**
 * What the crew wrote, set as text: paragraphs (a long one broken at its
 * sentence ends), lists, **bold**, `code`,
 * entity keys as chips (`user:alice`, an IP, an AWS key) and tool or field
 * names (`identity_resolve`) in mono. Crew text can carry words lifted from
 * logs, so everything here is a React text node or one of those elements:
 * never HTML, never a link out. A chip only opens EntityDialog in the console.
 */
import { Fragment, type ReactNode } from "react";
import { parseEntity, type EntityKind } from "@/lib/entity";
import { Entity } from "./entity";

const MARK = /(\*\*[^*\n]+\*\*|`[^`\n]+`)/g;
const BULLET = /^\s*[-*•]\s+/;
const NUMBER = /^\s*\d+[.)]\s+/;
/** Punctuation around a word that is not part of it: "(user:alice)." */
const EDGE = /^([("'[]*)(.*?)([)"'\].,;:!?]*)$/s;
/** A tool or field name holds an underscore: identity_resolve, google.get_user. */
const IDENT = /^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*_[a-z0-9]+(?:[._][a-z0-9]+)*$/;
/** Domains stay words: "events.query" and "posture.py" pass the domain pattern. */
const CHIP = new Set<EntityKind>(["ip", "cidr", "url", "email", "hash", "key", "resource", "cve", "user", "account", "host", "repo"]);

/** An IPv4 address with its port: the address is the chip, ":443" stays text. */
const PORT = /^((?:\d{1,3}\.){3}\d{1,3})(:\d{1,5})$/;

/**
 * A word as its leading punctuation, its core and its trailing punctuation. The
 * core is the whole word, so a hex run inside a longer token is never a hash.
 */
function parts(word: string): [string, string, string] {
  const [, head = "", core = "", tail = ""] = EDGE.exec(word) ?? [];
  // An IPv6 address may end in "::", which the edge takes for punctuation.
  const colons = /^:+/.exec(tail)?.[0];
  if (colons && parseEntity(core + colons)?.kind === "ip") return [head, core + colons, tail.slice(colons.length)];
  const port = PORT.exec(core);
  return port ? [head, port[1]!, port[2]! + tail] : [head, core, tail];
}

function words(text: string): ReactNode[] {
  // Parentheses split words too: "google.get_user(jane@example.com)" is a tool and an email.
  return text.split(/(\s+|[()])/).map((word, i) => {
    const [head, core, tail] = parts(word);
    const entity = core ? parseEntity(core) : null;
    const shown =
      entity && CHIP.has(entity.kind) ? (
        <Entity value={entity.key} button />
      ) : IDENT.test(core) ? (
        <code>{core}</code>
      ) : null;
    return shown ? (
      <Fragment key={i}>
        {head}
        {shown}
        {tail}
      </Fragment>
    ) : (
      word
    );
  });
}

function inline(text: string): ReactNode[] {
  return text.split(MARK).map((part, i) =>
    part.length > 4 && part.startsWith("**") && part.endsWith("**") ? (
      <strong key={i}>{part.slice(2, -2)}</strong>
    ) : part.length > 2 && part.startsWith("`") && part.endsWith("`") ? (
      <code key={i}>{part.slice(1, -1)}</code>
    ) : (
      <Fragment key={i}>{words(part)}</Fragment>
    ),
  );
}

/** A sentence end: ". " or ".; " before a capital or a digit; "identity.resolve" and "192.0.2.1" have no space. */
const SENTENCE = /(?<=[.!?][;"')\]]?)\s+(?=["'([]?[A-Z0-9])/;
const LONG = 360;
const SHORT = 160;

/** The crew writes one long paragraph: past LONG characters it breaks at sentence ends, a paragraph per SHORT or more. */
function paragraphs(block: string): string[] {
  if (block.length <= LONG || block.includes("\n")) return [block];
  const out: string[] = [];
  for (const sentence of block.split(SENTENCE)) {
    const last = out.at(-1);
    if (last !== undefined && last.length < SHORT) out[out.length - 1] = `${last} ${sentence}`;
    else out.push(sentence);
  }
  return out;
}

/** One line of crew text inside a row: bold, code and chips, no blocks. */
export function ProseLine({ text }: { text: string }) {
  return <span className="sh-prose">{inline(text)}</span>;
}

export function Prose({ text }: { text: string }) {
  const out: ReactNode[] = [];
  for (const [b, block] of text.trim().split(/\n{2,}/).flatMap(paragraphs).entries()) {
    // Runs of list lines become a list; the other lines a paragraph.
    let run: { kind: "p" | "ul" | "ol"; lines: string[] } | null = null;
    const runs: { kind: "p" | "ul" | "ol"; lines: string[] }[] = [];
    for (const line of block.split("\n")) {
      const kind = BULLET.test(line) ? "ul" : NUMBER.test(line) ? "ol" : "p";
      if (!run || run.kind !== kind) runs.push((run = { kind, lines: [] }));
      run.lines.push(kind === "p" ? line : line.replace(kind === "ul" ? BULLET : NUMBER, ""));
    }
    runs.forEach((r, i) => {
      const key = `${b}.${i}`;
      if (r.kind === "p")
        out.push(
          <p key={key}>
            {r.lines.map((line, j) => (
              <Fragment key={j}>
                {j ? <br /> : null}
                {inline(line)}
              </Fragment>
            ))}
          </p>,
        );
      else {
        const List = r.kind;
        out.push(
          <List key={key}>
            {r.lines.map((line, j) => (
              <li key={j}>{inline(line)}</li>
            ))}
          </List>,
        );
      }
    });
  }
  return <div className="sh-prose">{out}</div>;
}
