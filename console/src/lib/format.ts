/** Small formatters. Dense screens live or die on these. */

export function ago(value: string | null | undefined): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return days < 30 ? `${days}d ago` : new Date(value).toLocaleDateString();
}

/** "14:02": the 24-hour clock everywhere, as the timeline's `time()` writes it. */
export function clock(value: string | null | undefined): string {
  const t = time(value);
  return t === "—" ? t : t.slice(0, 5);
}

/** "25 Sep 14:02": a moment on another day. */
export function stamp(value: string | null | undefined): string {
  const d = dayMonth(value);
  return d === "—" ? d : `${d} ${clock(value)}`;
}

export function count(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

/** Dollars with cents, always: "$0.00" reads as nothing spent, never as a broken figure. */
export function money(value: number): string {
  return `$${value.toFixed(2)}`;
}

export function truncate(text: string, length = 120): string {
  return text.length <= length ? text : `${text.slice(0, length - 1)}…`;
}

export function duration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

/** "45s", "12m", "1h25m", "1.9d": a length of time in its largest sensible unit. */
export function span(seconds: number): string {
  if (!Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86_400) {
    const h = Math.floor(s / 3600);
    const m = Math.round((s % 3600) / 60);
    return m === 60 ? `${h + 1}h` : `${h}h${m ? `${m}m` : ""}`;
  }
  return `${(s / 86_400).toFixed(1).replace(/\.0$/, "")}d`;
}

/** "12m": how long ago, for a row's one time. `now` comes from the shared tick. */
export function age(value: string | null | undefined, now = Date.now()): string {
  if (!value) return "never";
  const then = Date.parse(value);
  if (Number.isNaN(then)) return "—";
  const seconds = (now - then) / 1000;
  if (seconds < 0) return "now";
  if (seconds >= 30 * 86_400) return day(value);
  return seconds < 86_400 ? span(seconds).replace(/h\d+m$/, "h") : `${Math.floor(seconds / 86_400)}d`;
}

/** "1h52", "14m", "40s": time left until a deadline; "" once it has passed. */
export function left(until: string | null | undefined, now = Date.now()): string {
  if (!until) return "";
  const seconds = (Date.parse(until) - now) / 1000;
  if (!(seconds > 0)) return "";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) {
    const m = Math.floor((seconds % 3600) / 60);
    return `${Math.floor(seconds / 3600)}h${String(m).padStart(2, "0")}`;
  }
  return `${Math.floor(seconds / 86_400)}d`;
}

/** "14:02:11", for timeline rows under a day heading. */
export function time(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** "Thu 25 Sep", the heading of a day of rows. Assembled by hand: en-GB spells September "Sept". */
export function day(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toLocaleDateString("en-US", { weekday: "short" })} ${dayMonth(value)}`;
}

/** "25 Sep": a day without its weekday (time-bar ticks, stamps). */
export function dayMonth(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.getDate()} ${date.toLocaleDateString("en-US", { month: "short" })}`;
}

/** "1,707". */
export function num(value: number): string {
  return value.toLocaleString("en-US");
}

/** "48k", "5.0M": a token count where the exact one is in a tip or a field. */
export function compact(n: number): string {
  // 999,500 rounds to 1000k: it reads 1.0M.
  return n >= 999_500 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 1000 ? `${Math.round(n / 1000)}k` : num(n);
}

/** "CASE-172f…": a uid short enough for a chip; the full id goes in its tip. */
export function shortId(uid: string): string {
  const dash = uid.indexOf("-");
  const head = dash >= 0 && dash < 6 ? uid.slice(0, dash + 1) : "";
  const rest = uid.slice(head.length);
  return rest.length > 4 ? `${head}${rest.slice(0, 4)}…` : uid;
}

/** "AKIA…MPLE": a long value cut in the middle, so both ends stay recognisable. */
export function middle(text: string, keep = 4): string {
  return text.length <= keep * 2 + 1 ? text : `${text.slice(0, keep)}…${text.slice(-keep)}`;
}

/** "200+" when a list came back at the kernel's cap, so a capped count never reads as the total. */
export function capped(n: number, cap: number): string {
  return n >= cap ? `${num(cap)}+` : num(n);
}
