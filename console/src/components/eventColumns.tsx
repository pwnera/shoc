/**
 * An event row's anatomy, the same in EventTable and Explore's results: the
 * product's logo and an outcome mark as glyphs, the operation as the name with
 * actor and source IP after it, and the time as the host words it.
 */
import type { EventRow } from "@/types";
import { ProductLogo } from "./ui/logo";
import { Mark } from "./ui/status";
import type { Column } from "./ui/table";

const outcome = (status: unknown) => (status === "Success" ? "good" : status === "Failure" ? "bad" : "idle");

export function eventColumns(when: (value: string) => string): Column<EventRow>[] {
  return [
    {
      label: "Source",
      fit: true,
      sort: (r) => String(r.metadata_product ?? ""),
      cell: (r) => (
        <span className="inline-flex items-center gap-1.5">
          <ProductLogo product={r.metadata_product} named />
          <Mark tone={outcome(r.status)} label={r.status ? String(r.status) : "no outcome"} />
        </span>
      ),
    },
    {
      label: "Event",
      sort: (r) => String(r.api_operation ?? r.activity_name ?? r.class_name ?? "event"),
      cell: (r) => (
        <>
          <span className="font-medium text-fg-1">{String(r.api_operation ?? r.activity_name ?? r.class_name ?? "event")}</span>
          {r.actor_user_name || r.src_endpoint_ip ? (
            <span className="sh-mono ml-2">{[r.actor_user_name, r.src_endpoint_ip].filter(Boolean).join(" · ")}</span>
          ) : null}
        </>
      ),
    },
    { label: "Time", fit: true, mono: true, sort: (r) => String(r.time ?? ""), cell: (r) => when(String(r.time)) },
  ];
}
