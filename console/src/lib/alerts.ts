/**
 * Which Ops alerts Health owns (OPS-1): each kind has one home screen
 * (section 6), and Health draws only the platform's own kinds: worker, model,
 * spend, reaching a person (nobody reachable, pages that reached nobody) and
 * the database's size.
 */
import type { OpsAlert } from "@/types";

/** The kinds Health › Problems draws; every other kind renders on its owner screen. */
export const ownedByHealth = (alert: OpsAlert) => /^(jobs|llm|cost|notify|page|store)\./.test(alert.kind);
