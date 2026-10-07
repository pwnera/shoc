/**
 * The two glyphs Response and the playbook page share: a platform's mark
 * (`ProductLogo`, its initial where the console has no logo) and ↺ or ⊘ for
 * an act that can or cannot be undone.
 */
import { ProductLogo } from "@/components/ui/logo";

/**
 * An action type's platform ("aws.disable_access_key" → AWS), like an event's
 * product logo. Decorative where the row's words name the platform; `named`
 * where the mark is its only mention.
 */
export function PlatformMark({ id, small, named }: { id: string; small?: boolean; named?: boolean }) {
  return <ProductLogo product={id.split(".")[0]} size={small ? 12 : 14} named={named} />;
}

/** ↺ for an act that can be undone, ⊘ in bad ink for one that cannot. */
export function Reach({ reversible }: { reversible: boolean }) {
  return reversible ? (
    <span className="text-fg-4" role="img" aria-label="reversible">
      ↺
    </span>
  ) : (
    <span className="text-bad" role="img" aria-label="one-way">
      ⊘
    </span>
  );
}
