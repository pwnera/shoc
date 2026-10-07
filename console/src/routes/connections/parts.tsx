/** How a source or connector is drawn: its logo. */
import { ProductLogo } from "@/components/ui/logo";
import { connectorOf } from "@/lib/sources";

/** The vendor's mark at 16px (`ProductLogo`); the row names the source. */
export function Logo({ name }: { name: string }) {
  return <ProductLogo product={connectorOf(name)} size={16} />;
}
