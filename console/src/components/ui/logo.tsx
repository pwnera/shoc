/**
 * A product's mark, drawn one way everywhere a row has a glyph column: its
 * logo (`brandOf`), else its initial in a neutral hairline tile, so the column
 * never shows a gap and no product gets a stand-in picture. A product may be an
 * event's `metadata_product`, a connector ("cloudflare_logs") or an action
 * type's platform ("tailscale"). `named` where the mark is the row's only
 * mention of the product; decorative otherwise.
 */
import { cn } from "@/lib/cn";
import { brandOf, productName } from "../brands";

const SIZE = { 12: "h-3 w-3", 14: "h-3.5 w-3.5", 16: "h-4 w-4" } as const;

export function ProductLogo({
  product,
  size = 14,
  named,
  className,
}: {
  product: string | null | undefined;
  size?: keyof typeof SIZE;
  named?: boolean;
  className?: string;
}) {
  const text = product ?? "";
  const name = text ? productName(text) : "no product";
  const box = cn("shrink-0", SIZE[size], className);
  const logo = brandOf(text);
  if (logo) return <img src={logo.src} alt={named ? name : ""} width={size} height={size} className={cn("sh-logo", box)} />;
  return (
    <span
      {...(named ? { role: "img", "aria-label": name } : { "aria-hidden": true })}
      className={cn("sh-logo-tile", box)}
    >
      {text ? name.charAt(0) : "·"}
    </span>
  );
}
