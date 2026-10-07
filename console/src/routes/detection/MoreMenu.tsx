/**
 * The "⋯" of a header: a menu whose confirming item swaps the menu for its
 * confirm. The page holds `open` and `asking`, so a key or a palette hand-off
 * (`?do=`) can open the menu straight on that confirm and run the same
 * handler as a click.
 */
import { MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Confirm, MenuList, Popover, type ConfirmProps, type MenuEntry } from "@/components/ui/pop";
import { Tip } from "@/components/ui/tip";
import { keyLabel } from "@/lib/commands";

export type MoreItem = Extract<MenuEntry, { label: string }>;

export function MoreMenu({
  label,
  items,
  open,
  asking,
  onOpenChange,
  onAsk,
}: {
  label: string;
  items: MoreItem[];
  open: boolean;
  /** The label of the item whose confirm shows, or null for the menu. */
  asking: string | null;
  onOpenChange: (open: boolean) => void;
  onAsk: (label: string | null) => void;
}) {
  return (
    <Popover
      menu
      align="end"
      open={open}
      onOpenChange={(now) => {
        onOpenChange(now);
        if (!now) onAsk(null);
      }}
      trigger={(props) => (
        <Tip label="More" kbd={keyLabel(".")}>
          <Button {...props} variant="ghost" size="icon" aria-label="More" aria-keyshortcuts=".">
            <MoreHorizontal aria-hidden />
          </Button>
        </Tip>
      )}
    >
      {(close) => {
        const item = items.find((i) => i.label === asking && i.confirm);
        if (item?.confirm)
          return (
            <Confirm
              {...(item.confirm as Omit<ConfirmProps, "onConfirm" | "onCancel">)}
              onCancel={() => onAsk(null)}
              onConfirm={async (note) => {
                await item.onSelect(note);
                close();
              }}
            />
          );
        return (
          <MenuList
            label={label}
            close={close}
            items={items.map(({ confirm, ...rest }) =>
              confirm ? { ...rest, keepOpen: true, onSelect: () => onAsk(rest.label) } : rest,
            )}
          />
        );
      }}
    </Popover>
  );
}
