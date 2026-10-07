/**
 * Copying text. The clipboard API needs a secure context, and the console is
 * often reached over plain HTTP on a Tailscale address, so a copy falls back
 * to a selection and execCommand. `copyText` is the mechanism (Copy and
 * CopyButton show its outcome in place); `copyAndSay` is for a key or a menu
 * item, where a toast is the only answer the reader gets.
 */
import { toast } from "./toast";

/** "selected" when only the selection worked: the value on screen is highlighted for ⌘C. */
export type CopyOutcome = "" | "copied" | "selected";

/** Select `el`'s text when given, then copy `value`; "" when nothing worked. */
export async function copyText(value: string, el?: HTMLElement | null): Promise<CopyOutcome> {
  if (el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
  }
  if (window.isSecureContext && navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(value);
      return "copied";
    } catch {
      /* fall through to the selection */
    }
  }
  // No element on screen holds the value: select it in a scratch field for execCommand.
  const scratch = el ? null : document.createElement("textarea");
  if (scratch) {
    scratch.value = value;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    // Inside an open modal dialog the rest of the page is inert, so the scratch field joins the dialog.
    (document.activeElement?.closest("dialog") ?? document.body).append(scratch);
    scratch.select();
  }
  try {
    if (document.execCommand("copy")) return "copied";
  } catch {
    /* the selection is all that is left */
  } finally {
    scratch?.remove();
  }
  // A scratch field leaves with its selection; only a value on screen stays selected.
  return el ? "selected" : "";
}

/** Copy and say so: "Copied <what>", or "Couldn't copy" when the browser refused. */
export async function copyAndSay(value: string, what = value): Promise<void> {
  const outcome = await copyText(value);
  toast({ tone: "neutral", text: outcome === "copied" ? `Copied ${what}` : "Couldn't copy" });
}
