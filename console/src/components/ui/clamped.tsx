/** Long text at two lines; when it runs past them, "more" shows the rest and "less" folds it back. */
import { useId, useLayoutEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";

export function Clamped({ text }: { text: string }) {
  const id = useId();
  const ref = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [long, setLong] = useState(false);
  // Measured while folded, and again when the width changes; open, it stays long.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || open) return;
    const measure = () => setLong(el.scrollHeight > el.clientHeight);
    measure();
    if (typeof ResizeObserver !== "function") return;
    const watch = new ResizeObserver(measure);
    watch.observe(el);
    return () => watch.disconnect();
  }, [text, open]);
  return (
    <span className="block">
      <span ref={ref} id={id} className={cn("block whitespace-normal", !open && "line-clamp-2")}>
        {text}
      </span>
      {long ? (
        <button type="button" className="sh-clamp__more" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
          {open ? "less" : "more"}
        </button>
      ) : null}
    </span>
  );
}
