/**
 * The account button, marked with the signed-in person's initial: who this
 * browser is signed in as, with the role, and where it talks to; the theme,
 * the single-key switch (WCAG 2.1.4: chords and ⌘ keys stay on), the shortcut
 * sheet, the version, and Log out, which ends the session (RFC 0028) and
 * empties the tab's session storage; a logout the kernel did not take stays
 * here with a toast, since the login page would sign straight back in. The
 * version is read only when the menu opens.
 *
 * Capabilities used: user.me, capability.list {area: "meta"} (the version).
 * Route used: /auth/logout.
 */
import { useState } from "react";
import { Keyboard, LogOut } from "lucide-react";
import { ApiError, apiHost, auth } from "@/lib/api";
import { browser } from "@/lib/signin";
import { toastError } from "@/lib/toast";
import { keyLabel, useSingleKeys } from "@/lib/commands";
import { useCapabilities, useMe } from "@/lib/reads";
import { MODES, useTheme, type Mode } from "@/lib/theme";
import { Avatar } from "./ui/avatar";
import { Badge } from "./ui/badge";
import { Switch } from "./ui/misc";
import { Popover } from "./ui/pop";
import { Seg } from "./ui/seg";

export function AccountMenu({ onKeys }: { onKeys: () => void }) {
  const [open, setOpen] = useState(false);
  const me = useMe();
  return (
    <Popover
      label="Account"
      align="end"
      onOpenChange={setOpen}
      trigger={(props) => (
        <button {...props} type="button" className="sh-shell__account" aria-label="Account">
          <Avatar who={`human:${me.data?.email || me.data?.id || "you"}`} size={24} tip={false} />
        </button>
      )}
    >
      {(close) => <Account open={open} close={close} onKeys={onKeys} />}
    </Popover>
  );
}

function Account({ open, close, onKeys }: { open: boolean; close: () => void; onKeys: () => void }) {
  const [mode, setMode] = useTheme();
  const [single, setSingle] = useSingleKeys();
  const [leaving, setLeaving] = useState(false);
  const meta = useCapabilities("meta", "", open);
  const me = useMe(open);

  return (
    <div className="sh-menu min-w-[260px]">
      <div className="flex flex-col gap-0.5 px-2 py-1.5">
        <span className="flex items-center gap-2">
          <span className="sh-mono sh-mono--strong truncate">{me.data ? me.data.email || me.data.id : me.isError ? "—" : "…"}</span>
          {me.data?.role ? <Badge tone="muted">{me.data.role}</Badge> : null}
        </span>
        <span className="sh-mono truncate">{apiHost}</span>
      </div>
      <hr className="sh-menu__sep" />
      <div className="flex items-center gap-2 px-2 py-1">
        <span className="sh-menu__text text-fg-2">Theme</span>
        <Seg<Mode> label="Theme" value={mode} options={MODES} onChange={setMode} />
      </div>
      <div className="px-2 py-1">
        <Switch checked={single} onChange={setSingle}>
          Single-key shortcuts
        </Switch>
      </div>
      <button
        type="button"
        className="sh-menu__item"
        onClick={() => {
          close();
          onKeys();
        }}
      >
        <Keyboard aria-hidden />
        <span className="sh-menu__text">Keyboard shortcuts</span>
        <kbd className="sh-menu__kbd">{keyLabel("?")}</kbd>
      </button>
      <hr className="sh-menu__sep" />
      <div className="flex items-center gap-2 px-2 py-1">
        <span className="sh-menu__text text-fg-3">Version</span>
        <span className="sh-mono">{meta.data?.version ?? (meta.isError ? "—" : "…")}</span>
      </div>
      <button
        type="button"
        className="sh-menu__item"
        disabled={leaving}
        onClick={() => {
          // Ends the session and clears the cookie, then opens the login page.
          setLeaving(true);
          const leave = () => {
            // The next person on this tab starts without the crew thread; the theme stays in localStorage.
            try {
              sessionStorage.clear();
            } catch {
              /* nothing kept */
            }
            browser.assign("/login");
          };
          void auth("logout").then(leave, (error: unknown) => {
            // A session already ended may leave; any other failure kept the cookie, which /login would take straight back.
            if (error instanceof ApiError && error.isSignedOut) return leave();
            setLeaving(false);
            toastError(error, "Log out failed");
          });
        }}
      >
        <LogOut aria-hidden />
        <span className="sh-menu__text">Log out</span>
      </button>
    </div>
  );
}
