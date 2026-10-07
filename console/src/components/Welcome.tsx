/**
 * /welcome, where an invitation or reset link lands (RFC 0028) before
 * anything else loads. The link travels in the fragment, which no server and
 * no Referer sees, and leaves the address bar at once for the tab's history
 * state, so a reload still opens it. An enrolling link
 * shows the new authenticator as a QR code, its secret and an otpauth link;
 * every link then takes a password and a first code, and signs this browser
 * in.
 *
 * Routes used: /auth/link, /auth/link/accept.
 */
import { useEffect, useState, type FormEvent } from "react";
import { renderSVG } from "uqr";
import { ApiError, auth } from "@/lib/api";
import { browser, refusal } from "@/lib/signin";
import { Button } from "./ui/button";
import { Copy, Field } from "./ui/field";
import { Input, Loading, Spinner } from "./ui/misc";

type Opened = { email: string; enrol: boolean; otpauth: string };

const EXPIRED = "This link has expired. Ask an admin for a new one.";

export function Welcome() {
  // Read during render, then moved from the address bar to history.state, where a reload still finds it.
  const [link] = useState(() => window.location.hash.slice(1) || (history.state as { link?: string } | null)?.link || "");
  const [opened, setOpened] = useState<Opened | null>(null);
  const [failed, setFailed] = useState(link ? "" : EXPIRED);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<{ on: "password" | "code"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (window.location.hash) history.replaceState({ ...history.state, link }, "", `${window.location.pathname}${window.location.search}`);
    if (!link) return;
    auth<Opened>("link", { link }).then(setOpened, (problem: unknown) =>
      setFailed(problem instanceof ApiError && problem.status === 410 ? EXPIRED : refusal(problem)),
    );
  }, [link]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (password !== confirm) return setError({ on: "password", text: "Passwords don't match" });
    setBusy(true);
    setError(null);
    try {
      await auth("link/accept", { link, password, code });
      browser.replace("/");
    } catch (problem) {
      setBusy(false);
      if (!(problem instanceof ApiError)) return setError({ on: "password", text: refusal(problem) });
      if (problem.status === 410) return setFailed(EXPIRED);
      // A spent code goes; a refused password leaves a good one for the next try.
      if (problem.status === 401 || problem.status === 429) setCode("");
      if (problem.status === 401) setError({ on: "code", text: "Wrong code" });
      else if (problem.status === 429) setError({ on: "code", text: "Too many attempts. Try later" });
      // The password rules (length, not the email) come back in the kernel's words.
      else setError({ on: "password", text: refusal(problem) });
    }
  };

  return (
    <div className="flex min-h-dvh items-center justify-center bg-bg-0 p-4">
      <div className="sh-card w-full max-w-sm">
        <form className="flex flex-col gap-3 p-4" onSubmit={(event) => void submit(event)}>
          <span className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-6 w-6" />
            <h1 className="m-0 text-[13px] font-semibold text-fg-1">shoc</h1>
          </span>
          {failed ? (
            <>
              <p className="m-0 text-fg-2">{failed}</p>
              <a href="/login" className="sh-btn sh-btn--default sh-btn--md self-start">
                Log in
              </a>
            </>
          ) : !opened ? (
            <Loading label="Opening the link" />
          ) : (
            <>
              <span className="sh-mono sh-mono--strong truncate">{opened.email}</span>
              {opened.enrol ? <Authenticator otpauth={opened.otpauth} /> : null}
              <Field label="New password" hint="12 characters or more" error={error?.on === "password" ? error.text : undefined}>
                <Input
                  type="password"
                  name="password"
                  autoComplete="new-password"
                  autoFocus
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </Field>
              <Field label="Confirm password">
                <Input type="password" name="confirm" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} />
              </Field>
              <Field label="Code" error={error?.on === "code" ? error.text : undefined}>
                <Input
                  mono
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                />
              </Field>
              <Button type="submit" variant="primary" className="self-end" disabled={busy || !password || !confirm || code.length !== 6}>
                {busy ? <Spinner /> : null}
                Continue
              </Button>
            </>
          )}
        </form>
      </div>
    </div>
  );
}

/** The new authenticator: scan the code, or copy the secret, or open the otpauth link on a phone. */
function Authenticator({ otpauth }: { otpauth: string }) {
  const secret = new URL(otpauth).searchParams.get("secret") ?? "";
  const qr = `data:image/svg+xml;utf8,${encodeURIComponent(renderSVG(otpauth))}`;
  return (
    <Field label="Authenticator" group>
      <div className="flex flex-col items-start gap-2">
        {/* A QR code reads dark on light in both themes. */}
        <img src={qr} alt="QR code for an authenticator app" className="h-40 w-40 rounded-control bg-white p-2" />
        <Copy value={secret} label="Copy the secret" />
        <a href={otpauth} className="sh-link">
          Open in an authenticator app
        </a>
      </div>
    </Field>
  );
}
