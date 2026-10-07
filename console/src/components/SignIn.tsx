/**
 * The login page's form (RFC 0028). The email decides the way in: an SSO
 * domain goes to the company's provider, any other email asks for a password,
 * then a code from the authenticator, and sends both at once so a right
 * password never answers differently from a wrong one. "Use a token" is the
 * last way in: a person's token becomes this browser's session.
 *
 * Routes used: /auth/start, /auth/login, /auth/forgot, /auth/token.
 */
import { useState, type FormEvent } from "react";
import { ChevronLeft } from "lucide-react";
import { ApiError, auth, clearSignedOut } from "@/lib/api";
import { browser, refusal } from "@/lib/signin";
import { Button } from "./ui/button";
import { Field } from "./ui/field";
import { Input, Spinner } from "./ui/misc";

type Step = "email" | "password" | "code" | "token";

const SLOW_DOWN = "Too many attempts. Try later";

export function SignIn({ onSignedIn, problem = "" }: { onSignedIn: () => void; problem?: string }) {
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState(problem);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const address = email.trim();

  const go = (next: Step) => {
    setStep(next);
    setError("");
    setNote("");
  };

  /** One request: `wrong` is what a 401 means on this step. Work that signs in answers true and stays busy until the page swaps. */
  async function send(work: () => Promise<boolean | void>, wrong: string, onWrong?: () => void) {
    setBusy(true);
    setError("");
    setNote("");
    try {
      if (!(await work())) setBusy(false);
    } catch (failure) {
      setBusy(false);
      if (failure instanceof ApiError && failure.status === 401) {
        onWrong?.();
        setError(wrong);
      } else setError(failure instanceof ApiError && failure.status === 429 ? SLOW_DOWN : refusal(failure));
    }
  }

  const signedIn = () => {
    clearSignedOut();
    onSignedIn();
    return true;
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (step === "email")
      void send(async () => {
        const start = await auth<{ method: string; url?: string }>("start", {
          email: address,
          return_to: `${window.location.pathname}${window.location.search}`,
        });
        if (start.method === "sso" && start.url) browser.assign(start.url);
        else go("password");
      }, "Sign-in failed");
    else if (step === "password") go("code");
    else if (step === "code")
      void send(
        async () => {
          await auth("login", { email: address, password, code });
          return signedIn();
        },
        "Wrong email, password or code",
        () => {
          setPassword("");
          setCode("");
          setStep("password");
        },
      );
    else
      void send(async () => {
        await auth("token", { token: token.trim() });
        return signedIn();
      }, "Token rejected");
  };

  const forgot = () =>
    void send(async () => {
      const answer = await auth<{ sent: boolean }>("forgot", { email: address });
      setNote(answer.sent ? "Check your email" : "Ask an admin for a reset link");
    }, "Sign-in failed");

  const ready =
    step === "email" ? address.includes("@") : step === "password" ? Boolean(password) : step === "code" ? code.length === 6 : Boolean(token.trim());

  return (
    <form className="flex flex-col gap-4" onSubmit={submit}>
      {step === "password" || step === "code" ? (
        // The email it continues with; clicking it goes back to change it.
        <Button size="sm" variant="ghost" className="self-start" aria-label={`Change email, ${address}`} onClick={() => go("email")}>
          <ChevronLeft aria-hidden />
          {address}
        </Button>
      ) : null}
      {step === "email" ? (
        <Field label="Email" error={error || undefined}>
          <Input
            type="email"
            name="email"
            autoComplete="username"
            data-autofocus
            autoFocus
            spellCheck={false}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </Field>
      ) : step === "password" ? (
        <Field
          label="Password"
          error={error || undefined}
          hint={note || undefined}
          aside={
            <Button size="sm" variant="ghost" disabled={busy} onClick={forgot}>
              Forgot password?
            </Button>
          }
        >
          <Input
            type="password"
            name="password"
            autoComplete="current-password"
            autoFocus
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>
      ) : step === "code" ? (
        <Field label="Code" error={error || undefined}>
          <Input
            mono
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            autoFocus
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
          />
        </Field>
      ) : (
        <Field label="Token" error={error || undefined}>
          <Input
            mono
            type="password"
            name="token"
            autoComplete="off"
            autoFocus
            spellCheck={false}
            placeholder="shoc_…"
            value={token}
            onChange={(event) => setToken(event.target.value)}
          />
        </Field>
      )}
      <Button type="submit" variant="primary" className="w-full" disabled={!ready || busy}>
        {busy ? <Spinner /> : null}
        {step === "token" ? "Open" : "Continue"}
      </Button>
      {step === "email" || step === "token" ? (
        <Button variant="ghost" size="sm" className="self-center" onClick={() => go(step === "email" ? "token" : "email")}>
          {step === "email" ? "Use a token" : "Use email"}
        </Button>
      ) : null}
    </form>
  );
}
