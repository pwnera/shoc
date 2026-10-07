/**
 * What the sign-in screens share outside React (RFC 0028): the words for the
 * `?signin=` codes the SSO callback redirects to and for a refusal, where the
 * login page is, and the navigations that leave the page, kept on an object so
 * a test can watch them (jsdom's `location` cannot be replaced).
 */
import { ApiError, explain } from "./api";

const PROBLEMS: Record<string, string> = {
  sso_state: "Sign-in timed out. Try again",
  sso_failed: "Your provider's sign-in failed",
  sso_domain: "This email can't sign in here",
  sso_unverified: "Your provider hasn't verified this email",
  disabled: "This account is disabled",
};

/** Read `?signin=` and drop it from the address bar: its words, or "" when there is none. */
export function takeSigninProblem(): string {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("signin");
  if (code === null) return "";
  url.searchParams.delete("signin");
  history.replaceState(history.state, "", `${url.pathname}${url.search}${url.hash}`);
  return PROBLEMS[code] ?? "Sign-in failed";
}

/** A sign-in route's refusal in words: `cross_site` means this page is not at SHOC_PUBLIC_URL. */
export function refusal(failure: unknown): string {
  return failure instanceof ApiError && failure.code === "cross_site" ? "Open shoc at its public address" : explain(failure);
}

/** The login page for this screen: `/login` from `/`, the front page's address, else this address, which signing in opens again. */
export function loginHere(): string {
  const { pathname, search } = window.location;
  return pathname === "/" ? "/login" : `${pathname}${search}`;
}

export const browser = {
  /** Off to the login page, or to the company's provider, which sends the browser back to `/auth/sso/callback`. */
  assign: (url: string) => window.location.assign(url),
  /** Into the console, replacing `/welcome` in the history. */
  replace: (url: string) => window.location.replace(url),
};
