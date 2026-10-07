# Contributing to the shoc console

The console is an independent project inside the shoc repository. It has its own
Node toolchain and CI job (`.github/workflows/console.yml`, which runs only when
`console/**` changes) and shares the repository's licence, governance and
[contributing rules](../CONTRIBUTING.md).

## Setup

```bash
cd console
npm install
SHOC_URL=http://127.0.0.1:8080 npm run dev     # a shoc you are running
npm run check                                   # eslint, tsc, vitest
```

You need a shoc to point at. The quickest one is the kernel's quick start:
`docker compose up -d` in `deploy/`, then `shoc migrate` and
`shoc replay aws_cloudtrail evals/scenarios/leaked_aws_key/events.json` so there
is something on the screen. To sign in, give shoc
`SHOC_PUBLIC_URL=http://localhost:5173` and run
`shoc user invite you@example.com --role admin`, or use a token
(`shoc token create --who you@example.com --role admin`) with "Use a
token".

## The rule that matters

The console may only call capabilities the API already exposes. No console-only
endpoint, no reaching into the database, no second way in. Signing in is the
one path outside `/v1`: the `/auth/*` routes (RFC 0028) set and clear the
session cookie, belong to the kernel, and serve any browser client the same
way. People are managed through capabilities (`user.*`, `sso.*`) like
everything else. If a screen needs something:

1. Add the capability in `../shoc/capabilities/`, with its test.
2. Add a hook for it in `src/lib/queries.ts` (in `src/lib/reads.ts` if the
   shell itself reads it; `queries.ts` re-exports those).
3. Use it here.

That order keeps the API sufficient for every client, not just this one.

## Conventions

- One hook per capability in `src/lib/queries.ts`; screens do not call `fetch`.
- Each screen's docstring lists the capabilities it uses.
- Severity colours mean severity; blue means the crew. Nothing else carries
  colour.
- Every agent statement renders its citations. A claim with none says so.
- Tests cover the API client, the formatters and anything with logic. Screens
  are thin enough that testing them mostly tests React.
- Conventional Commits with a `console` scope, DCO sign-off (`git commit -s`),
  no CLA.
