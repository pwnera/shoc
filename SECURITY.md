# Security policy

shoc is a security product. We treat a vulnerability in it as we would ask our
users to treat one in their own systems.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting on
this repository ("Security" → "Report a vulnerability"), or email
**security@shoc.dev**.

Please include: affected version or commit, environment, a description of the
impact, and the smallest reproduction you can manage.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | 2 business days |
| Initial assessment and severity | 5 business days |
| Fix for a confirmed high or critical issue | 7 days, as an out-of-band patch |
| Public advisory | With the fix, or at 90 days, whichever comes first |

We follow 90-day coordinated disclosure. We will credit you in the advisory
unless you ask us not to.

## Supported versions

The latest two minor releases receive security fixes. During 0.x, that is the
current minor and the one before it.

## Scope

In scope: the kernel, the capability registry and its generated surfaces, the
autonomy policy, the audit log, connectors, backend adapters, detection content
and the container image.

Out of scope: vulnerabilities in third-party services you connect shoc to,
findings that require a compromised host or database superuser, and missing
hardening that is documented as the operator's responsibility.

## Security model in brief

- Log content is untrusted data. It is quoted into prompts as data and never
  followed as instructions.
- Agents read; only the playbook runner acts. Every action is typed, checked
  against the autonomy policy, and audited.
- L2 actions require a human principal. No agent can approve one.
- The audit log is append-only and chained with an HMAC keyed from the master
  key; `shoc health audit` verifies it, and the worker does so every hour.
- Connector secrets are encrypted at rest with a master key you provide.
