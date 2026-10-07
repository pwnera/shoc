---
rfc: 0024
title: Run shoc as a role that does not own its schema, and rotate the master key
status: accepted
authors: ["@Rettila"]
created: 2026-10-02
requirements: ["SEC-1"]
supersedes: null
---

# RFC 0024: Run shoc as a role that does not own its schema, and rotate the master key

## Summary

`serve` and `worker` connect as a runtime role (`SHOC_DSN`) that does not own
the `shoc` schema. `shoc migrate` connects as the owner (`SHOC_MIGRATE_DSN`)
and grants the runtime role what it needs, which on the audit log is SELECT and
INSERT. Every webhook delivery carries the chain's head, signed, so a copy lives
outside Postgres. Sealed secrets are bound to the row they are stored in, and
`shoc rotate-key` moves the secrets and the audit chain to a new master key
without breaking verification of older rows.

## Motivation

D61 made the audit chain an HMAC keyed from `SHOC_MASTER_KEY`, so nobody
without the key can edit, insert or re-chain rows. It left three gaps, listed
under SEC-1 in `docs/prd.md`:

- shoc ran as the role that owns `shoc.audit_log`. That role can run
  `ALTER TABLE shoc.audit_log DISABLE TRIGGER USER`, delete the newest rows or a
  tenant's whole log, and what remains still verifies.
- One Fernet key sealed every tenant's secrets, and a sealed value named neither
  its tenant nor its source, so a value copied from one row into another, or
  into another tenant's, decrypted there.
- `SHOC_MASTER_KEY` could not be changed: the chain key was derived from it, and
  rows keyed with the old one would no longer verify.

## Guide-level explanation

Compose creates three roles (`deploy/postgres-init`): `shoc` owns the database,
`shoc_app` is what `serve` and `worker` connect as, and `shoc_agent` is the
read-only agent role. Only the migrate service gets the owner's DSN:

```yaml
x-shoc-env: &shoc-env
  SHOC_DSN: postgresql://shoc_app:…@postgres:5432/shoc
migrate:
  environment:
    <<: *shoc-env
    SHOC_MIGRATE_DSN: postgresql://shoc:…@postgres:5432/shoc
```

The Helm chart puts `SHOC_MIGRATE_DSN` in the secret and overrides it with an
empty value in the serve and worker pods. With one DSN for both, everything
works as before, and `migrate`, `serve` and `worker` print a warning naming the
risk.

```bash
shoc health audit --head 4812:9f2c…       # the head a webhook delivery carried
docker compose run --rm migrate rotate-key  # prints the new key once
```

## Reference-level explanation

**Runtime role.** After the migrations, `shoc migrate` runs
`migrate.grant_runtime` when `SHOC_MIGRATE_DSN` is set and names a different
user than `SHOC_DSN`: CONNECT and CREATE on the database; USAGE on `shoc`;
SELECT, INSERT, UPDATE, DELETE on its tables; sequences and functions; then
INSERT, UPDATE, DELETE and TRUNCATE are revoked on `schema_migrations`,
`audit_key` and `audit_epochs`, and UPDATE, DELETE and TRUNCATE on `audit_log`.
Without ownership the runtime role cannot disable triggers either. Tenant event
schemas belong to the runtime role, because loading adds and drops monthly
partitions and adds columns, which takes ownership; `migrate` creates the
default tenant's schema through `SHOC_DSN`, and hands over any tenant schema the
owner created before the runtime role existed. Granting on those schemas for the
agent role needs the owner to be a member of the runtime role, which the init
script sets (`GRANT shoc_app TO shoc`); the runtime role is a member of nothing.

**Anchor outside Postgres.** `stream.deliver` adds `audit_head`
(`seq:hash` of the tenant's newest audit row) to every webhook body it signs.
`health.audit` takes an optional `head` and fails when the chain no longer holds
that row with that hash. This catches the owner or a superuser deleting the
newest rows, as long as somebody kept a head.

**Bound secrets.** `secrets.seal` and `open_secret` take the row: tenant,
table and the key column's value (`source`, `provider`, `feed`, `webhook_id`).
They use AES-256-GCM (`cryptography`'s `AESGCM`, already a dependency) under a
key derived from the master key, with the row as associated data. A sealed value
starts with byte `0x02`; a Fernet token starts with `gAAAA`, so the two never
collide. `shoc migrate` re-seals any Fernet value it finds (`secrets.reseal`
with `unbound_only`), and `open_secret` refuses one that is left, naming
`shoc migrate`. Per-tenant keys derived with HKDF were the other option; they
bind the tenant but not the source, and associated data does both.

**Rotation.** `shoc rotate-key` reads the current key from `SHOC_MASTER_KEY`
and the new one from `SHOC_NEW_MASTER_KEY`, or generates one and prints it once.
As the owner, in one transaction, it re-seals every secret and calls
`audit.rotate`, which locks `shoc.audit_log` against appends, seals the retiring
chain key with the new master key into `shoc.audit_epochs` (migration 037)
beside `until_seq`, the first row it no longer covers, re-seals the keys already
there, records the new key's fingerprint in `shoc.audit_key`, and appends an
`audit.rekey` row to every tenant's chain, keyed with the new key and chained
onto the old head. `audit.verify` checks each row with the epoch key whose
`until_seq` is above it, and with the current key otherwise.

## Drawbacks

- Two DSNs to configure outside Compose, and an existing Compose install has to
  create `shoc_app` by hand once, because Postgres runs its init script only on
  a fresh volume (`docs/deploy.md`, "Upgrading to the runtime role").
- Rotation needs `serve` and `worker` stopped: they hold the old key until they
  restart.
- The anchor only helps if a webhook subscriber keeps the heads it receives.

## Alternatives

- **Do nothing.** The owner-delete gap stays and the key can never change.
- **A NOLOGIN owner role and `SET ROLE` in migrate.** The runtime role would
  have to be a member of the owner to switch, and membership is enough to
  disable the triggers.
- **Re-chain old rows under the new key on rotation.** That rewrites the log the
  chain exists to protect, and needs the triggers off.
- **Keep the chain key fixed and only re-wrap it.** Rotation would then change
  nothing for the chain after a key leak.
- **Write the head to a file.** Inside the same container or host it is no
  further from an attacker with database access than the table; webhook
  subscribers are other systems.

## Dependency and scope impact

- New dependencies: none (`cryptography` was already core).
- New required services: none.
- Public contract changes: `SHOC_MIGRATE_DSN` and `SHOC_NEW_MASTER_KEY`;
  `shoc rotate-key`; `health.audit` gains `head` in its input and output;
  webhook bodies gain `audit_head`; `shoc.audit_epochs`.

## Security considerations

The runtime role can still append rows (keyed, so they verify only with the
key) and read the log. Whoever holds the owner's DSN, or a superuser, can still
delete the newest rows; the webhook anchor and backups are what show it. The
master key opens every secret and keys the chain; rotation limits how long a
leaked key stays useful, and the retired chain keys sit in the database sealed
with the current master key, so they are as safe as the secrets are.

## Unresolved questions

- Whether the hourly `ops.check` should publish the head to the stream as well,
  for installs with no webhook subscriber.

## Adoption and migration

The default Compose file and the chart use the runtime role. A single DSN keeps
working with a warning. `shoc migrate` converts existing secrets in place and
creates `shoc.audit_epochs`; nothing else changes until the first rotation.
