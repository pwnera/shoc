/**
 * Access › People: who signs in to this shoc (RFC 0028), with which role, how,
 * and when they last did. A row opens its dialog (`?person=`); ⋯ changes the
 * role (`?change=<user_id>`), sends a reset link, or disables, each behind an
 * L2 confirm. Invite (I, `?invite=1`) and SSO (`?sso=1`) sit in the toolbar,
 * beside the text (`?pq=`, the email) and the role and state chips. A link
 * that was not emailed is shown once, like a new token, never in the URL, and
 * "I've stored it" removes it from the page.
 *
 * Capabilities used: user.list, user.invite, user.reset, user.update,
 * sso.show, sso.configure.
 */
import { useState } from "react";
import { MoreHorizontal, Plus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy, Field } from "@/components/ui/field";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, Input } from "@/components/ui/misc";
import { Confirm, Menu, type MenuEntry } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { QueryState } from "@/components/ui/state";
import { AutonomyBadge } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useCommand, useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { ago, stamp } from "@/lib/format";
import { usePaged } from "@/lib/paged";
import { useFollow, useOpen, usePopValue } from "@/lib/popup";
import { useConfigureSso, useInviteUser, useResetUser, useSso, useUpdateUser, useUsers } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { Issued, SsoSettings, User } from "@/types";

const ROLES = ["reader", "operator", "deployer", "admin"] as const;
type Role = (typeof ROLES)[number];

const l2 = <AutonomyBadge level="L2" />;
const warn = (text: string) => (
  <>
    {l2}
    <span className="sh-badge sh-tone-warn">{text}</span>
  </>
);

const stateOf = (u: User) => (u.disabled_at ? "disabled" : u.last_login_at ? "active" : "invited");

/** "disabled", "invited" until the first sign-in, else when they last signed in. */
function State({ user }: { user: User }) {
  if (user.disabled_at) return <Badge tone="faint">disabled</Badge>;
  if (!user.last_login_at) return <Badge tone="warn">invited</Badge>;
  return <span className="sh-mono text-fg-3">{ago(user.last_login_at)}</span>;
}

export function People() {
  const users = useUsers();
  const sso = useSso();
  const reset = useResetUser();
  const update = useUpdateUser();
  // The dialogs live in the URL, so Back closes them; the one-time link stays in state, out of it.
  const [inviting, invite] = usePopValue("invite");
  const [configuring, configure] = usePopValue("sso");
  const [changeId, change] = usePopValue("change");
  const [issued, setIssued] = useState<{ title: string; result: Issued } | null>(null);
  const all = users.data?.users ?? [];
  const changing = all.find((u) => u.user_id === changeId);
  const count = (test: (u: User) => boolean) => all.filter(test).length;
  const roles = [...new Set(all.map((u) => u.role))].sort();
  const dims: Dim<User>[] = [
    {
      id: "role",
      label: "role",
      options: roles.map((r) => ({ value: r, count: count((u) => u.role === r) })),
      test: (u, v) => u.role === v,
    },
    {
      id: "state",
      label: "state",
      options: (["invited", "disabled"] as const).map((v) => ({ value: v, count: count((u) => stateOf(u) === v) })),
      test: (u, v) => stateOf(u) === v,
    },
  ];
  // Its own text parameter: Registry, a tab away, keeps `q`.
  const filters = useFilters(dims, { text: "pq", match: (u, text) => u.email.toLowerCase().includes(text) });
  const rows = all.filter(filters.keep);
  const dialog = useOpen("person", rows.map((u) => u.user_id));
  const { page, pager, start, prev, next } = usePaged(rows);
  const nav = useListNav(page, (u) => u.user_id, { onOpen: (u) => dialog.open(u.user_id), onPrevPage: prev, onNextPage: next });
  useFollow(nav, dialog.value);
  useCommand("access.invite", () => invite("1"));
  const picked = rows[dialog.at];

  /** A link not emailed is shown once; an emailed one, or none (an SSO domain), is a toast. */
  const deliver = (title: string) => (result: Issued) => {
    if (result.link) return setIssued({ title, result });
    toast({ tone: "ok", text: result.emailed ? `Emailed to ${result.email}` : `${result.email} signs in with SSO` });
  };
  const stored = () => {
    // The link leaves the page: the state, and the mutation's own copy.
    setIssued(null);
    reset.reset();
  };

  const actions = (u: User): MenuEntry[] =>
    u.disabled_at
      ? [
          {
            label: "Enable",
            onSelect: () => update.mutateAsync({ email: u.email, disabled: false }),
            confirm: { what: `Enable ${u.email}`, facts: l2, go: "Enable" },
          },
        ]
      : [
          { label: "Change role", onSelect: () => change(u.user_id) },
          {
            label: "Reset",
            // The provider holds an SSO account's way in.
            disabled: u.method === "sso",
            onSelect: () => reset.mutateAsync(u.email).then((envelope) => deliver("Reset link")(envelope.data)),
            confirm: { what: `Reset ${u.email}`, facts: warn("new password and authenticator"), go: "Reset" },
          },
          {
            label: "Disable",
            danger: true,
            onSelect: () => update.mutateAsync({ email: u.email, disabled: true }),
            confirm: { what: `Disable ${u.email}`, facts: warn("ends their sessions and tokens"), go: "Disable", danger: true },
          },
        ];

  const columns: Column<User>[] = [
    { label: "", fit: true, cell: (u) => <Badge tone="muted">{u.role}</Badge> },
    { label: "", strong: true, cell: (u) => u.email },
    { label: "", fit: true, hide: "md", cell: (u) => <span className="sh-mono text-fg-3">{u.method === "sso" ? "SSO" : "password"}</span> },
    { label: "", fit: true, align: "right", truncate: false, cell: (u) => <State user={u} /> },
    {
      label: "",
      width: 40,
      menu: true,
      // The popover is the cell's child: left-aligned, or its confirm inherits the cell's right alignment.
      cell: (u) => (
        <span className="inline-block text-left">
          <Menu
            label={`${u.email} actions`}
            items={actions(u)}
            trigger={(props) => (
              <Button {...props} variant="ghost" size="icon" aria-label={`${u.email} actions`}>
                <MoreHorizontal aria-hidden />
              </Button>
            )}
          />
        </span>
      ),
    },
  ];

  return (
    <>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter people"
      >
        <Button size="sm" variant="ghost" onClick={() => configure("1")}>
          SSO
          {sso.data?.configured ? <span className="sh-mono text-fg-3">{sso.data.domains.join(", ")}</span> : null}
        </Button>
        <Button size="sm" aria-keyshortcuts="I" onClick={() => invite("1")}>
          <Plus aria-hidden />
          Invite
        </Button>
      </FilterBar>
      <Table
        label="People"
        columns={columns}
        rows={page}
        start={start}
        rowKey={(u) => u.user_id}
        rowProps={nav.rowProps}
        loading={users.isPending}
        error={users.isLoadingError ? users.error : undefined}
        onRetry={() => void users.refetch()}
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No one matches" onClear={filters.clear} />
          ) : (
            "No one signs in yet"
          )
        }
      />
      {pager}
      {picked ? (
        <Dialog
          key={picked.user_id}
          title={picked.email}
          id={picked.user_id}
          head={<Badge tone="muted">{picked.role}</Badge>}
          step={dialog.step}
          onClose={dialog.close}
        >
          <Fields
            ruled
            rows={[
              ["Signs in with", picked.method === "sso" ? "SSO" : "Password and authenticator"],
              ["Last sign-in", picked.last_login_at ? stamp(picked.last_login_at) : "never"],
              ["Added", stamp(picked.created_at)],
              ["Disabled", picked.disabled_at ? stamp(picked.disabled_at) : null],
            ]}
          />
        </Dialog>
      ) : null}
      {changing ? <ChangeRole key={changing.user_id} user={changing} onClose={() => change(null)} /> : null}
      {inviting ? (
        <Invite
          onClose={() => invite(null)}
          onIssued={(result) => {
            invite(null);
            deliver("Invitation")(result);
          }}
        />
      ) : null}
      {configuring ? <Sso onClose={() => configure(null)} /> : null}
      {issued ? (
        <Dialog
          title={issued.title}
          size="sm"
          onClose={stored}
          footer={
            <Button variant="primary" onClick={stored}>
              I've stored it
            </Button>
          }
        >
          <Field label={issued.result.email} hint="Shown once">
            <Copy value={issued.result.link} block label="Copy the link" />
          </Field>
        </Dialog>
      ) : null}
    </>
  );
}

function ChangeRole({ user, onClose }: { user: User; onClose: () => void }) {
  const update = useUpdateUser();
  const [role, setRole] = useState<Role>((ROLES as readonly string[]).includes(user.role) ? (user.role as Role) : "reader");
  const [asking, setAsking] = useState(false);
  return (
    <Dialog
      title={user.email}
      size="sm"
      onClose={onClose}
      footer={
        asking ? null : (
          <Button variant="primary" disabled={role === user.role} onClick={() => setAsking(true)}>
            Change
          </Button>
        )
      }
    >
      <Field label="Role" group>
        <Seg label="Role" value={role} onChange={setRole} options={ROLES} className="self-start" />
      </Field>
      {asking ? (
        <Confirm
          inline
          what={`${user.email} · ${user.role} → ${role}`}
          facts={l2}
          go="Change"
          onConfirm={() => update.mutateAsync({ email: user.email, role }).then(onClose)}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}

function Invite({ onClose, onIssued }: { onClose: () => void; onIssued: (result: Issued) => void }) {
  const invite = useInviteUser();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("reader");
  const [asking, setAsking] = useState(false);
  const address = email.trim().toLowerCase();
  const ready = /^[^\s@]+@[^\s@]+$/.test(address);
  return (
    <Dialog
      title="Invite"
      size="sm"
      onClose={onClose}
      footer={
        asking ? null : (
          <Button variant="primary" disabled={!ready} onClick={() => setAsking(true)}>
            Invite
          </Button>
        )
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) setAsking(true);
        }}
      >
        <Field label="Email">
          <Input type="email" data-autofocus value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="off" />
        </Field>
        <Field label="Role" group>
          <Seg label="Role" value={role} onChange={setRole} options={ROLES} className="self-start" />
        </Field>
      </form>
      {asking ? (
        <Confirm
          inline
          what={`Invite ${address} · ${role}`}
          facts={l2}
          go="Invite"
          onConfirm={() => invite.mutateAsync({ email: address, role }).then((envelope) => onIssued(envelope.data))}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}

function Sso({ onClose }: { onClose: () => void }) {
  const sso = useSso();
  if (sso.data) return <SsoForm settings={sso.data} onClose={onClose} />;
  return (
    <Dialog title="SSO" size="sm" onClose={onClose}>
      <QueryState queries={sso}>{null}</QueryState>
    </Dialog>
  );
}

/** The company's OpenID Connect provider; a blank secret keeps the stored one. */
function SsoForm({ settings, onClose }: { settings: SsoSettings; onClose: () => void }) {
  const configure = useConfigureSso();
  const [issuer, setIssuer] = useState(settings.issuer);
  const [clientId, setClientId] = useState(settings.client_id);
  const [secret, setSecret] = useState("");
  const [domains, setDomains] = useState(settings.domains.join(", "));
  const [asking, setAsking] = useState<"save" | "off" | null>(null);
  const list = domains
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  const ready = Boolean(issuer.trim() && clientId.trim() && list.length && (secret || settings.key === "set"));
  return (
    <Dialog
      title="SSO"
      size="sm"
      onClose={onClose}
      footer={
        asking ? null : (
          <>
            {settings.configured ? (
              <Button variant="danger" onClick={() => setAsking("off")}>
                Turn off
              </Button>
            ) : null}
            <Button variant="primary" disabled={!ready} onClick={() => setAsking("save")}>
              Save
            </Button>
          </>
        )
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) setAsking("save");
        }}
      >
        <Field label="Redirect URI">
          {settings.redirect_uri ? (
            <Copy value={settings.redirect_uri} label="Copy the redirect URI" />
          ) : (
            <Tip label="SHOC_PUBLIC_URL" mono>
              <span className="text-fg-3">Needs shoc's public address</span>
            </Tip>
          )}
        </Field>
        <Field label="Issuer">
          <Input
            type="url"
            data-autofocus
            placeholder="https://accounts.google.com"
            spellCheck={false}
            value={issuer}
            onChange={(event) => setIssuer(event.target.value)}
          />
        </Field>
        <Field label="Client ID">
          <Input mono spellCheck={false} value={clientId} onChange={(event) => setClientId(event.target.value)} autoComplete="off" />
        </Field>
        <Field label="Client secret">
          <Input
            type="password"
            autoComplete="new-password"
            placeholder={settings.key === "set" ? "stored ••••" : undefined}
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
          />
        </Field>
        <Field label="Domains">
          <Input placeholder="example.com" spellCheck={false} value={domains} onChange={(event) => setDomains(event.target.value)} />
        </Field>
      </form>
      {asking === "save" ? (
        <Confirm
          inline
          what={`SSO · ${list.join(", ")}`}
          facts={warn("new people join as reader")}
          go="Save"
          onConfirm={() =>
            configure
              .mutateAsync({ issuer: issuer.trim(), client_id: clientId.trim(), client_secret: secret, domains: list })
              .then(onClose)
          }
          onCancel={() => setAsking(null)}
        />
      ) : asking === "off" ? (
        <Confirm
          inline
          what="Turn off SSO"
          facts={l2}
          go="Turn off"
          danger
          onConfirm={() => configure.mutateAsync({ clear: true }).then(onClose)}
          onCancel={() => setAsking(null)}
        />
      ) : null}
    </Dialog>
  );
}
