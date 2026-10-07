/**
 * Access › Tokens: who holds a live key, what it may do and when it ends. A row
 * opens its dialog (`?token=`); ⋯ › Revoke confirms first, names the holder, and warns
 * that revoking the token this browser holds signs it out. New token (N)
 * confirms (L2), then shows the token once; "I've stored it" removes it from
 * the page.
 *
 * Capabilities used: token.list, token.create, token.revoke.
 */
import { useState } from "react";
import { MoreHorizontal, Plus } from "lucide-react";
import { Countdown } from "@/components/ui/approval";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CardToolbar } from "@/components/ui/card";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy, Field } from "@/components/ui/field";
import { Input } from "@/components/ui/misc";
import { Confirm, Menu } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { AutonomyBadge } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useCommand, useListNav } from "@/lib/commands";
import { stamp } from "@/lib/format";
import { useNarrow } from "@/lib/media";
import { usePaged } from "@/lib/paged";
import { useFollow, useOpen } from "@/lib/popup";
import { useCreateToken, useRevokeToken, useTokens } from "@/lib/queries";
import type { ApiToken } from "@/types";

const DAY = 86_400_000;
const ROLES = ["reader", "operator", "deployer", "admin"] as const;
const EXPIRY = [
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
  { value: "365", label: "1y" },
  { value: "0", label: "never" },
] as const;

/** Time left and the lifetime used, bad under seven days; "never" without an end. */
function Expiry({ token }: { token: ApiToken }) {
  if (!token.expires_at) return <span className="sh-mono text-fg-3">never</span>;
  return <Countdown elapsed from={token.created_at} to={token.expires_at} badUnder={7 * DAY} />;
}

const revokeFacts = (
  <>
    <AutonomyBadge level="L2" />
    <span className="sh-badge sh-tone-warn">signs out this browser if it holds it</span>
  </>
);

export function Tokens() {
  const tokens = useTokens();
  const revoke = useRevokeToken();
  const narrow = useNarrow();
  const [adding, setAdding] = useState(false);
  const rows = tokens.data?.tokens ?? [];
  const dialog = useOpen("token", rows.map((t) => t.token_id));
  const { page, pager, start, prev, next } = usePaged(rows);
  const nav = useListNav(page, (t) => t.token_id, { onOpen: (t) => dialog.open(t.token_id), onPrevPage: prev, onNextPage: next });
  useFollow(nav, dialog.value);
  useCommand("access.new-token", () => setAdding(true));
  const picked = rows[dialog.at];

  const columns: Column<ApiToken>[] = [
    { label: "", fit: true, cell: (t) => <Badge tone="muted">{t.role ?? t.kind}</Badge> },
    { label: "", strong: true, cell: (t) => t.who },
    {
      label: "",
      width: narrow ? 64 : 96,
      align: "right",
      truncate: false,
      // A phone drops the bar.
      cell: (t) => (
        <span className="max-lg:[&_.sh-countdown\_\_bar]:hidden">
          <Expiry token={t} />
        </span>
      ),
    },
    {
      label: "",
      width: 40,
      menu: true,
      // The popover is the cell's child: left-aligned, or its confirm inherits the cell's right alignment.
      cell: (t) => (
        <span className="inline-block text-left">
          <Menu
            label={`${t.who} token actions`}
            items={[
              {
                label: "Revoke",
                danger: true,
                onSelect: () => revoke.mutateAsync(t.token_id),
                confirm: { what: `Revoke ${t.who} · ${t.token_id}`, facts: revokeFacts, go: "Revoke", danger: true },
              },
            ]}
            trigger={(props) => (
              <Button {...props} variant="ghost" size="icon" aria-label={`${t.who} token actions`}>
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
      <CardToolbar className="justify-end">
        <Button size="sm" aria-keyshortcuts="N" onClick={() => setAdding(true)}>
          <Plus aria-hidden />
          New token
        </Button>
      </CardToolbar>
      <Table
        label="Tokens"
        columns={columns}
        rows={page}
        start={start}
        rowKey={(t) => t.token_id}
        rowProps={nav.rowProps}
        loading={tokens.isPending}
        error={tokens.isLoadingError ? tokens.error : undefined}
        onRetry={() => void tokens.refetch()}
        empty="No live tokens"
      />
      {pager}
      {picked ? (
        <Dialog
          key={picked.token_id}
          title={picked.who}
          id={picked.token_id}
          head={<Badge tone="muted">{picked.role ?? picked.kind}</Badge>}
          step={dialog.step}
          onClose={dialog.close}
        >
          <Fields
            ruled
            rows={[
              ["Kind", picked.kind],
              [
                "Scopes",
                picked.scopes.length ? (
                  <span className="flex flex-wrap gap-1">
                    {picked.scopes.map((s) => (
                      <Badge key={s}>{s}</Badge>
                    ))}
                  </span>
                ) : null,
              ],
              ["Issued", `${stamp(picked.created_at)} · ${picked.created_by}`],
              [
                "Expires",
                <span className="inline-flex flex-wrap items-center gap-1">
                  {picked.expires_at ? (
                    <>
                      {stamp(picked.expires_at)}
                      <span aria-hidden>·</span>
                    </>
                  ) : null}
                  <Expiry token={picked} />
                </span>,
              ],
            ]}
          />
        </Dialog>
      ) : null}
      {adding ? <NewToken onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function NewToken({ onClose }: { onClose: () => void }) {
  const create = useCreateToken();
  const [who, setWho] = useState("");
  const [role, setRole] = useState<(typeof ROLES)[number]>("operator");
  const [expiry, setExpiry] = useState<(typeof EXPIRY)[number]["value"]>("90");
  const [asking, setAsking] = useState(false);
  const [token, setToken] = useState("");
  const name = who.trim();
  const done = () => {
    // The token leaves the page: the state, and the mutation's own copy.
    setToken("");
    create.reset();
    onClose();
  };

  if (token)
    return (
      <Dialog title="New token" size="sm" onClose={done} footer={<Button variant="primary" onClick={done}>I've stored it</Button>}>
        <Field label={`${role} token for ${name}`} hint="Shown once">
          <Copy value={token} block label="Copy the token" />
        </Field>
      </Dialog>
    );

  return (
    <Dialog
      title="New token"
      size="sm"
      onClose={onClose}
      footer={
        asking ? null : (
          <Button variant="primary" disabled={!name} onClick={() => setAsking(true)}>
            Create
          </Button>
        )
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (name) setAsking(true);
        }}
      >
        <Field label="Who">
          <Input data-autofocus value={who} onChange={(event) => setWho(event.target.value)} autoComplete="off" />
        </Field>
        <Field label="Role" group>
          <Seg label="Role" value={role} onChange={setRole} options={ROLES} className="self-start" />
        </Field>
        <Field label="Expires" group>
          <Seg label="Expires" value={expiry} onChange={setExpiry} options={EXPIRY} className="self-start" />
        </Field>
      </form>
      {asking ? (
        <Confirm
          inline
          what={`New ${role} token · ${name}`}
          facts={
            <>
              <AutonomyBadge level="L2" />
              <span className="sh-badge">{EXPIRY.find((e) => e.value === expiry)?.label}</span>
            </>
          }
          go="Create"
          onConfirm={() =>
            create.mutateAsync({ who: name, role, expires_days: Number(expiry) }).then((envelope) => {
              setToken(envelope.data.token);
              setAsking(false);
            })
          }
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}
