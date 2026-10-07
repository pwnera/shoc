/**
 * Propose an action yourself; it goes through the same policy as the crew's.
 * Pick from the actions the policy allows, grouped by platform; a required
 * parameter starts filled only when a case entity fits it, and offers the
 * entities that fit it (all of them when none does) in one click; a pill says what will happen (waits for you, runs now,
 * notifies only, dry run); a reason is required.
 * Propose confirms first, in a popover on the button.
 *
 * Capabilities used: policy.show, action.propose.
 */
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Empty, Input, Label } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { QueryState } from "@/components/ui/state";
import { AutonomyBadge } from "@/components/ui/status";
import { isAwsKey, PATTERNS } from "@/lib/entity";
import { actionLabel, actionState } from "@/lib/labels";
import { ruleOf } from "@/lib/policy";
import { useProposeAction, usePolicy } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { Action, PolicyView } from "@/types";

/** Kinds whose pattern means the same on every platform. */
const NEUTRAL = new Set(["ip", "cidr", "url", "email", "domain", "hash", "cve"]);

/**
 * The case entities that fit a parameter, whole words only: `ip` takes the
 * case's ip when the value is one. Any other kind (a user, a key, an account)
 * fits only an action on the case's own platform, known when its key or
 * account is AWS-shaped: a Claude API key's `key_id` never takes an AWS key.
 */
function fitting(action: string, param: string, entities: Record<string, string>): [string, string][] {
  const aws = isAwsKey(entities.key ?? "") || /^\d{12}$/.test(entities.account ?? "");
  const fits = (kind: string, value: string) =>
    NEUTRAL.has(kind) ? PATTERNS.some((p) => p.kind === kind && p.test(value)) : aws && action.startsWith("aws.");
  const words = param.split("_");
  return Object.entries(entities).filter(([kind, value]) => value && words.includes(kind) && fits(kind, value));
}

/** Fill the parameters the case can answer; the rest stay empty, with the chips one click away. */
function prefill(action: string, required: string[], entities: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const param of required) {
    const hit = fitting(action, param, entities)[0];
    if (hit) out[param] = hit[1];
  }
  return out;
}

/** What proposing it will do: its autonomy badge says who acts, the rest whether it can be undone and whether it is a dry run. */
function consequence(policy: PolicyView, action: string) {
  const { autonomy: level, reversible } = ruleOf(policy, action);
  return { level, reversible, dry: policy.defaults.dry_run === true };
}

export function ProposeDialog({
  caseUid,
  entities,
  again,
  onDone,
  onClose,
}: {
  caseUid: string;
  entities: Record<string, string>;
  /** An expired approval to propose again. */
  again?: Pick<Action, "type" | "params"> | null;
  onDone: (action: Action) => void;
  onClose: () => void;
}) {
  const policy = usePolicy();
  const propose = useProposeAction();
  const [action, setAction] = useState(again?.type ?? "");
  const [params, setParams] = useState<Record<string, string>>(
    again ? Object.fromEntries(Object.entries(again.params ?? {}).map(([k, v]) => [k, String(v)])) : {},
  );
  const [why, setWhy] = useState("");
  const [search, setSearch] = useState("");
  const [asking, setAsking] = useState(false);
  const data = policy.data?.data;
  const required = (action && data?.action_params[action]?.required) || [];
  const missing = required.filter((name) => !params[name]?.trim());
  const ready = Boolean(action) && !missing.length && Boolean(why.trim());
  const choose = (name: string) => {
    setAction(name);
    setParams(prefill(name, data?.action_params[name]?.required ?? [], entities));
    setAsking(false);
  };

  const groups = new Map<string, string[]>();
  for (const name of data?.available_actions ?? []) {
    const text = `${name} ${actionLabel(name)}`.toLowerCase();
    if (search && !text.includes(search.toLowerCase())) continue;
    const platform = name.split(".")[0] ?? name;
    groups.set(platform, [...(groups.get(platform) ?? []), name]);
  }
  const known = Object.entries(entities).filter(([, value]) => value);
  const chipsFor = (param: string) => {
    const fit = fitting(action, param, entities);
    return fit.length ? fit : known;
  };
  const pill = data && action ? consequence(data, action) : null;
  const facts = pill ? (
    <>
      <AutonomyBadge level={pill.level} />
      {pill.reversible ? <Badge tone="idle">↺ reversible</Badge> : <Badge tone="bad">⊘ one-way</Badge>}
      {pill.dry ? <Badge tone="idle">dry run</Badge> : null}
    </>
  ) : null;

  const submit = () =>
    propose.mutateAsync({ action, params, case_uid: caseUid, rationale: why.trim() }).then(({ data: row }) => {
      toast({ tone: "ok", text: `${actionLabel(row.type)} · ${actionState(row).word}` });
      onDone(row);
      onClose();
    });

  const footer = action ? (
    <>
      <Button
        variant="ghost"
        onClick={() => {
          setAction("");
          setAsking(false);
        }}
      >
        Back
      </Button>
      <Popover
        open={asking}
        onOpenChange={setAsking}
        label={`Propose ${actionLabel(action)}`}
        align="end"
        trigger={(props) => (
          <Button {...props} variant="primary" disabled={!ready}>
            Propose
          </Button>
        )}
      >
        <Confirm
          what={[actionLabel(action), ...Object.values(params).filter(Boolean)].join(" · ")}
          facts={facts}
          go="Propose"
          onConfirm={submit}
          onCancel={() => setAsking(false)}
        />
      </Popover>
    </>
  ) : undefined;

  return (
    <Dialog title={action ? actionLabel(action) : "New action"} head={action ? facts : null} onClose={onClose} footer={footer}>
      <QueryState queries={policy}>
        {action ? (
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (ready) setAsking(true);
            }}
          >
            {required.map((name, index) => (
              <div key={name} className="flex flex-col gap-1">
                <Field label={name.replace(/_/g, " ")}>
                  <Input
                    value={params[name] ?? ""}
                    onChange={(e) => setParams({ ...params, [name]: e.target.value })}
                    autoFocus={index === 0}
                    mono
                  />
                </Field>
                {/* The case's entities that fit, else all of them, one click each. */}
                <div className="flex flex-wrap gap-1">
                  {chipsFor(name).map(([kind, value]) => (
                    <button key={kind} type="button" className="sh-chip" onClick={() => setParams({ ...params, [name]: value })}>
                      <span className="sh-chip__label">{kind}</span>
                      <span className="sh-chip__value">{value}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <Field label="Why">
              <Input value={why} onChange={(e) => setWhy(e.target.value)} autoFocus={!required.length} />
            </Field>
          </form>
        ) : (
          <div className="flex flex-col gap-3">
            <Input
              small
              data-autofocus
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Find an action"
              aria-label="Find an action"
            />
            {groups.size ? (
              [...groups].map(([platform, names]) => (
                <div key={platform} className="flex flex-col gap-1">
                  <Label>{platform}</Label>
                  <div className="flex flex-wrap gap-1">
                    {names.map((name) => (
                      <button key={name} type="button" className="sh-chip" onClick={() => choose(name)}>
                        {actionLabel(name)}
                      </button>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <Empty kind="filtered" title="No action matches" onClear={() => setSearch("")} />
            )}
          </div>
        )}
      </QueryState>
    </Dialog>
  );
}
