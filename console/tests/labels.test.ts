import { describe, expect, it } from "vitest";
import {
  ACTIONS,
  actionLabel,
  actionState,
  findingCase,
  findingStatus,
  jobWord,
  lookupState,
  modelProvider,
  pageState,
  queueState,
  reachLabel,
  readWord,
  ruleState,
  severityLabel,
  silentLabel,
  stepState,
} from "@/lib/labels";
import type { RuleHealth } from "@/types";

describe("action labels", () => {
  it("names a known action in plain words", () => {
    expect(actionLabel("notify.page")).toBe("Page on-call");
  });

  it("names every action type policy.show lists (contract/v1.json actions)", () => {
    const types = [
      "anthropic.disable_api_key",
      "aws.detach_role_policy",
      "aws.detach_user_policy",
      "aws.disable_access_key",
      "aws.revoke_role_sessions",
      "azure.stop_vm",
      "cloudflare.block_ip",
      "cloudflare.disable_api_token",
      "crowdstrike.block_hash",
      "crowdstrike.isolate_host",
      "defender.block_hash",
      "defender.isolate_host",
      "entra.remove_admin_role",
      "entra.remove_factor",
      "entra.reset_password",
      "entra.revoke_sessions",
      "entra.suspend_user",
      "gcp.disable_firewall_rule",
      "gcp.disable_service_account",
      "gcp.disable_service_account_key",
      "github.demote_org_owner",
      "github.enable_secret_scanning",
      "github.make_repo_private",
      "github.remove_collaborator",
      "github.remove_deploy_key",
      "gitlab.block_user",
      "google.revoke_app_token",
      "google.revoke_sessions",
      "google.suspend_user",
      "m365.delete_inbox_rule",
      "m365.revoke_app_consent",
      "notify.page",
      "okta.remove_admin_role",
      "okta.remove_factor",
      "okta.reset_password",
      "okta.revoke_sessions",
      "okta.suspend_user",
      "openai.delete_api_key",
      "sentinelone.block_hash",
      "sentinelone.isolate_host",
      "stripe.block_charge_card",
      "tailscale.deauthorize_device",
      "tailscale.revoke_key",
      "tailscale.suspend_user",
      "wazuh.block_ip",
    ];
    expect(types.filter((t) => !ACTIONS[t])).toEqual([]);
  });

  it("turns an unknown action id into words", () => {
    expect(actionLabel("okta.brand_new_act")).toBe("Brand new act");
  });

  it("says an action's reach in accounts, and unknown when the kernel could not see it", () => {
    expect([1, 3, -1].map(reachLabel)).toEqual(["1 account affected", "3 accounts affected", "reach unknown"]);
  });

  it("names a job kind in words, as Health and the worker banner do", () => {
    expect(["hunt.daily", "detect.run"].map(jobWord)).toEqual(["daily hunts", "detection"]);
    expect(jobWord("brand_new.kind")).toBe("brand new kind");
  });
});

describe("silent rule labels", () => {
  it("says why a rule is silent", () => {
    expect(silentLabel("not_ingested")).toBe("not ingested");
    expect(silentLabel("field_empty:actor.user.name")).toBe("field empty: actor.user.name");
    expect(silentLabel("value_absent:ConsoleLogin")).toBe("never sent: ConsoleLogin");
  });

  it("says nothing for a rule that is merely quiet", () => {
    expect(silentLabel("quiet")).toBe("");
    expect(silentLabel("")).toBe("");
  });
});

describe("state words", () => {
  it("says planned for a dry run and expired for an approval nobody gave", () => {
    expect(actionState({ state: "done", dry_run: true, error: null, approved_by: "human:jane" }).word).toBe("planned");
    expect(actionState({ state: "done", dry_run: false, error: null, approved_by: null })).toEqual({ word: "done", tone: "good" });
    expect(actionState({ state: "rejected", dry_run: false, error: null, approved_by: null }).word).toBe("rejected");
    expect(actionState({ state: "rejected", dry_run: false, error: null, approved_by: "unattended" }).word).toBe("expired");
    expect(actionState({ state: "rolled_back", dry_run: false, error: null, approved_by: null }).word).toBe("undone");
    // A dry run never acted: undoing it reads "plan undone", apart from the Planned segment.
    expect(actionState({ state: "rolled_back", dry_run: true, error: null, approved_by: null }).word).toBe("plan undone");
  });

  it("says a page's state in a page's words, the same on every screen", () => {
    const page = (over: object) => ({ state: "done" as const, dry_run: false, error: null, approved_by: null, ...over });
    expect(pageState(page({})).word).toBe("delivered");
    expect(pageState(page({ dry_run: true })).word).toBe("planned");
    expect(pageState(page({ state: "rejected" })).word).toBe("not sent");
    expect(pageState(page({ state: "rolled_back" })).word).toBe("withdrawn");
  });

  it("calls informational info, and set-aside findings by their words", () => {
    expect(severityLabel("informational")).toBe("info");
    expect(findingStatus("self")).toBe("shoc's own");
    expect(findingStatus("false_positive")).toBe("rule was wrong");
  });

  it("gives every rule one state, in precedence", () => {
    const health = (over: Partial<RuleHealth>): RuleHealth =>
      ({ error: null, noisy: false, silent_reason: "", findings_7d: 0, ...over }) as RuleHealth;
    expect(ruleState(undefined)).toBeUndefined();
    expect(ruleState(health({ error: "boom", noisy: true }))).toBe("failing");
    expect(ruleState(health({ noisy: true }))).toBe("noisy");
    expect(ruleState(health({ silent_reason: "field_empty:actor.user.name", findings_7d: 2 }))).toBe("field_empty");
    expect(ruleState(health({ findings_7d: 2 }))).toBe("live");
    expect(ruleState(health({ silent_reason: "quiet" }))).toBe("armed");
    expect(ruleState(health({ silent_reason: "value_absent:ConsoleLogin" }))).toBe("never_sent");
    expect(ruleState(health({ silent_reason: "not_ingested" }))).toBe("no_source");
  });

  it("maps playbook step states onto the step marks", () => {
    expect(stepState("retrying")).toBe("running");
    expect(stepState("waiting")).toBe("waiting");
    expect(stepState("pending")).toBe("todo");
    expect(stepState("blocked")).toBe("failed");
  });

  it("finds a finding's case through the Sentinel when the row has none", () => {
    expect(findingCase({ case_uid: null, evidence: { sentinel: { decision: "attach", case_uid: "CASE-1" } } })).toBe("CASE-1");
    expect(findingCase({ evidence: { sentinel: { decision: "defer", case_uid: "CASE-1" } } })).toBeNull();
    expect(findingCase({ case_uid: "CASE-2", evidence: {} })).toBe("CASE-2");
  });

  it("says where a keyed lookup stands: off until set up, rate-limited by a 429, then at its quota", () => {
    const now = Date.parse("2026-10-05T12:00:00Z");
    const set = { configured: true, enabled: true, paused_until: null, calls_today: 3, per_day: 800 };
    expect(lookupState({ ...set, configured: false }, now).word).toBe("not set up");
    expect(lookupState({ ...set, enabled: false }, now).word).toBe("off");
    expect(lookupState({ ...set, paused_until: "2026-10-05T13:00:00Z" }, now)).toEqual({ word: "rate-limited", tone: "warn" });
    // A back-off that has run out no longer counts.
    expect(lookupState({ ...set, paused_until: "2026-10-05T11:00:00Z" }, now).word).toBe("ok");
    expect(lookupState({ ...set, calls_today: 800 }, now)).toEqual({ word: "quota reached", tone: "warn" });
  });

  it("says what a credential's read returned in one word everywhere", () => {
    expect(readWord(true)).toEqual({ word: "works", tone: "good" });
    expect(readWord(false)).toEqual({ word: "refused", tone: "bad" });
    // PagerDuty's routing key has nothing to read with.
    expect(readWord(null).word).toBe("no read to try");
  });

  it("names the model's provider, telling the two OpenAI APIs apart", () => {
    expect(modelProvider("anthropic")).toBe("Anthropic");
    expect(modelProvider("openai")).toBe("OpenAI");
    expect(modelProvider("openai-responses")).toBe("OpenAI Responses");
    expect(modelProvider("acme")).toBe("acme");
  });

  it("names an unread report's state, and warns only for one dropped for budget", () => {
    expect(queueState("same_story")).toMatchObject({ word: "same story", tone: "idle" });
    expect(queueState("dropped").tone).toBe("warn");
  });
});
