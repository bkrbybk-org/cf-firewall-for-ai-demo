// #17: vendor outage alerts. Every hour a Cron Trigger reads the last hour of guardrail verdicts from Analytics Engine
// (the same rows and the same aggregation as the Analytics page — src/guardrailAnalytics.ts) and decides, per vendor,
// whether it is DOWN: too many of its checks ended with no verdict (an error, whether its fail mode then stopped the
// turn or let it through).
//
// Decided with the user (2026-10-12): alerts go to a webhook the operator sets as a secret (ALERT_WEBHOOK_URL); until
// it is set, an alert is only a line in the Worker's logs and nothing leaves Cloudflare.
//
// The rules:
//   - **Down** = at least ALERT_MIN_CHECKS checks in the hour, and at least ALERT_NO_VERDICT_RATE of them with no
//     verdict. Prompt and reply checks count together: an outage is the vendor's, not one check's.
//   - **Too few checks is "unknown", never "ok".** A quiet hour says nothing about a vendor; it keeps the state it had.
//     (The scheduled re-run sends 12 prompts every 6 hours, so an enabled vendor is never quiet for long.)
//   - **Alert on a change only**: ok → down, and down → ok ("recovered"). The state is kept in D1
//     (migration 0011), so an outage is one message, not one an hour. A vendor never seen before that is already down
//     alerts; one first seen healthy just records "ok".
//   - **What a message holds:** vendor names, counts, the rate and the window. Never an error text (it can carry a
//     vendor's message), a prompt, or the webhook URL itself.
//   - Sampled rows are weighted, as on the page; the rate is a ratio of weighted counts.
//   - **A rejected key is named** (2026-10-18): when most checks without a verdict got HTTP 401/403, the message says
//     the vendor rejected the key and where to fix it. Still one "down" state — the fix differs, the outage does not.

import { deliverAlert, webhookUrl } from "./alertDelivery";
import { PROVIDERS } from "./externalGuardrails";
import { aggregate, buildSql, parseRow, type VendorStats, type VerdictRow } from "./guardrailAnalytics";
import { SCHEDULED_PROMPTS, SCHEDULED_SET_VERSION } from "./scheduledCorpus";
import { RERUN_CRON } from "./scheduledRerun";
import type { Env, ExternalGuardrailProvider } from "./types";
import { WATCH_CONFIRM_RUNS, watchStatus } from "./verdictWatch";

export const ALERT_CRON = "17 * * * *";
export const ALERT_WINDOW_HOURS = 1;
export const ALERT_MIN_CHECKS = 3;
export const ALERT_NO_VERDICT_RATE = 0.5;
export { webhookUrl }; // kept here too: tests and Settings import it from this module

export type AlertState = "ok" | "down";

export interface VendorCheck {
  provider: ExternalGuardrailProvider;
  checked: number; // weighted: block + allow + error + failedOpen, prompt and reply together
  noVerdict: number; // error + failedOpen
  authFailed: number; // of noVerdict: HTTP 401/403 — the vendor rejected the key
  state: AlertState | "unknown";
}

// "Key rejected" when most of the checks without a verdict were 401/403 — a mixed outage (some timeouts) still reads
// as the more common cause, and a single stray 403 among timeouts does not send the operator to rotate a good key.
export const keyRejected = (c: { noVerdict: number; authFailed: number }) => c.noVerdict > 0 && c.authFailed / c.noVerdict > 0.5;

// Per vendor, prompt and reply checks together.
export function evaluate(vendors: VendorStats[]): VendorCheck[] {
  const by = new Map<ExternalGuardrailProvider, { checked: number; noVerdict: number; authFailed: number }>();
  for (const v of vendors) {
    const e = by.get(v.provider) ?? { checked: 0, noVerdict: 0, authFailed: 0 };
    e.checked += v.checked;
    e.noVerdict += v.error + v.failedOpen;
    e.authFailed += v.authFailed ?? 0;
    by.set(v.provider, e);
  }
  return [...by.entries()].map(([provider, e]) => ({
    provider,
    ...e,
    state:
      e.checked < ALERT_MIN_CHECKS ? "unknown" : e.noVerdict / e.checked >= ALERT_NO_VERDICT_RATE ? "down" : "ok",
  }));
}

export interface Transition {
  provider: ExternalGuardrailProvider;
  to: AlertState;
  from: AlertState | null; // null: never seen before
  checked: number;
  noVerdict: number;
  authFailed: number;
}

// What changed since the stored states. `unknown` changes nothing. A first sighting alerts only when it is already down.
export function transitions(prev: Map<ExternalGuardrailProvider, AlertState>, now: VendorCheck[]): Transition[] {
  const out: Transition[] = [];
  for (const c of now) {
    if (c.state === "unknown") continue;
    const before = prev.get(c.provider) ?? null;
    if (before === c.state) continue;
    if (before === null && c.state === "ok") continue; // recorded, not announced
    out.push({ provider: c.provider, to: c.state, from: before, checked: c.checked, noVerdict: c.noVerdict, authFailed: c.authFailed });
  }
  return out;
}

const pct = (n: number, d: number) => `${Math.round((n / d) * 100)}%`;
const count = (n: number) => (Number.isInteger(n) ? String(n) : `≈${Math.round(n)}`);

export function alertText(t: Transition[], windowHours = ALERT_WINDOW_HOURS): string {
  const lines = t.map((x) =>
    x.to === "down"
      ? keyRejected(x)
        ? `🔑 ${PROVIDERS[x.provider].label} REJECTED THE KEY: ${count(x.authFailed)} of ${count(x.checked)} checks got HTTP 401/403 in the last ${windowHours}h. Issue a new key in the vendor's console, then save it in Settings → ${PROVIDERS[x.provider].label}.`
        : `🔴 ${PROVIDERS[x.provider].label} looks DOWN: ${count(x.noVerdict)} of ${count(x.checked)} checks (${pct(x.noVerdict, x.checked)}) got no verdict in the last ${windowHours}h.`
      : `🟢 ${PROVIDERS[x.provider].label} recovered: ${count(x.noVerdict)} of ${count(x.checked)} checks without a verdict in the last ${windowHours}h.`,
  );
  return ["cf-ai-waf-demo — external guardrail health", ...lines].join("\n");
}

export interface AlertRunSummary {
  event: "guardrail_alert_check";
  vendors: { provider: ExternalGuardrailProvider; state: VendorCheck["state"]; checked: number; noVerdict: number; authFailed: number }[];
  alerts: number;
  delivered: "webhook" | "log" | "none" | "failed";
  skipped?: string;
}

export async function runVendorAlerts(
  env: Env,
  deps: { fetchImpl?: typeof fetch; now?: number; log?: (line: unknown) => void } = {},
): Promise<AlertRunSummary> {
  const log = deps.log ?? ((line: unknown) => console.log(line));
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now();
  const base = { event: "guardrail_alert_check" as const, vendors: [], alerts: 0, delivered: "none" as const };
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID || !env.DB) {
    const s = { ...base, skipped: "needs CF_ANALYTICS_TOKEN, CF_ACCOUNT_ID and the DB binding" };
    log(s);
    return s;
  }

  // 1. The last hour, every source — an outage is an outage whoever's turn found it.
  const res = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
    method: "POST",
    headers: { authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
    body: buildSql(ALERT_WINDOW_HOURS, "all"),
  });
  if (!res.ok) {
    // Not an alert: the check itself failed. Logged, and no state changes (an unread hour is not a healthy one).
    const s = { ...base, skipped: `Analytics Engine returned HTTP ${res.status}` };
    log(s);
    return s;
  }
  const body = (await res.json()) as { data?: unknown[] };
  const raw = Array.isArray(body.data) ? body.data : [];
  const rows = raw.map(parseRow).filter((r): r is VerdictRow => r != null);
  const agg = aggregate(rows, { hours: ALERT_WINDOW_HOURS, now, source: "all", rowsRead: raw.length, rowsDropped: raw.length - rows.length });
  const checks = evaluate(agg.vendors);

  // 2. Compare with the stored states, then store what this hour saw.
  const { results } = await env.DB.prepare("SELECT provider, state FROM guardrail_alert_state").all<{ provider: string; state: string }>();
  const prev = new Map<ExternalGuardrailProvider, AlertState>();
  for (const r of results ?? []) {
    if (r.provider in PROVIDERS && (r.state === "ok" || r.state === "down")) prev.set(r.provider as ExternalGuardrailProvider, r.state);
  }
  const changed = transitions(prev, checks);
  const known = checks.filter((c) => c.state !== "unknown");
  if (known.length) {
    await env.DB.batch(
      known.map((c) =>
        env.DB!.prepare(
          `INSERT INTO guardrail_alert_state (provider, state, since, updated_at) VALUES (?,?,?,?)
           ON CONFLICT(provider) DO UPDATE SET
             since = CASE WHEN guardrail_alert_state.state = excluded.state THEN guardrail_alert_state.since ELSE excluded.since END,
             state = excluded.state, updated_at = excluded.updated_at`,
        ).bind(c.provider, c.state, now, now),
      ),
    );
  }

  const vendors = checks.map(({ provider, state, checked, noVerdict, authFailed }) => ({ provider, state, checked, noVerdict, authFailed }));
  if (changed.length === 0) {
    const s = { ...base, vendors };
    log(s);
    return s;
  }

  // 3. Deliver. The text names vendors and counts only.
  const text = alertText(changed);
  const payload = {
    text,
    alerts: changed.map((t) => ({ ...t, label: PROVIDERS[t.provider].label })),
    windowHours: ALERT_WINDOW_HOURS,
    at: new Date(now).toISOString(),
  };
  const delivered = await deliverAlert(env, "guardrail_alert", payload, { fetchImpl, log });
  const s = { ...base, vendors, alerts: changed.length, delivered };
  log(s);
  return s;
}

// What Settings shows about the two schedules (#15, #17). The webhook only as set / not set — never its value.
export async function automationStatus(env: Env) {
  return {
    rerun: { cron: RERUN_CRON, prompts: SCHEDULED_PROMPTS.length, setVersion: SCHEDULED_SET_VERSION },
    alerts: {
      cron: ALERT_CRON,
      windowHours: ALERT_WINDOW_HOURS,
      minChecks: ALERT_MIN_CHECKS,
      noVerdictRate: ALERT_NO_VERDICT_RATE,
      webhook: env.ALERT_WEBHOOK_URL ? (webhookUrl(env.ALERT_WEBHOOK_URL) ? "set" : "invalid") : "unset",
      states: await loadAlertStates(env.DB),
    },
    // 2026-10-18: verdict changes on the scheduled prompts. null when the table cannot be read (migration 0012).
    verdictWatch: { confirmRuns: WATCH_CONFIRM_RUNS, ...((await watchStatus(env.DB)) ?? { tracked: null, pending: null }) },
  };
}

// For the Settings page: the stored states, read-only. Empty when the table is missing (migration not applied).
export async function loadAlertStates(
  db: D1Database | undefined,
): Promise<{ provider: ExternalGuardrailProvider; state: AlertState; since: number; updatedAt: number }[]> {
  if (!db) return [];
  try {
    const { results } = await db
      .prepare("SELECT provider, state, since, updated_at FROM guardrail_alert_state")
      .all<{ provider: string; state: string; since: number; updated_at: number }>();
    return (results ?? [])
      .filter((r) => r.provider in PROVIDERS && (r.state === "ok" || r.state === "down"))
      .map((r) => ({ provider: r.provider as ExternalGuardrailProvider, state: r.state as AlertState, since: r.since, updatedAt: r.updated_at }));
  } catch {
    return [];
  }
}
