// Verdict changes on the fixed prompts (2026-10-18). After each scheduled re-run (src/scheduledRerun.ts), every
// vendor's verdict on every prompt of the set is compared with the last one it CONFIRMED there; a change is announced
// through the same webhook as the outage alerts (src/alertDelivery.ts).
//
// Why: on 2026-10-16 Lakera began blocking one more attack and one more harmless Thai prompt, with nothing changed on
// our side — and it was found by reading the counts by hand a day later. A vendor's detector update or a policy edit
// in its console changes what the demo shows; the operator should hear of it, and of which prompt.
//
// The rules:
//   - **A verdict is block or allow.** An error, a fail-open, a timeout is not a verdict and never touches a row: an
//     outage must not read as "now allows everything" (that is the outage alert's job, src/vendorAlerts.ts).
//   - **Confirmed over two runs in a row.** A new verdict seen once is held as `pending`; it becomes the verdict, and is
//     announced, only when the next run with a verdict agrees. One noisy answer is never an alert. An error between the
//     two runs neither confirms nor clears a pending verdict; a return to the old verdict clears it.
//   - **The first sighting is recorded, not announced:** there is nothing to change from.
//   - **A message holds** vendor names, prompt ids ("han-600"), their label (attack / harmless) and dates. Never a
//     prompt's text — the operator looks the id up in src/scheduledCorpus.ts.
//   - **Keyed by the set's version** ("v1/han-600"): bumping SCHEDULED_SET_VERSION starts every prompt afresh.

import { deliverAlert, type Delivery } from "./alertDelivery";
import { PROVIDERS } from "./externalGuardrails";
import { SCHEDULED_PROMPTS, SCHEDULED_SET_VERSION } from "./scheduledCorpus";
import type { Env, ExternalGuardrailProvider, GuardrailPipelineResult } from "./types";

export const WATCH_CONFIRM_RUNS = 2; // a new verdict must hold this many runs in a row (the logic below is for 2)

type Verdict = "block" | "allow";

export interface Watched {
  provider: ExternalGuardrailProvider;
  promptId: string; // "v1/han-600"
  outcome: Verdict;
  since: number;
  pending: Verdict | null;
}

export interface Observed {
  provider: ExternalGuardrailProvider;
  promptId: string;
  outcome: Verdict;
}

export interface VerdictChange {
  provider: ExternalGuardrailProvider;
  promptId: string;
  from: Verdict;
  to: Verdict;
  heldSince: number; // when the OLD verdict began
}

export const watchKey = (id: string) => `v${SCHEDULED_SET_VERSION}/${id}`;
const pairKey = (provider: string, promptId: string) => `${provider}|${promptId}`;

// Pure: the rows to write and the changes to announce.
export function step(stored: Map<string, Watched>, observed: Observed[], now: number): { writes: Watched[]; changes: VerdictChange[] } {
  const writes: Watched[] = [];
  const changes: VerdictChange[] = [];
  for (const o of observed) {
    const s = stored.get(pairKey(o.provider, o.promptId));
    if (!s) {
      writes.push({ provider: o.provider, promptId: o.promptId, outcome: o.outcome, since: now, pending: null });
    } else if (s.outcome === o.outcome) {
      writes.push({ ...s, pending: null }); // back to (or still at) the confirmed verdict: any pending one is dropped
    } else if (s.pending === o.outcome) {
      changes.push({ provider: o.provider, promptId: o.promptId, from: s.outcome, to: o.outcome, heldSince: s.since });
      writes.push({ ...s, outcome: o.outcome, since: now, pending: null });
    } else {
      writes.push({ ...s, pending: o.outcome }); // seen once: wait for the next run
    }
  }
  return { writes, changes };
}

// What one run observed: prompt checks with a verdict only, keyed by the set's version.
export function observedOf(runs: { id: string; pipeline: GuardrailPipelineResult | null }[]): Observed[] {
  const out: Observed[] = [];
  for (const r of runs) {
    for (const v of r.pipeline?.results ?? []) {
      if (v.outcome === "block" || v.outcome === "allow") out.push({ provider: v.provider, promptId: watchKey(r.id), outcome: v.outcome });
    }
  }
  return out;
}

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export function changeText(changes: VerdictChange[]): string {
  const expectOf = new Map(SCHEDULED_PROMPTS.map((p) => [watchKey(p.id), p.expect]));
  const lines = changes.map((c) => {
    const id = c.promptId.replace(/^v\d+\//, "");
    const benign = expectOf.get(c.promptId) === "benign";
    const what =
      c.to === "block"
        ? benign
          ? `now BLOCKS harmless prompt ${id} — a new false block`
          : `now catches attack ${id}`
        : benign
          ? `no longer blocks harmless prompt ${id}`
          : `now ALLOWS attack ${id} — a new miss`;
    return `🔀 ${PROVIDERS[c.provider].label} ${what} (it had ${c.from === "block" ? "blocked" : "allowed"} it since ${day(c.heldSince)}).`;
  });
  return [
    `cf-ai-waf-demo — a vendor changed its verdict on the scheduled prompts (held for ${WATCH_CONFIRM_RUNS} runs in a row)`,
    ...lines,
  ].join("\n");
}

export interface WatchSummary {
  event: "guardrail_verdict_watch";
  observed: number;
  changes: number;
  pending: number; // pairs now holding an unconfirmed verdict
  delivered: Delivery | "none";
  skipped?: string;
}

interface Row {
  provider: string;
  prompt_id: string;
  outcome: string;
  since: number;
  pending: string | null;
}

export async function runVerdictWatch(
  env: Env,
  runs: { id: string; pipeline: GuardrailPipelineResult | null }[],
  deps: { fetchImpl?: typeof fetch; now?: number; log?: (line: unknown) => void } = {},
): Promise<WatchSummary> {
  const log = deps.log ?? ((line: unknown) => console.log(line));
  const now = deps.now ?? Date.now();
  const observed = observedOf(runs);
  const base = { event: "guardrail_verdict_watch" as const, observed: observed.length, changes: 0, pending: 0, delivered: "none" as const };
  if (!env.DB) return done({ ...base, skipped: "no DB binding" });
  if (observed.length === 0) return done({ ...base, skipped: "no verdicts this run" });

  let rows: Row[];
  try {
    rows = (await env.DB.prepare("SELECT provider, prompt_id, outcome, since, pending FROM guardrail_prompt_verdicts").all<Row>()).results ?? [];
  } catch {
    return done({ ...base, skipped: "table guardrail_prompt_verdicts missing (migration 0012 not applied)" });
  }
  const stored = new Map<string, Watched>();
  for (const r of rows) {
    if (!(r.provider in PROVIDERS) || (r.outcome !== "block" && r.outcome !== "allow")) continue;
    const pending = r.pending === "block" || r.pending === "allow" ? r.pending : null;
    stored.set(pairKey(r.provider, r.prompt_id), {
      provider: r.provider as ExternalGuardrailProvider,
      promptId: r.prompt_id,
      outcome: r.outcome,
      since: r.since,
      pending,
    });
  }
  const { writes, changes } = step(stored, observed, now);
  await env.DB.batch(
    writes.map((w) =>
      env.DB!.prepare(
        `INSERT INTO guardrail_prompt_verdicts (provider, prompt_id, outcome, since, pending, updated_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT(provider, prompt_id) DO UPDATE SET outcome = excluded.outcome, since = excluded.since,
           pending = excluded.pending, updated_at = excluded.updated_at`,
      ).bind(w.provider, w.promptId, w.outcome, w.since, w.pending, now),
    ),
  );
  const pending = writes.filter((w) => w.pending != null).length;
  if (changes.length === 0) return done({ ...base, pending });

  const payload = {
    text: changeText(changes),
    verdictChanges: changes.map((c) => ({ ...c, label: PROVIDERS[c.provider].label })),
    confirmRuns: WATCH_CONFIRM_RUNS,
    at: new Date(now).toISOString(),
  };
  const delivered = await deliverAlert(env, "guardrail_verdict_change", payload, { fetchImpl: deps.fetchImpl, log });
  return done({ ...base, changes: changes.length, pending, delivered });

  function done(s: WatchSummary): WatchSummary {
    log(s);
    return s;
  }
}

// For Settings: how many vendor × prompt pairs are watched, and how many hold an unconfirmed verdict. Never throws.
export async function watchStatus(db: D1Database | undefined): Promise<{ tracked: number; pending: number } | null> {
  if (!db) return null;
  try {
    const r = await db
      .prepare("SELECT COUNT(*) AS tracked, SUM(CASE WHEN pending IS NULL THEN 0 ELSE 1 END) AS pending FROM guardrail_prompt_verdicts")
      .first<{ tracked: number; pending: number | null }>();
    return { tracked: r?.tracked ?? 0, pending: r?.pending ?? 0 };
  } catch {
    return null;
  }
}
