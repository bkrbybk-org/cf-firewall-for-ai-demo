// Glue between a finished Red Team run on the page and the saved-run API
// (/api/redteam-runs): build the save body, and turn a fetched run back into the
// RtSavedRun that diffRuns() compares. Pure, so the two decisions that matter are
// testable without a browser:
//  - WHICH attack set a saved run claims. Its fingerprint is taken over the attacks
//    that actually have a result, not the whole corpus on screen: a subset run or a
//    stopped run did not fire the rest, and claiming the full corpus would let
//    diffRuns call two different attack sets "the same corpus".
//  - the totals saved are scoreRun() over exactly those results, including
//    `external` and `skipped` — the server stores what it is sent and defaults a
//    missing count to 0, which would silently erase them.
import type { RedTeamRunSaveRequest } from "./api";
import {
  attackKey,
  corpusFingerprint,
  scoreRun,
  type RedTeamAttack,
  type RtResultState,
  type RtRunDiff,
  type RtRunResult,
  type RtSavedRun,
  type RtSeverity,
} from "./redteam";
import type { RedTeamResultRow, RedTeamRunRow } from "./types";

export interface RunContext {
  corpusName: string; // "AI Red Team Sample" or the CSV's file name
  corpus: RedTeamAttack[]; // the corpus on screen when the run was started
  fired: number; // how many attacks the run was started with (a ticked subset may be fewer than corpus)
  route: "direct" | "gateway";
  gatewayId?: string | null;
  guarded?: boolean;
  dynamicRoute?: string | null;
  delayMs: number;
  label?: string | null;
  ts?: number;
}

export function buildRunSaveRequest(ctx: RunContext, results: Map<string, RtRunResult>): RedTeamRunSaveRequest | null {
  const byId = new Map(ctx.corpus.map((a) => [a.id, a]));
  // Only results whose attack is still known — a result can only be saved with
  // its prompt (the server redacts it into a preview) and its join key.
  const pairs = [...results.values()]
    .map((r) => ({ r, a: byId.get(r.id) }))
    .filter((p): p is { r: RtRunResult; a: RedTeamAttack } => !!p.a);
  if (pairs.length === 0) return null;

  const attacks = pairs.map((p) => p.a);
  const score = scoreRun(pairs.map((p) => p.r));
  const partial = attacks.length < ctx.corpus.length;
  return {
    ts: ctx.ts,
    label: ctx.label?.trim() || null,
    route: ctx.route,
    gatewayId: ctx.route === "gateway" ? (ctx.gatewayId ?? null) : null,
    guarded: ctx.route === "gateway" && !!ctx.guarded,
    model: null, // the runner sends the Worker's default model; it does not pick one
    dynamicRoute: ctx.route === "gateway" ? ctx.dynamicRoute?.trim() || null : null,
    // Said in the name, since the list shows it: a partial run is not the whole corpus.
    corpusName: partial ? `${ctx.corpusName} (${attacks.length} of ${ctx.corpus.length})` : ctx.corpusName,
    corpusSize: ctx.fired,
    corpusFingerprint: corpusFingerprint(attacks),
    delayMs: ctx.delayMs,
    ...score,
    results: pairs.map(({ r, a }) => ({
      attackKey: attackKey(a),
      attackId: a.id,
      category: a.category,
      severity: a.severity ?? null,
      state: r.state,
      ray: r.ray ?? null,
      ts: r.ts ?? null,
      prompt: a.prompt,
    })),
  };
}

// What changed between two saved runs, attack by attack, in words a "the gap closed"
// claim can stand on. diffRuns' reachedDelta alone cannot: an attack that reached the
// model before and has NO verdict after (pending, error, a non-WAF refusal) leaves
// `reached` too, so a run whose verdicts never resolved would read as a win. And an
// attack now stopped by an external guardrail or AI Gateway Guardrails was not
// stopped by the edge. So the summary keeps those apart.
export type StopControl = "edge" | "external" | "guardrails";
const REACHED = new Set<RtResultState>(["allow", "log"]);
const STOPPED_BY: Partial<Record<RtResultState, StopControl>> = {
  block: "edge",
  challenge: "edge",
  external: "external",
  guardrails: "guardrails",
};

export interface DiffSummary {
  closed: Record<StopControl, number>; // reached before → stopped after, by the control that stopped it
  closedTotal: number;
  opened: number; // did not reach before (stopped, or no verdict) → reached after
  lostVerdict: number; // reached before → no verdict after: neither a fix nor a regression
  otherChanges: number; // e.g. stopped by one control → another, or no verdict → stopped
}

export function summarizeDiff(diff: RtRunDiff): DiffSummary {
  const closed: Record<StopControl, number> = { edge: 0, external: 0, guardrails: 0 };
  let opened = 0;
  let lostVerdict = 0;
  let otherChanges = 0;
  for (const r of diff.rows) {
    if (r.status !== "changed" || !r.before || !r.after) continue;
    const wasReached = REACHED.has(r.before);
    const isReached = REACHED.has(r.after);
    const stop = STOPPED_BY[r.after];
    if (wasReached && stop) closed[stop]++;
    else if (!wasReached && isReached) opened++;
    else if (wasReached && !isReached) lostVerdict++;
    else otherChanges++;
  }
  return { closed, closedTotal: closed.edge + closed.external + closed.guardrails, opened, lostVerdict, otherChanges };
}

const SEVERITIES = new Set<string>(["critical", "high", "medium", "low"]);

// The wire rows are what the Worker stored after validating every state against
// its whitelist (src/redteamruns.ts RT_RESULT_STATES), so the cast is safe; a
// severity outside the four known values (a custom corpus has none) becomes null
// rather than a label nobody defined.
export function toSavedRun(run: RedTeamRunRow, results: RedTeamResultRow[]): RtSavedRun {
  return {
    ...run,
    results: results.map((r) => ({
      attackKey: r.attackKey,
      attackId: r.attackId,
      category: r.category,
      severity: r.severity && SEVERITIES.has(r.severity) ? (r.severity as RtSeverity) : null,
      state: r.state as RtResultState,
      ray: r.ray,
      ts: r.ts,
      promptPreview: r.promptPreview,
    })),
  };
}
