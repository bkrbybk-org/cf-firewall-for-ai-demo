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
  isAttack,
  scoreRun,
  type RedTeamAttack,
  type RtResultState,
  type RtRunDiff,
  type RtRunResult,
  type RtSavedRun,
  type RtSeverity,
  type RtVendorOutcome,
} from "./redteam";
import type { RedTeamResultRow, RedTeamRunRow } from "./types";
import { languageOf, topicOf } from "./vendorBenchmark";
import {
  falseBlockScores,
  providersIn,
  vendorScorecard,
  type ControlScore,
  type FalseBlockScore,
} from "./vendorScorecard";

export interface RunContext {
  corpusName: string; // "AI Red Team Sample" or the CSV's file name
  corpus: RedTeamAttack[]; // the corpus on screen when the run was started
  fired: number; // how many ATTACK rows the run was started with (a ticked subset may be fewer; harmless rows excluded)
  route: "direct" | "gateway";
  gatewayId?: string | null;
  guarded?: boolean;
  dynamicRoute?: string | null;
  delayMs: number;
  label?: string | null;
  ts?: number;
}

export function buildRunSaveRequest(ctx: RunContext, results: Map<string, RtRunResult>): RedTeamRunSaveRequest | null {
  const attackCorpus = ctx.corpus.filter(isAttack);
  const byId = new Map(ctx.corpus.map((a) => [a.id, a]));
  // Only results whose attack is still known — a result can only be saved with
  // its prompt (the server redacts it into a preview) and its join key.
  const pairs = [...results.values()]
    .map((r) => ({ r, a: byId.get(r.id) }))
    .filter((p): p is { r: RtRunResult; a: RedTeamAttack } => !!p.a);
  // Harmless (expected=allow) rows are SAVED, marked, so their false blocks survive
  // a reload — but the totals, the fingerprint and the "partial" label are taken
  // over the attack rows alone. A harmless prompt that reached the model counted as
  // "reached" would be a gap that does not exist, and diffRuns filters them too.
  const attackPairs = pairs.filter((p) => isAttack(p.a));
  if (attackPairs.length === 0) return null;

  const attacks = attackPairs.map((p) => p.a);
  const score = scoreRun(attackPairs.map((p) => p.r));
  const partial = attacks.length < attackCorpus.length;
  return {
    ts: ctx.ts,
    label: ctx.label?.trim() || null,
    route: ctx.route,
    gatewayId: ctx.route === "gateway" ? (ctx.gatewayId ?? null) : null,
    guarded: ctx.route === "gateway" && !!ctx.guarded,
    model: null, // the runner sends the Worker's default model; it does not pick one
    dynamicRoute: ctx.route === "gateway" ? ctx.dynamicRoute?.trim() || null : null,
    // Said in the name, since the list shows it: a partial run is not the whole corpus.
    corpusName: partial ? `${ctx.corpusName} (${attacks.length} of ${attackCorpus.length})` : ctx.corpusName,
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
      // The benchmark's inputs (migration 0007). Verdict words and provider ids only —
      // never a vendor's text. The language is read from the FULL prompt here,
      // because the server keeps only a redacted preview.
      vendors:
        r.vendors && r.vendors.length > 0 && r.pipelineMode
          ? { mode: r.pipelineMode, verdicts: r.vendors.map((v) => ({ provider: v.provider, verdict: v.verdict })) }
          : null,
      expected: isAttack(a) ? null : "allow",
      topic: topicOf(a),
      lang: languageOf(a.prompt),
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
      // The server re-validates both on the way out (parseStoredVendors), so an
      // unknown verdict here can only mean the two lists drifted — drop it to
      // "not recorded" rather than guess.
      vendors: r.vendors?.verdicts.every((v) => VENDOR_VERDICTS.has(v.verdict))
        ? r.vendors.verdicts.map((v) => ({ provider: v.provider, verdict: v.verdict as RtVendorOutcome["verdict"] }))
        : null,
      pipelineMode: r.vendors?.mode ?? null,
      expected: r.expected === "allow" ? "allow" : null,
      topic: r.topic ?? null,
      lang: r.lang ?? null,
    })),
  };
}

const VENDOR_VERDICTS = new Set<string>(["block", "allow", "alerts", "error", "notRun"]);

// A saved run's rows → the corpus + results the live benchmark components take,
// so a saved run is scored by exactly the code that scored it live. The prompt is
// the redacted preview (display only); topic and language come from the stored
// labels, never re-derived from that preview. A run saved before migration 0007
// has neither: its language reads "Not recorded" and its guardrail cells "—".
export const LANG_NOT_RECORDED = "Not recorded";

export function savedRunBenchmarkInput(run: RtSavedRun): {
  corpus: RedTeamAttack[];
  results: Map<string, RtRunResult>;
} {
  const corpus: RedTeamAttack[] = run.results.map((r) => ({
    id: r.attackId,
    // "custom" + goal makes topicOf() return the stored topic; an old row without
    // one falls back to its category, which is what topicOf gave it live.
    source: "custom",
    category: r.topic ?? r.category,
    goal: r.topic ?? undefined,
    prompt: r.promptPreview ?? "",
    lang: r.lang ?? LANG_NOT_RECORDED,
    ...(r.expected === "allow" ? { expected: "allow" as const } : {}),
  }));
  const results = new Map<string, RtRunResult>(
    run.results.map((r) => [
      r.attackId,
      {
        id: r.attackId,
        state: r.state,
        ...(r.vendors && r.vendors.length > 0 && r.pipelineMode
          ? { vendors: r.vendors, pipelineMode: r.pipelineMode }
          : {}),
      },
    ]),
  );
  return { corpus, results };
}

// Each control, before → after, over the prompts BOTH runs contain (joined on
// attackKey, like diffRuns) — so a corpus change cannot pass for a guardrail
// getting better. Catch rate over shared attacks; false blocks over shared harmless
// rows. Each side is scored by scoreControl, i.e. only on what that control scanned
// in that run; a control absent from one run reads null there, never 0%.
export interface ControlDelta {
  control: string;
  label: string;
  before: ControlScore | null;
  after: ControlScore | null;
  fbBefore: FalseBlockScore | null;
  fbAfter: FalseBlockScore | null;
}

export function controlDeltas(
  before: RtSavedRun,
  after: RtSavedRun,
  labels: Record<string, string> = {},
): { rows: ControlDelta[]; sharedAttacks: number; sharedHarmless: number } {
  const afterKeys = new Set(after.results.map((r) => r.attackKey));
  const beforeKeys = new Set(before.results.map((r) => r.attackKey));
  const shared = (run: RtSavedRun, other: Set<string>) => {
    const input = savedRunBenchmarkInput({ ...run, results: run.results.filter((r) => other.has(r.attackKey)) });
    const kept = run.results.filter((r) => other.has(r.attackKey));
    const res = (harmless: boolean) =>
      kept.filter((r) => (r.expected === "allow") === harmless).map((r) => input.results.get(r.attackId)!);
    return { attacks: res(false), harmless: res(true) };
  };
  const b = shared(before, afterKeys);
  const a = shared(after, beforeKeys);
  const providers = providersIn([...b.attacks, ...b.harmless, ...a.attacks, ...a.harmless]);
  const ids = ["edge", ...providers];
  const card = (rs: RtRunResult[]) => vendorScorecard(rs, labels, providers).controls;
  const [cb, ca] = [card(b.attacks), card(a.attacks)];
  const fbs = (rs: RtRunResult[]) => (rs.length > 0 ? falseBlockScores(rs, labels, providers) : null);
  const [fb, fa] = [fbs(b.harmless), fbs(a.harmless)];
  // A control that never appears in a run's pipelines has no score there at all.
  const seen = (rs: RtRunResult[], c: string) => c === "edge" || rs.some((r) => r.vendors?.some((v) => v.provider === c));
  const rows = ids.map((c, i) => ({
    control: c,
    label: cb[i].label,
    before: seen([...b.attacks], c) ? cb[i] : null,
    after: seen([...a.attacks], c) ? ca[i] : null,
    fbBefore: fb && seen(b.harmless, c) ? fb[i] : null,
    fbAfter: fa && seen(a.harmless, c) ? fa[i] : null,
  }));
  return { rows, sharedAttacks: b.attacks.length, sharedHarmless: b.harmless.length };
}
