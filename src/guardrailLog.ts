// The record of each external guardrail verdict: one Workers Logs line (for browsing single turns) and one
// Analytics Engine data point (for counting — what the Analytics page's "External guardrails" tab reads back
// through src/guardrailAnalytics.ts), instead of a D1 table.
//
// Decided with the user (2026-10-09): no database of ours. Workers Logs came first, but this account samples it on
// ingest (see the Analytics Engine section below), so the counted copy is Analytics Engine (kept 3 months).
//
// PRIVACY — what a line may hold is an allowlist, built field by field (never by spreading a result):
//   - vendor, prompt/reply, outcome, the alert / redaction / incomplete flags, latency, HTTP status;
//   - the NAMES of what fired (`detected`, already shape-checked by each vendor's parser);
//   - the Cloudflare ray (to join with the edge events and the prompt log), the vendor's scan id (to look
//     the verdict up in that vendor's console), the pipeline mode, whether this vendor decided the turn.
// Never: the prompt, the reply, `error` text (it can carry a vendor's message), `raw`, `summary`,
// `category` beyond Datadog's deny/abort token, or `policy` (operator free text).

import type { ExternalGuardrailProvider, ExternalGuardrailResult, GuardrailPipelineResult } from "./types";

// The marker every line carries, so the query can select exactly these lines out of the Worker's logs.
export const VERDICT_EVENT = "guardrail_verdict";
// Bumped if a field changes meaning, so the reader can refuse a shape it does not know.
export const VERDICT_SCHEMA = 1;

export type VerdictOutcome = "block" | "allow" | "error" | "failed_open" | "not_run";
// Where the turn came from. "redteam" is the app's own Red Team page (it says so in a request header);
// everything else — the chat page, the API, an external scanner — is "chat".
export type VerdictSource = "chat" | "redteam";

export interface VerdictLine {
  event: typeof VERDICT_EVENT;
  v: typeof VERDICT_SCHEMA;
  src: VerdictSource;
  dir: "prompt" | "reply";
  provider: ExternalGuardrailProvider;
  outcome: VerdictOutcome;
  alerts: boolean; // allow with alerts (detectOnly)
  redaction: boolean; // redaction requested, not applied (transformed)
  incomplete: boolean; // a vendor sub-check timed out (Prisma AIRS)
  decided: boolean; // this vendor's verdict stopped the turn
  ms: number | null; // the vendor call's latency; null when it never ran
  status: number | null; // the vendor's HTTP status, when it answered
  detected: string; // comma-joined names; "" when nothing fired
  ray: string | null;
  scanId: string | null;
  mode: "sequential" | "parallel";
  action: string | null; // Datadog's "deny" / "abort" only — the one category that is a fixed token
}

const NAME = /^[A-Za-z0-9_.:\-/ ]{1,80}$/;
const SCAN_ID = /^[A-Za-z0-9_.:-]{1,100}$/;

function outcomeOf(r: ExternalGuardrailResult): VerdictOutcome {
  if (r.outcome === "block") return "block";
  if (r.outcome === "allow") return "allow";
  return r.failedOpen ? "failed_open" : "error";
}

// The lines for one pipeline run: one per vendor that ran, and one per vendor listed as not run (so a
// vendor skipped after a block is counted as skipped, never as missing).
export function verdictLines(p: GuardrailPipelineResult, src: VerdictSource, ray: string | null): VerdictLine[] {
  // The bare ray id ("8f1c…", not "8f1c…-SIN"): the form the edge's firewall events carry as rayName, so
  // a line joins to the edge verdict; the prompt log's full cf-ray starts with it.
  const rayId = ray ? ray.split("-")[0].trim() || null : null;
  const base = { event: VERDICT_EVENT, v: VERDICT_SCHEMA, src, dir: p.direction ?? "prompt", ray: rayId, mode: p.mode } as const;
  const ran = p.results.map(
    (r): VerdictLine => ({
      ...base,
      provider: r.provider,
      outcome: outcomeOf(r),
      // Flags describe a verdict; an error has none, whatever the result object carries.
      alerts: r.outcome === "allow" && !!r.detectOnly,
      redaction: r.outcome === "allow" && !!r.transformed,
      incomplete: r.outcome !== "error" && !!r.incomplete,
      decided: p.stoppedBy === r.provider,
      ms: Number.isFinite(r.latencyMs) ? Math.max(0, Math.round(r.latencyMs)) : null,
      status: typeof r.httpStatus === "number" ? r.httpStatus : null,
      detected: r.outcome === "error" ? "" : [...new Set((r.detected ?? []).filter((d) => NAME.test(d)))].join(","),
      scanId: typeof r.scanId === "string" && SCAN_ID.test(r.scanId) ? r.scanId : null,
      action:
        r.provider === "datadog-ai-guard" && (r.category === "deny" || r.category === "abort") ? r.category : null,
    }),
  );
  const skipped = p.notRun.map(
    (n): VerdictLine => ({
      ...base,
      provider: n.provider,
      outcome: "not_run",
      alerts: false,
      redaction: false,
      incomplete: false,
      decided: false,
      ms: null,
      status: null,
      detected: "",
      scanId: null,
      action: null,
    }),
  );
  return [...ran, ...skipped];
}

// ── Analytics Engine ────────────────────────────────────────────────────────
// The COUNTED copy. Workers Logs turned out to be sampled on ingest for this account (a turn's 10 lines
// came back as 6, and six smoke-test turns not at all — PROGRESS.md 2026-10-09), so the analytics read
// Analytics Engine instead, which samples only at very high volume, per index, and reports it per row
// (`_sample_interval`). The log line stays, for looking at single turns in the dashboard.
//
// Column positions are the schema (AE has no names): src/guardrailAnalytics.ts reads exactly these.
//
// The INDEX is unique per data point (ray | check | vendor), on purpose. AE samples "based on the index … only
// indexes that receive large numbers of events" — and with the vendor as the index, 4 turns in 15 s (7 points
// per vendor) were already stored as 5, two of them counted x2 (measured on prod, 2026-10-09). An index that
// never repeats never receives "many" events. Nothing queries by index; the vendor is in blob4.
export const AE_SCHEMA = "gv1"; // blob1 — lets the reader skip rows of any other shape

export function dataPointOf(l: VerdictLine, unique: () => string = () => crypto.randomUUID()): AnalyticsEngineDataPoint {
  // At most 96 bytes (AE's index limit): a 16-char ray, "prompt"/"reply", a vendor id of 18 chars or fewer. With
  // no ray (local dev, tests) a random id keeps it unique.
  return {
    indexes: [`${l.ray ?? unique()}|${l.dir}|${l.provider}`],
    blobs: [
      AE_SCHEMA, // blob1
      l.src, // blob2
      l.dir, // blob3
      l.provider, // blob4
      l.outcome, // blob5
      l.detected, // blob6
      l.ray ?? "", // blob7
      l.scanId ?? "", // blob8
      l.mode, // blob9
      l.action ?? "", // blob10
    ],
    doubles: [
      l.ms ?? -1, // double1 — -1: the vendor never ran (not_run), so there is no latency to count
      l.status ?? 0, // double2 — 0: no HTTP answer
      l.alerts ? 1 : 0, // double3
      l.redaction ? 1 : 0, // double4
      l.incomplete ? 1 : 0, // double5
      l.decided ? 1 : 0, // double6
    ],
  };
}

// Writes the lines: to Workers Logs as an OBJECT (each field indexed, for browsing single turns) and,
// when bound, to Analytics Engine (for counting). Never throws — bookkeeping must not break a chat turn.
export function logVerdicts(
  p: GuardrailPipelineResult | null,
  src: VerdictSource,
  ray: string | null,
  opts: { ae?: AnalyticsEngineDataset; sink?: (line: VerdictLine) => void } = {},
): void {
  if (!p) return;
  const sink = opts.sink ?? ((line: VerdictLine) => console.log(line));
  try {
    for (const line of verdictLines(p, src, ray)) {
      sink(line);
      opts.ae?.writeDataPoint(dataPointOf(line)); // non-blocking; never awaited (Cloudflare's guidance)
    }
  } catch {
    /* a missing line is a gap in the analytics, never a failed turn */
  }
}

// The request header the Red Team page sets. Only a label for the analytics — it decides nothing else.
export const SOURCE_HEADER = "x-demo-source";

export function sourceOf(request: Request): VerdictSource {
  return request.headers.get(SOURCE_HEADER) === "redteam" ? "redteam" : "chat";
}
