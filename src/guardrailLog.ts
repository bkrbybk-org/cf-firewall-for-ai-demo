// One structured Workers Logs line per external guardrail verdict — the record the Analytics page's
// "External guardrails" tab reads back live (src/guardrailAnalytics.ts) instead of a D1 table.
//
// Decided with the user (2026-10-09): live log fetching, not a database. Workers Logs is already on
// (`observability.enabled` in wrangler.jsonc); Cloudflare keeps each line up to 7 days on the paid plan
// (3 on free) and deletes it itself.
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

// Writes the lines. console.log of an OBJECT, not a string: Workers Logs indexes each field, so the
// query can filter and group by them. Never throws — bookkeeping must not break a chat turn.
export function logVerdicts(
  p: GuardrailPipelineResult | null,
  src: VerdictSource,
  ray: string | null,
  sink: (line: VerdictLine) => void = (line) => console.log(line),
): void {
  if (!p) return;
  try {
    for (const line of verdictLines(p, src, ray)) sink(line);
  } catch {
    /* a missing log line is a gap in the analytics, never a failed turn */
  }
}

// The request header the Red Team page sets. Only a label for the analytics — it decides nothing else.
export const SOURCE_HEADER = "x-demo-source";

export function sourceOf(request: Request): VerdictSource {
  return request.headers.get(SOURCE_HEADER) === "redteam" ? "redteam" : "chat";
}
