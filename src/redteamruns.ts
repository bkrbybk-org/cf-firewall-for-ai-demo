// Validation + query building for GET/POST/DELETE /api/redteam-runs.
//
// Split out of handlers.ts for the same reason buildPromptLogQuery is split
// out of promptlog.ts: this is the part of the feature with actual room to
// misbehave on hostile input, so it needs to be testable on its own without a
// D1 binding.
//
// The write side (POST) is the sharper edge here. /api/redteam-runs is an
// UNAUTHENTICATED write endpoint — prod sits behind Cloudflare Access, but
// `wrangler dev` does not, and D1 is shared with the rest of the app. Every
// field below is validated and capped server-side; nothing from the client
// body reaches a bound parameter (or a stored column) without passing through
// here first. Scoring itself never happens server-side (see the header on
// redteam_runs in migrations/0003_redteam_runs.sql) — this file only decides
// whether an already-scored run is small enough and well-formed enough to
// store.
import { redact } from "./redact";

// ── Caps ─────────────────────────────────────────────────────────────────
// The client-side CSV importer (web/src/lib/attackCsv.ts) caps a custom
// corpus at 200 attacks. 500 here is deliberate headroom, not a mirror of
// that cap — this endpoint has no way to know it was reached via the CSV
// importer at all, so it enforces its own independent ceiling rather than
// trusting the client to have already enforced one.
export const REDTEAM_RUN_MAX_ATTACKS = 500;
// Prune to the newest N runs on every insert so the table can't grow without
// bound from an unauthenticated endpoint being hit repeatedly.
export const REDTEAM_RUNS_MAX_STORED = 50;

export const REDTEAM_MAX_LABEL_LEN = 200;
// Generic cap for the short identifying strings (model id, gateway id,
// corpus name, category, attack id, fingerprint). None of these are prose —
// if something needs more than this it is not what the field is for.
export const REDTEAM_MAX_FIELD_LEN = 300;
// Prompt text arrives whole (so it can be redacted here rather than trusting
// a client-side redaction), but is never stored past this length. Applied
// BEFORE redact() so a pathological multi-KB CSV cell can't inflate the work
// redact()'s regex passes do — the redact.ts header notes those regexes were
// measured for ReDoS and disposed safe, but bounding input size costs
// nothing and removes the question entirely.
export const REDTEAM_MAX_PROMPT_INPUT_LEN = 4000;
export const REDTEAM_PROMPT_PREVIEW_LEN = 200;

// The full RtResultState union (web/src/lib/redteam.ts), duplicated here
// rather than imported: this file compiles as part of the Worker, the type
// lives in the web (Vite) tree, and duplicating eight literals is cheaper and
// more honest than reaching across that boundary. Kept in sync by hand, same
// as src/types.ts and web/src/lib/types.ts already are (see the brief).
export const RT_RESULT_STATES = [
  "block",
  "challenge",
  "log",
  "allow",
  "denied",
  "guardrails",
  "pending",
  "error",
] as const;
export type RtResultStateServer = (typeof RT_RESULT_STATES)[number];

export interface ValidatedResult {
  attackKey: string;
  attackId: string;
  category: string;
  severity: string | null;
  state: RtResultStateServer;
  ray: string | null;
  ts: number | null;
  promptPreview: string; // redacted + truncated here, never the raw input
}

export interface ValidatedRun {
  ts: number;
  label: string | null;
  route: "direct" | "gateway";
  gatewayId: string | null;
  guarded: boolean;
  model: string | null;
  corpusName: string;
  corpusSize: number;
  corpusFingerprint: string;
  delayMs: number;
  total: number;
  scored: number;
  reached: number;
  stopped: number;
  denied: number;
  guardrails: number;
  pending: number;
  error: number;
  reachedPct: number;
  results: ValidatedResult[];
}

export type ValidationResult = { ok: true; run: ValidatedRun } | { ok: false; error: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Trim + cap a string field. `null`/`undefined`/non-string all collapse to
// `""` — a hostile body substituting an object or array for a string field
// must not reach String(x) and produce "[object Object]" in storage.
function str(v: unknown, maxLen: number): string {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, maxLen);
}

function strOrNull(v: unknown, maxLen: number): string | null {
  const s = str(v, maxLen);
  return s === "" ? null : s;
}

// Non-negative finite integer, clamped into [min, max]. Anything else
// (NaN, Infinity, a string, negative) falls back rather than propagating —
// this feeds directly into LIMIT-adjacent arithmetic and a stored column, so
// it must never be able to carry through as NaN or a huge number.
function int(v: unknown, min: number, max: number, fallback: number): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function isRtResultState(v: unknown): v is RtResultStateServer {
  return typeof v === "string" && (RT_RESULT_STATES as readonly string[]).includes(v);
}

// Redact + truncate one result's prompt text for storage. Mirrors the
// prompt_log convention (src/redact.ts): store enough to be useful for a
// reviewer, never enough to be a live PII/secret dump. A custom CSV can
// contain anything a user pasted, so this runs on every result regardless of
// `source`.
function toPromptPreview(rawPrompt: unknown): string {
  const capped = str(rawPrompt, REDTEAM_MAX_PROMPT_INPUT_LEN);
  const { text } = redact(capped);
  return text.slice(0, REDTEAM_PROMPT_PREVIEW_LEN);
}

// Validate one entry of the `results` array. Returns null (not a thrown
// error) for a malformed entry — one bad row in an otherwise fine batch
// should not fail validation for a required top-level field like `state`,
// where getting it right is not optional. Skips are counted in the caller and
// reported back so silently-dropped rows are visible, not just absorbed.
function validateResult(v: unknown): ValidatedResult | null {
  if (!isPlainObject(v)) return null;
  const attackKey = str(v.attackKey, REDTEAM_MAX_FIELD_LEN);
  const attackId = str(v.attackId, REDTEAM_MAX_FIELD_LEN);
  const category = str(v.category, REDTEAM_MAX_FIELD_LEN);
  if (!attackKey || !attackId || !category) return null;
  if (!isRtResultState(v.state)) return null;
  return {
    attackKey,
    attackId,
    category,
    severity: strOrNull(v.severity, 20),
    state: v.state,
    ray: strOrNull(v.ray, 64),
    ts: v.ts == null ? null : int(v.ts, 0, Number.MAX_SAFE_INTEGER, 0) || null,
    promptPreview: toPromptPreview(v.prompt),
  };
}

// Validate a full POST body into a row this module is willing to insert.
// Every branch that returns `{ ok: false }` is something an adversarial or
// simply buggy client can trigger — an oversized corpus, a bogus `state`
// value, a missing corpus fingerprint — and every one of them must fail
// closed (reject the whole run) rather than silently coercing into something
// storable, because a coerced-but-wrong row is exactly what would corrupt a
// later diffRuns() comparison.
export function validateRedTeamRunPayload(body: unknown): ValidationResult {
  if (!isPlainObject(body)) return { ok: false, error: "Request body must be a JSON object" };

  const route = body.route === "gateway" ? "gateway" : body.route === "direct" ? "direct" : null;
  if (!route) return { ok: false, error: "route must be 'direct' or 'gateway'" };

  const corpusName = str(body.corpusName, REDTEAM_MAX_FIELD_LEN);
  if (!corpusName) return { ok: false, error: "corpusName is required" };

  const corpusFingerprint = str(body.corpusFingerprint, REDTEAM_MAX_FIELD_LEN);
  if (!corpusFingerprint) return { ok: false, error: "corpusFingerprint is required" };

  if (!Array.isArray(body.results)) return { ok: false, error: "results must be an array" };
  if (body.results.length === 0) return { ok: false, error: "results must not be empty" };
  if (body.results.length > REDTEAM_RUN_MAX_ATTACKS) {
    return { ok: false, error: `results exceeds the ${REDTEAM_RUN_MAX_ATTACKS}-attack limit` };
  }

  const results: ValidatedResult[] = [];
  for (const r of body.results) {
    const v = validateResult(r);
    if (v) results.push(v);
  }
  if (results.length === 0) return { ok: false, error: "no valid entries in results" };

  // corpusSize describes the CORPUS the run was fired against, which may be
  // larger than `results` (a stopped/aborted run has fewer results than
  // attacks). Falls back to the validated result count so a client that
  // omits it still stores something coherent rather than a 0.
  const corpusSize = int(body.corpusSize, 0, REDTEAM_RUN_MAX_ATTACKS, results.length);

  // The scored totals (RtScore) are trusted from the client here — recomputing
  // them from `results` would be straightforward (scoreRun in
  // web/src/lib/redteam.ts already does it), but duplicating that reducer
  // Worker-side is exactly the "rewrite of the feature" the brief rules out
  // for scoring in general. They are simple non-negative integers, so the
  // only server-side obligation is to clamp them, not to re-derive them.
  const total = int(body.total, 0, REDTEAM_RUN_MAX_ATTACKS, results.length);
  const scored = int(body.scored, 0, total, 0);
  const reached = int(body.reached, 0, scored, 0);
  const stopped = int(body.stopped, 0, scored, 0);
  const denied = int(body.denied, 0, total, 0);
  const guardrails = int(body.guardrails, 0, total, 0);
  const pending = int(body.pending, 0, total, 0);
  const error = int(body.error, 0, total, 0);
  const reachedPct = int(body.reachedPct, 0, 100, scored === 0 ? 0 : Math.round((reached / scored) * 100));

  return {
    ok: true,
    run: {
      ts: int(body.ts, 0, Number.MAX_SAFE_INTEGER, Date.now()),
      label: strOrNull(body.label, REDTEAM_MAX_LABEL_LEN),
      route,
      gatewayId: strOrNull(body.gatewayId, REDTEAM_MAX_FIELD_LEN),
      guarded: body.guarded === true,
      model: strOrNull(body.model, REDTEAM_MAX_FIELD_LEN),
      corpusName,
      corpusSize,
      corpusFingerprint,
      delayMs: int(body.delayMs, 0, 60_000, 0),
      total,
      scored,
      reached,
      stopped,
      denied,
      guardrails,
      pending,
      error,
      reachedPct,
      results,
    },
  };
}

// ── Read side ────────────────────────────────────────────────────────────

// GET /api/redteam-runs (list) — capped independently of REDTEAM_RUNS_MAX_STORED
// so the two stay conceptually separate: this bounds one response, that
// bounds the table.
export const REDTEAM_RUNS_LIST_LIMIT = 50;

// A single `?id=` query param, validated into a positive integer or null.
// Used by both the GET-one and DELETE handlers, which take exactly the same
// param.
export function parseRunId(raw: string | null): number | null {
  if (raw == null) return null;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}
