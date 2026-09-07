// Static configuration: pricing constants and demo defaults.
// Model registry lives in models.ts.

// Reply length cap. Reasoning models (Gemma 4, DeepSeek R1) burn tokens on
// their reasoning phase first — 512 truncated them before any final answer.
export const MAX_REPLY_TOKENS = 2048;

export const DEFAULT_SYSTEM_PROMPT =
  "You are a helpful assistant in a Cloudflare security demo. " +
  "Answer briefly (a few sentences at most). Never repeat back personal data.";
export const MAX_SYSTEM_PROMPT_LEN = 2000;

// Multi-turn conversation caps (server-enforced on the history[] field).
export const MAX_HISTORY_TURNS = 10;
export const MAX_HISTORY_CHARS = 8000;

// Workers AI Neuron pricing, from the pricing page above.
export const FREE_DAILY_NEURONS = 10_000;
export const OVERAGE_USD_PER_1K_NEURONS = 0.011;

export const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
export const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// --- Time-series bucket width --------------------------------------------
// Every chart in the app buckets by one of these widths. Picked from the
// window length, in one place, because three separate call sites used to
// carry their own copy of the ternary (zone analytics, gateway analytics,
// prompt analytics) and could drift apart.
//
// The 1-hour range needs finer than hourly: an hourly bucket over a 1-hour
// window is one or two points, which is a number, not a chart. 5-minute
// buckets give 12–13 across the range.
export type SeriesBucket = "5m" | "hour" | "day";

export const BUCKET_STEP_MS: Record<SeriesBucket, number> = {
  "5m": 300_000,
  hour: 3_600_000,
  day: 86_400_000,
};

export function bucketFor(hours: number): { bucket: SeriesBucket; stepMs: number } {
  const bucket: SeriesBucket = hours <= 1 ? "5m" : hours <= 48 ? "hour" : "day";
  return { bucket, stepMs: BUCKET_STEP_MS[bucket] };
}

// --- Edge-verdict lookup window ------------------------------------------
// A verdict is found by filtering the analytics datasets to a time range
// around the request. Two very different ranges are needed:
//
//   live      — the prompt was just sent and we don't know exactly when the
//               edge event will land, so look back far and slightly forward.
//   anchored  — we know the request's own timestamp (prompt_log.ts), so a
//               tight window around THAT instant is both correct and cheap.
//
// Anchoring matters: with only the live window, any request older than
// ~15 minutes falls outside the range and looks like it was never scanned.
export const VERDICT_LIVE_LOOKBACK_MS = 15 * 60_000;
export const VERDICT_LIVE_LOOKAHEAD_MS = 60_000;
// Slack on both sides of a known timestamp, covering clock skew between the
// Worker writing `ts` and the edge event's own datetime.
export const VERDICT_ANCHOR_SLACK_MS = 5 * 60_000;

// Used when the GraphQL settings node can't be read — deliberately shorter
// than the smallest plan retention so we never claim data exists past it.
export const VERDICT_RETENTION_FALLBACK_S = 30 * 86_400;

// The datetime range to filter the analytics datasets by. `atMs` is the
// request's own timestamp when known; omitted for a just-sent prompt.
export function verdictWindow(atMs?: number, now: number = Date.now()): { since: string; until: string } {
  const anchored = atMs != null && Number.isFinite(atMs);
  const from = anchored ? atMs! - VERDICT_ANCHOR_SLACK_MS : now - VERDICT_LIVE_LOOKBACK_MS;
  const to = anchored ? atMs! + VERDICT_ANCHOR_SLACK_MS : now + VERDICT_LIVE_LOOKAHEAD_MS;
  return { since: new Date(from).toISOString(), until: new Date(to).toISOString() };
}

// True when the request predates what the analytics datasets still hold, so
// a lookup is guaranteed to come back empty and is not worth spending.
export function isBeyondRetention(atMs: number | undefined, retentionSeconds: number, now: number = Date.now()): boolean {
  if (atMs == null || !Number.isFinite(atMs)) return false;
  return now - atMs > retentionSeconds * 1000;
}

// AI Gateway fallback name if CF_AI_GATEWAY_ID isn't set. "default" auto-creates.
export const DEFAULT_AI_GATEWAY_ID = "default";

// AI Gateway Dynamic Routing. A route is addressed by putting its name in the
// `model` field of the OpenAI-compatible endpoint, prefixed with "dynamic/".
// The Workers AI binding only accepts "@cf/…" or "author/model" model ids, so
// routes are unreachable through env.AI.run() — they need this REST path.
export const DYNAMIC_ROUTE_PREFIX = "dynamic/";
export const OPENAI_CHAT_PATH = "/ai/v1/chat/completions";
// Same charset the gateway-id checks use.
export const ROUTE_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Normalise a user-supplied dynamic-route name to the bare id the REST call
// needs (the prefix is added back at call time).
//
// The dashboard renders a route as "dynamic / demo-routes", so people paste
// "dynamic/demo-routes" — which the bare-id charset rejects because of the
// slash. Accept either form rather than silently discarding the value.
// Returns null when the remainder isn't a usable route id, so the caller can
// report the rejection instead of falling through to a different code path.
export function normalizeDynamicRoute(raw: string): string | null {
  let name = raw.trim();
  if (name.toLowerCase().startsWith(DYNAMIC_ROUTE_PREFIX)) {
    name = name.slice(DYNAMIC_ROUTE_PREFIX.length).trim();
  }
  return ROUTE_ID_RE.test(name) ? name : null;
}

// AI Gateway keeps only the first five custom-metadata entries per request and
// drops the rest without an error, so both sides cap explicitly.
export const MAX_METADATA_ENTRIES = 5;

// AI Gateway per-request REST headers (cf-aig-*) — caps mirror the documented
// limits: https://developers.cloudflare.com/ai-gateway/usage/rest-api/
export const MAX_GATEWAY_ATTEMPTS = 5;
export const MAX_GATEWAY_RETRY_DELAY_MS = 5000;
export const GATEWAY_BACKOFF_VALUES = ["constant", "linear", "exponential"] as const;
export type GatewayBackoff = (typeof GATEWAY_BACKOFF_VALUES)[number];

// ── Prompt log feature flag ─────────────────────────────────────────────────
// The prompt log stores a PII-redacted copy of every prompt and reply that
// reaches the Worker. That is useful evidence for a compliance story and a
// liability everywhere else, so it is OPT-IN: absent, empty or anything other
// than the exact string "true" means off.
//
// Deliberately not `!== "false"`. A misspelled or half-deployed var must fail
// CLOSED — the failure mode of "we thought logging was off" is storing prompts
// nobody agreed to store, which cannot be undone after the fact. The reverse
// (logging silently off when someone wanted it on) shows up immediately as an
// empty tab, and costs nothing.
//
// Wrangler serialises vars as strings, so this compares a string, not a bool.
export function promptLogEnabled(env: { PROMPT_LOG_ENABLED?: string }): boolean {
  return env.PROMPT_LOG_ENABLED === "true";
}
