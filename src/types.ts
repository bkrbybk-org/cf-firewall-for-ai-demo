// Shared type definitions for the Worker.

import type { SeriesBucket } from "./config";

export interface Env {
  AI: Ai;
  ASSETS: Fetcher;
  // Optional D1 store for the prompt log (GET/DELETE /api/prompt-log). When
  // unbound the feature degrades to a "not configured" state. Prompts are
  // PII-redacted before they are written here.
  DB?: D1Database;
  // Master switch for the prompt log, OPT-IN: only the exact string "true"
  // turns it on. Off means the Worker writes no prompt rows at all, both
  // read endpoints report the feature as disabled, and the client hides the
  // Analytics tab and the per-turn toggle entirely. Binding DB is therefore
  // necessary but not sufficient — see promptLogEnabled() in config.ts for
  // why this fails closed.
  PROMPT_LOG_ENABLED?: string; // plain var in wrangler.jsonc
  // Optional: enables the live "edge verdict" lookup (GET /api/verdict).
  CF_ZONE_ID?: string; // set as a SECRET (and in .env for wrangler dev)
  // Optional: enables the Neuron usage monitor (GET /api/neurons).
  CF_ACCOUNT_ID?: string; // set as a SECRET (and in .env for wrangler dev)
  // API token used by both features above. Needs BOTH "Zone Analytics: Read"
  // (for /api/verdict) and "Account Analytics: Read" (for /api/neurons).
  CF_ANALYTICS_TOKEN?: string; // set as a secret
  // AI Gateway name for /api/gateway/chat. "default" auto-creates on first use.
  CF_AI_GATEWAY_ID?: string; // plain var in wrangler.jsonc
  // Second gateway with Guardrails enabled in the dashboard. Optional — the
  // Guardrails toggle in the UI only appears when this is set.
  CF_AI_GATEWAY_GUARDED_ID?: string; // plain var in wrangler.jsonc
  // Separate from CF_ANALYTICS_TOKEN (which is read-only): needs "AI Gateway -
  // Read", "AI Gateway - Edit", and "Workers AI - Read" to call the
  // OpenAI-compatible REST endpoint. Required for ANY AI Gateway request (not
  // just Dynamic Routing) since the gateway route always calls this REST
  // endpoint — a direct Workers AI call never needs it. Kept apart from
  // CF_ANALYTICS_TOKEN deliberately — the two have different blast radii.
  CF_AIG_TOKEN?: string; // set as a secret
}

// One prior conversation turn, as sent by the client and re-validated here.
export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ChatRequestBody {
  prompt?: unknown;
  model?: unknown;
  systemPrompt?: unknown;
  history?: unknown; // ChatTurn[] — validated server-side
  stream?: unknown; // true → SSE response instead of JSON
  // AI Gateway routing (optional). When gateway is true the Worker calls
  // env.AI.run(..., { gateway }) instead of a direct Workers AI call. The
  // request still hits the same cf-llm-labeled /api/chat path, so the edge
  // WAF scan (and thus the verdict) applies to both routes identically.
  gateway?: unknown; // true → route the inference through AI Gateway
  gatewayId?: unknown; // gateway only — which configured gateway to use
  skipCache?: unknown; // gateway only
  // Dynamic Routing: a route name configured in the gateway dashboard. When
  // set (and gateway is true) the Worker calls the OpenAI-compatible REST
  // endpoint instead of the binding, because routes are addressed as a model
  // name and the binding rejects anything that isn't a real model id. Absent
  // → the binding path, i.e. today's behaviour, unchanged.
  dynamicRoute?: unknown;
  // Custom metadata for ANY gateway request (not just dynamic routes): tags
  // land in the AI Gateway logs and a dynamic route's Conditional nodes can
  // branch on them (e.g. { plan: "paid" }). Max 5 entries; values coerced to
  // strings, sent as the cf-aig-metadata header.
  routeMetadata?: unknown;
  // Remaining per-request AI Gateway REST headers (gateway only — a direct
  // Workers AI call never goes through the gateway, so these have no effect
  // there). See https://developers.cloudflare.com/ai-gateway/usage/rest-api/
  cacheTtl?: unknown; // seconds — cf-aig-cache-ttl
  cacheKey?: unknown; // cf-aig-cache-key
  collectLog?: unknown; // boolean — cf-aig-collect-log
  requestTimeoutMs?: unknown; // cf-aig-request-timeout
  maxAttempts?: unknown; // 1-5 — cf-aig-max-attempts
  retryDelayMs?: unknown; // 0-5000 — cf-aig-retry-delay
  backoff?: unknown; // "constant" | "linear" | "exponential" — cf-aig-backoff
  // Skip writing this turn to the D1 prompt_log table. App-level, both routes —
  // unrelated to AI Gateway's own request log (collectLog above).
  excludeFromLog?: unknown;
}

export interface VerdictResult {
  found: boolean;
  httpStatus: number | null;
  securityAction: string | null;
  securitySource: string | null;
  ai: {
    injectionScore: number | null;
    piiCategories: string[];
    unsafeTopicCategories: string[];
    customTopicCategories: { label: string; score: number }[];
    customTopicScoreMin: number | null;
  } | null;
  rules: { ruleId: string; action: string; description: string; source: string }[];
  // Onboarding diagnostics so the UI can explain a "nothing happened" verdict:
  cfLlmLabeled: boolean; // endpoint carries the cf-llm managed label in Web Assets
  scored: boolean; // AI Security actually scored the prompt (injectionScore !== 100)
  // Set when the request predates what the analytics datasets still hold, so
  // the lookup was skipped. Distinct from "not ingested yet" — waiting longer
  // cannot help here, the raw data is gone.
  tooOld?: boolean;
  retentionDays?: number;
  error?: string;
}

export interface NeuronUsage {
  totalNeurons: number;
  requestCount: number;
  error?: string;
}

// One row of the prompt log (D1). Prompt/reply are PII-redacted at write time.
export interface PromptLogRow {
  ray: string;
  ts: number; // epoch ms
  route: "direct" | "gateway";
  model: string;
  gatewayId: string | null;
  guarded: number; // 0/1 (SQLite has no bool)
  outcome: "reply" | "guardrails" | "error";
  prompt: string;
  reply: string | null; // null for streamed replies (not captured) or blocks
  redactions: number; // PII spans masked in prompt+reply
  promptTokens: number | null;
  completionTokens: number | null;
  // Worker-observed only (starts just before the model call, inside the
  // Worker) — never includes the edge AI Security scan, and rows the WAF
  // blocked never exist at all. null on rows written before this column
  // existed. Meaning depends on `streamed` — see PromptAnalytics.latency.
  latencyMs: number | null;
  streamed: number; // 0/1 (SQLite has no bool) — see PromptAnalytics.latency
}

// Aggregated security analytics for the dashboard page (GET /api/analytics).
// Raw events are fetched from GraphQL and aggregated Worker-side so the
// client gets one small ready-to-render payload.
export interface AnalyticsSummary {
  rangeHours: number;
  since: string;
  until: string;
  totalEvents: number;
  // True when a dataset returned exactly the row cap, so totalEvents is a
  // floor ("500+"), not an exact count. The UI must not present it as exact.
  truncated?: boolean;
  // Same-length window immediately before this one, for trend deltas. Absent
  // when that window was itself truncated — a delta between two capped windows
  // says nothing, so no number is better than a wrong one.
  prev?: { totalEvents: number; blocked: number; logged: number; piiRequests: number };
  actions: Record<string, number>; // raw action → count (block, log, …)
  topRules: { name: string; action: string; count: number }[];
  // Time buckets: 5-minute at 1h, hourly to 48h, daily beyond (see bucketFor).
  series: { t: string; block: number; log: number; other: number }[];
  bucket: SeriesBucket;
  aiScored: number; // requests AI Security actually scored
  scoreBuckets: { label: string; count: number }[]; // injection-score histogram
  piiRequests: number; // requests with ≥1 PII category detected
  // Firewall for AI detection breakdowns (per-category, not just totals).
  unsafeTopics: { code: string; count: number }[];
  piiCategories: { name: string; count: number }[];
  // avgStrength = mean of (100 − score); higher = stronger match, matching the
  // inversion the verdict card uses so both surfaces agree.
  customTopics: { label: string; count: number; avgStrength: number }[];
  scannedRequests: number; // /api/chat rows seen in the window
  labeledRequests: number; // …of those, rows carrying the cf-llm managed label
  error?: string;
}

// Aggregated prompt log (GET /api/prompt-analytics). Aggregation runs as SQL
// GROUP BY inside D1 rather than Worker-side, so it stays correct as the table
// grows past any row cap.
export interface PromptAnalytics {
  total: number;
  withPii: number; // prompts where redaction fired ≥1
  redactions: number; // total masked spans
  promptTokens: number;
  completionTokens: number;
  byOutcome: { outcome: string; count: number }[];
  byRoute: { route: string; count: number }[];
  byModel: { model: string; count: number; promptTokens: number; completionTokens: number }[];
  // Same prompt text seen more than once — attack replay / autopilot reruns.
  repeated: { prompt: string; count: number; redactions: number }[];
  series: { t: string; reply: number; guardrails: number; error: number }[];
  bucket: SeriesBucket;
  firstTs: number | null;
  lastTs: number | null;
  // Worker-observed latency, grouped by (route, guarded, streamed) — never
  // mixed across `streamed`, since a streamed row's latency_ms is
  // time-to-first-byte and a non-streamed row's is total generation time
  // (see migrations/0002_latency.sql). This measures direct vs gateway vs
  // guarded-gateway model latency AS THE WORKER SEES IT — it starts inside
  // the Worker, so it excludes the edge AI Security scan entirely, and rows
  // the WAF blocked have no row here at all. It is not a measurement of what
  // AI Security costs.
  latency: {
    route: string;
    guarded: number; // 0/1
    streamed: number; // 0/1
    n: number;
    p50: number | null;
    p95: number | null;
    max: number | null;
  }[];
  // How many rows in the window actually have a latency_ms value, out of the
  // window's total — old rows (before this column existed) are NULL forever,
  // so a rollup over a handful of covered rows must never read as covering
  // the whole table.
  latencyCoverage: { withLatency: number; total: number };
  error?: string;
}

// One row of a persisted Red Team run (D1, GET/POST/DELETE
// /api/redteam-runs). Scoring happens client-side (see
// web/src/hooks/useRedTeam.ts: sendOne → resolveState) — this is only the
// finished, already-scored run the client POSTs, plus the comparability trio
// (corpusName/corpusSize/corpusFingerprint) diffRuns needs to refuse a
// misleading before/after. `guarded` is 0/1, same SQLite-has-no-bool
// convention as PromptLogRow.
export interface RedTeamRunRow {
  id: number;
  ts: number;
  label: string | null;
  route: "direct" | "gateway";
  gatewayId: string | null;
  guarded: number;
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
}

// One attack's result within a run. `attackKey` is the diffRuns join key
// (stable across CSV reorders/re-uploads, see attackKey() in
// web/src/lib/redteam.ts); `attackId` is that run's own display id only.
// `promptPreview` is redact()-ed and truncated server-side — never the raw
// prompt (src/redteamruns.ts toPromptPreview).
export interface RedTeamResultRow {
  attackKey: string;
  attackId: string;
  category: string;
  severity: string | null;
  state: string; // RtResultState, see web/src/lib/redteam.ts
  ray: string | null;
  ts: number | null;
  promptPreview: string | null;
}

// Aggregated AI Gateway logs for the dashboard's gateway tab
// (GET /api/gateway-analytics). Sourced from the AI Gateway logs REST API and
// summed Worker-side, mirroring how AnalyticsSummary is built.
export interface GatewayAnalytics {
  gatewayId: string;
  guarded: boolean;
  rangeHours: number;
  since: string;
  until: string;
  requests: number;
  cachedRequests: number;
  totalCost: number;
  tokensIn: number;
  tokensOut: number;
  avgMs: number;
  p50Ms: number;
  p95Ms: number;
  errors: number; // success === false
  statusCodes: { code: number; count: number }[];
  byModel: { model: string; count: number; tokensIn: number; tokensOut: number; cost: number }[];
  series: { t: string; hit: number; miss: number; error: number }[];
  bucket: SeriesBucket;
  truncated: boolean; // hit the row cap — totals are a floor, not exact
  error?: string;
}
