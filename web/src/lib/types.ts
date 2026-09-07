export interface Model {
  id: string;
  label: string;
  priceIn?: number; // USD per 1M input tokens (client-side cost for streamed replies)
  priceOut?: number; // USD per 1M output tokens
}

export interface GatewayOption {
  id: string;
  label: string;
  guarded: boolean;
}

// Server-side caps for the AI Gateway numeric settings. Served rather than
// re-declared client-side: the Worker clamps to these values regardless, so
// duplicating them by hand only creates a chance for the two to disagree.
export interface GatewayLimits {
  maxAttempts: number;
  retryDelayMs: number;
}

export interface ModelsResponse {
  default: string;
  models: Model[];
  defaultSystemPrompt: string;
  maxSystemPromptLen: number;
  gateways?: GatewayOption[]; // configured AI Gateways for the dropdown
  defaultGateway?: string; // id of the first configured gateway
  limits?: GatewayLimits;
  // Prompt-log feature flag. `enabled` requires both the PROMPT_LOG_ENABLED
  // var and a bound D1, so the client can treat it as "is there anywhere for
  // a prompt to go" and hide the whole feature when there isn't. Optional
  // because a cached or older Worker may not send it — treat absent as OFF,
  // matching the server's own opt-in default.
  promptLog?: { enabled: boolean };
}

// GET /api/zone-rules — the zone's WAF custom rules, read live from the
// Rulesets API. `source: "fallback"` means the lookup was unavailable and the
// client should keep using its static ZONE_RULES mirror.
export interface ZoneRuleLive {
  id: string;
  name: string; // the rule description, as firewallEventsAdaptive reports it
  action: string;
  expression: string;
  enabled: boolean;
  llm: boolean; // expression references cf.llm.* — an AI Security rule
}

export interface ZoneRules {
  configured?: boolean;
  source: "live" | "fallback";
  rules: ZoneRuleLive[];
  error?: string;
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  estimated: boolean;
}

// AI Gateway metadata, present on a reply only when the prompt was routed
// through the gateway (POST /api/chat with gateway:true).
export interface GatewayMeta {
  gatewayId?: string;
  cached?: boolean | null; // true HIT / false MISS / null unknown
  latencyMs?: number;
  logId?: string | null;
  guarded?: boolean;
}

export interface ChatResponse {
  reply?: string;
  model?: string;
  ray?: string | null;
  usage?: Usage;
  cost?: number | null;
  error?: string;
  blocked?: boolean;
  detection?: string;
  reason?: string;
  gateway?: GatewayMeta; // set when routed via AI Gateway
  // AI Gateway Guardrails block (error 2016/2017) — same shape the old
  // /api/gateway/chat used, now returned from the unified /api/chat.
  guardrailsBlocked?: boolean;
  direction?: "prompt" | "response";
  detail?: string;
  dynamicRoute?: string; // echoed back when the reply came from a dynamic route
}

export interface VerdictRule {
  ruleId: string;
  action: string;
  description: string;
  source: string;
}

export interface Verdict {
  configured?: boolean;
  ray?: string;
  found?: boolean;
  // What the edge actually returned. Load-bearing: a 4xx here with no
  // blocking rule means something above the WAF (Access, rate limiting)
  // rejected the request, which the rule list alone cannot reveal.
  httpStatus?: number | null;
  securityAction?: string | null;
  ai?: {
    injectionScore: number | null;
    piiCategories: string[];
    unsafeTopicCategories: string[];
    customTopicCategories: { label: string; score: number }[];
    customTopicScoreMin: number | null;
  } | null;
  rules?: VerdictRule[];
  cfLlmLabeled?: boolean;
  scored?: boolean;
  // Request predates the analytics retention window — the data is gone, so
  // unlike "not ingested yet" this will never resolve by waiting.
  tooOld?: boolean;
  retentionDays?: number;
  error?: string;
}

export interface Neurons {
  configured: boolean;
  totalNeurons?: number;
  freeLimit?: number;
  pctUsed?: number;
  overageUsdPer1k?: number;
  resetsAt?: string;
  error?: string;
}

// GET /api/analytics — aggregated payload, see Worker AnalyticsSummary.
export interface Analytics {
  configured: boolean;
  rangeHours?: number;
  since?: string;
  until?: string;
  totalEvents?: number;
  actions?: Record<string, number>;
  // totalEvents is a floor, not an exact count, when this is set (row cap hit).
  truncated?: boolean;
  // Preceding same-length window, for trend deltas. Absent when that window was
  // itself truncated — see AnalyticsSummary in src/types.ts.
  prev?: { totalEvents: number; blocked: number; logged: number; piiRequests: number };
  topRules?: { name: string; action: string; count: number }[];
  series?: { t: string; block: number; log: number; other: number }[];
  bucket?: "5m" | "hour" | "day";
  aiScored?: number;
  scoreBuckets?: { label: string; count: number }[];
  piiRequests?: number;
  // Firewall for AI per-category breakdowns.
  unsafeTopics?: { code: string; count: number }[];
  piiCategories?: { name: string; count: number }[];
  // avgStrength = mean of (100 − score); higher = stronger match (same
  // convention as the verdict card's TopicBars).
  customTopics?: { label: string; count: number; avgStrength: number }[];
  scannedRequests?: number;
  labeledRequests?: number;
  error?: string;
}

// GET /api/prompt-log — recent PII-redacted prompts (D1). Detections aren't
// stored; the UI joins each row to the live edge verdict by ray.
export interface PromptLogRow {
  ray: string;
  ts: number;
  route: "direct" | "gateway";
  model: string;
  gatewayId: string | null;
  guarded: number;
  outcome: "reply" | "guardrails" | "error";
  prompt: string;
  reply: string | null;
  redactions: number;
  promptTokens: number | null;
  completionTokens: number | null;
  // Worker-observed only — see PromptAnalytics.latency for what that excludes.
  // null on rows written before this column existed.
  latencyMs: number | null;
  streamed: number; // 0/1
}
export interface PromptLog {
  configured: boolean;
  // The operator turned the feature off, as opposed to D1 not being bound.
  // Distinct because only the latter deserves a setup hint.
  disabled?: boolean;
  rows?: PromptLogRow[]; // one page, already filtered/sorted by SQL
  filtered?: number; // rows matching the filters — drives the page count
  total?: number; // rows in the whole table, regardless of filters
  limit?: number;
  offset?: number;
  error?: string;
}

// GET /api/prompt-analytics — rollups computed as SQL GROUP BY inside D1.
export interface PromptAnalytics {
  configured: boolean;
  disabled?: boolean; // see PromptLog.disabled

  total?: number;
  withPii?: number;
  redactions?: number;
  promptTokens?: number;
  completionTokens?: number;
  byOutcome?: { outcome: string; count: number }[];
  byRoute?: { route: string; count: number }[];
  byModel?: { model: string; count: number; promptTokens: number; completionTokens: number }[];
  repeated?: { prompt: string; count: number; redactions: number }[];
  series?: { t: string; reply: number; guardrails: number; error: number }[];
  bucket?: "5m" | "hour" | "day";
  firstTs?: number | null;
  lastTs?: number | null;
  // Worker-observed latency, grouped by (route, guarded, streamed) — never mix
  // rows across `streamed` (TTFB vs total generation time are different
  // quantities). This is direct vs gateway vs guarded-gateway model latency
  // AS THE WORKER SEES IT: it excludes the edge AI Security scan (which runs
  // before the Worker is invoked) and has no rows for requests the WAF
  // blocked. It is not a measurement of what AI Security costs.
  latency?: {
    route: string;
    guarded: number;
    streamed: number;
    n: number;
    p50: number | null;
    p95: number | null;
    max: number | null;
  }[];
  // How many rows in the window have a latency_ms value, out of the total —
  // old rows are permanently NULL, so this guards against a rollup over a
  // handful of rows reading as the whole table.
  latencyCoverage?: { withLatency: number; total: number };
  error?: string;
}

// GET/POST/DELETE /api/redteam-runs — persisted Red Team runs (D1), hand-
// mirrored from src/types.ts's RedTeamRunRow/RedTeamResultRow. These are the
// raw wire shapes the Worker returns; the domain types callers actually work
// with (RtRunSummary, RtSavedRun, RtStoredResult) and diffRuns() itself live
// in ./redteam — this file's RedTeamRunRow/RedTeamResultRow are structurally
// identical to those, kept as separate named types only so this file stays
// consistent with how every other endpoint here mirrors its Worker-side row
// shape (see PromptLogRow above).
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

export interface RedTeamResultRow {
  attackKey: string;
  attackId: string;
  category: string;
  severity: string | null;
  state: string; // RtResultState, see ./redteam
  ray: string | null;
  ts: number | null;
  promptPreview: string | null;
}

export interface RedTeamRunsList {
  configured: boolean;
  runs?: RedTeamRunRow[];
  error?: string;
}

export interface RedTeamRunDetail {
  configured: boolean;
  run?: RedTeamRunRow | null;
  results?: RedTeamResultRow[];
  error?: string;
}

export interface RedTeamRunSaveResult {
  configured: boolean;
  id?: number;
  pruned?: number; // how many older runs were dropped by the server-side 50-run cap
  error?: string;
}

export interface RedTeamRunDeleteResult {
  configured: boolean;
  deleted?: boolean;
  error?: string;
}

// GET /api/gateway-analytics — aggregated AI Gateway logs, see Worker
// GatewayAnalytics. Account-scoped: covers every app using the gateway.
export interface GatewayAnalytics {
  configured: boolean;
  gatewayId?: string;
  guarded?: boolean;
  rangeHours?: number;
  requests?: number;
  cachedRequests?: number;
  totalCost?: number;
  tokensIn?: number;
  tokensOut?: number;
  avgMs?: number;
  p50Ms?: number;
  p95Ms?: number;
  errors?: number;
  statusCodes?: { code: number; count: number }[];
  byModel?: { model: string; count: number; tokensIn: number; tokensOut: number; cost: number }[];
  series?: { t: string; hit: number; miss: number; error: number }[];
  bucket?: "5m" | "hour" | "day";
  truncated?: boolean;
  error?: string;
}
