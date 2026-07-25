// Shared type definitions for the Worker.

export interface Env {
  AI: Ai;
  ASSETS: Fetcher;
  // Optional D1 store for the prompt log (GET/DELETE /api/prompt-log). When
  // unbound the feature degrades to a "not configured" state. Prompts are
  // PII-redacted before they are written here.
  DB?: D1Database;
  // Optional: enables the live "edge verdict" lookup (GET /api/verdict).
  CF_ZONE_ID?: string; // zone id, set as a plain var in wrangler.jsonc
  // Optional: enables the Neuron usage monitor (GET /api/neurons).
  CF_ACCOUNT_ID?: string; // account id, set as a plain var in wrangler.jsonc
  // API token used by both features above. Needs BOTH "Zone Analytics: Read"
  // (for /api/verdict) and "Account Analytics: Read" (for /api/neurons).
  CF_ANALYTICS_TOKEN?: string; // set as a secret
  // AI Gateway name for /api/gateway/chat. "default" auto-creates on first use.
  CF_AI_GATEWAY_ID?: string; // plain var in wrangler.jsonc
  // Second gateway with Guardrails enabled in the dashboard. Optional — the
  // Guardrails toggle in the UI only appears when this is set.
  CF_AI_GATEWAY_GUARDED_ID?: string; // plain var in wrangler.jsonc
  // Separate from CF_ANALYTICS_TOKEN (which is read-only): needs "AI Gateway
  // Run" to call the OpenAI-compatible REST endpoint for Dynamic Routing.
  // Kept apart deliberately — the two have different blast radii.
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
  // Arbitrary key/values the route's Conditional nodes can branch on
  // (e.g. { plan: "paid" }). Values are coerced to strings.
  routeMetadata?: unknown;
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
}

// Aggregated security analytics for the dashboard page (GET /api/analytics).
// Raw events are fetched from GraphQL and aggregated Worker-side so the
// client gets one small ready-to-render payload.
export interface AnalyticsSummary {
  rangeHours: number;
  since: string;
  until: string;
  totalEvents: number;
  actions: Record<string, number>; // raw action → count (block, log, …)
  topRules: { name: string; action: string; count: number }[];
  // Time buckets: hourly for ranges ≤ 48h, daily beyond that.
  series: { t: string; block: number; log: number; other: number }[];
  bucket: "hour" | "day";
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
  bucket: "hour" | "day";
  firstTs: number | null;
  lastTs: number | null;
  error?: string;
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
  bucket: "hour" | "day";
  truncated: boolean; // hit the row cap — totals are a floor, not exact
  error?: string;
}
