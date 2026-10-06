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
  // External guardrail pipeline (e.g. Palo Alto Networks Prisma AIRS). When it
  // stopped the turn the response is a 200 with `externalGuardrailBlocked: true`
  // — never a 403, which is reserved for the edge WAF so the two are never
  // confused. On a reply it carries the verdicts that let the prompt through.
  externalGuardrailBlocked?: boolean;
  // Guardrail-only mode: the prompt passed the edge and every enabled external
  // guardrail, and the model was deliberately NOT called (no reply, no tokens,
  // no cost). AI Gateway Guardrails did not run either — they are part of the
  // model call. Never render this as a model answer.
  guardrailOnly?: boolean;
  externalGuardrails?: GuardrailPipelineResult;
}

// ── External guardrails (GET/PUT /api/external-guardrails) ─────────────────
// Third-party guardrails the Worker forwards each prompt to before calling the
// model. Any number may be enabled; the pipeline config decides how they run.
export type ExternalGuardrailProvider =
  | "prisma-airs"
  | "crowdstrike-aidr"
  | "cisco-ai-defense"
  | "lakera-guard"
  | "cato-ai-security";

// GET /api/external-guardrails/report — Prisma AIRS's own per-detection report
// for one scan. Allowlisted on the server: names, categories, verdicts, actions
// and counts only — never snippets, URLs, code or masked text from the prompt.
export interface GuardrailReportDetection {
  service: string; // PANW's detection_service, e.g. "dlp", "urlf", "prompt injection"
  dataType: string | null; // "prompt" | "response" | "tool_event"
  // What the detector CONCLUDED ("malicious" | "benign") and what the AI
  // security profile DOES about it ("block" | "allow"). Different facts: a
  // malicious verdict with action allow means the profile only alerts. Never
  // collapse them into one word.
  verdict: string | null;
  action: string | null;
  details: string[];
}

export interface GuardrailReport {
  provider: "prisma-airs";
  reportId: string;
  scanId: string | null;
  transactionId: string | null;
  source: string | null;
  detections: GuardrailReportDetection[];
}

// `pending`: PANW has no report under this id yet — not an error, not "clean".
export type GuardrailReportResponse =
  | { ok: true; report: GuardrailReport }
  | { ok: false; pending?: boolean; error: string; httpStatus?: number };

// How enabled guardrails run, between the edge WAF (always first, before the
// Worker) and the model (where AI Gateway Guardrails run, gateway route only):
//   sequential — in `order`; the first one that stops the turn ends it, and the
//                rest do not run (listed in `notRun`). Latency adds up.
//   parallel   — all at once; the model runs only if EVERY one lets it through.
//                The Worker waits for all of them (each is capped by its own
//                timeout), so every verdict is shown. Latency = the slowest.
export type GuardrailPipelineMode = "sequential" | "parallel";

export interface GuardrailPipelineConfig {
  mode: GuardrailPipelineMode;
  // Stop before the model: for testing the checks without model cost. Applies
  // to chat AND red-team runs (one global switch).
  guardrailOnly: boolean;
  order: ExternalGuardrailProvider[]; // every provider exactly once; sequential order
}

// PUT /api/external-guardrails/pipeline. Omitted fields are left unchanged.
// `order` must list every provider exactly once.
export type GuardrailPipelineUpdate = Partial<GuardrailPipelineConfig>;

// What the pipeline did for one prompt.
export interface GuardrailPipelineResult {
  mode: GuardrailPipelineMode;
  guardrailOnly: boolean;
  // One per guardrail that ran, in the order run (sequential) or configured order (parallel).
  // Empty when none is enabled (possible in guardrail-only mode: edge-only test).
  results: ExternalGuardrailResult[];
  // Enabled guardrails that did not run because an earlier one stopped the turn (sequential).
  notRun: { provider: ExternalGuardrailProvider; reason: string }[];
  // The guardrail whose result stopped the turn, or null when the turn went on.
  stoppedBy: ExternalGuardrailProvider | null;
  latencyMs: number; // wall clock for the whole pipeline
}

// What one forwarded prompt produced. `outcome` is what the Worker DID:
//   allow — the provider said allow; the model ran.
//   block — the provider said block; the model did not run.
//   error — the provider could not be reached or rejected the request (bad key,
//           timeout, 4xx/5xx). Whether the turn then ran depends on `failMode`:
//           `failedOpen: true` means the model ran unscanned.
// An error is NEVER a verdict: it must not be rendered as "malicious".
export interface ExternalGuardrailResult {
  provider: ExternalGuardrailProvider;
  outcome: "allow" | "block" | "error";
  failedOpen?: boolean; // outcome "error" + failMode "allow" → the turn ran unscanned
  action?: "allow" | "block"; // the provider's own verdict, when there was one
  category?: string; // Prisma AIRS: "benign" | "malicious"
  detected?: string[]; // which detections fired, e.g. ["injection", "dlp", "toxic_content"]
  scanId?: string | null; // look up the full report in Strata Cloud Manager
  reportId?: string | null;
  profileName?: string | null;
  latencyMs: number; // Worker-observed round trip to the provider
  error?: string; // set when outcome is "error"
  httpStatus?: number; // provider's HTTP status, when it answered
  // The provider returned a verdict, but at least one of its detection services
  // timed out or errored (Prisma AIRS `timeout` / `error`). The verdict covers
  // only what did run, so an "allow" here is weaker than a complete one.
  incomplete?: boolean;
  policy?: string; // CrowdStrike AIDR: the policy its collector token evaluated
  summary?: string; // CrowdStrike AIDR: its own one-line description of the result
  // CrowdStrike AIDR redacted something in the prompt. This app does NOT apply
  // the redaction — the model gets the original prompt — so say so, never imply
  // the model saw a cleaned version.
  transformed?: boolean;
  // Lakera Guard in Detect mode: detectors fired, but the project only logs them, so
  // `flagged` is forced false and the outcome is allow. "Allow with alerts" — never
  // rendered as a clean pass, never as a block.
  detectOnly?: boolean;
  // Present only when this viewer asked for raw responses (includeRaw) and the turn came
  // back as JSON: the vendor's response as it arrived. It can quote the prompt and what
  // the vendor detected — shown, never stored or exported.
  raw?: GuardrailRawResponse;
}

export interface GuardrailRawResponse {
  status: number;
  body: unknown; // parsed JSON, or the text when the body was not JSON
  json: boolean;
  truncated: boolean;
}

export interface ExternalGuardrailRegion {
  id: string; // e.g. "us"
  label: string; // e.g. "United States"
  url: string; // the official API host — the only endpoints the Worker will call
}

export interface ExternalGuardrailConfig {
  provider: ExternalGuardrailProvider;
  label: string; // "Palo Alto Networks Prisma AIRS"
  supported: boolean; // false → shown for context, cannot be configured yet
  verified?: boolean; // false → built from the vendor's docs; not yet checked against a real response
  enabled: boolean;
  region: string; // ExternalGuardrailRegion.id
  endpoint: string; // full scan URL derived from the region (read-only)
  regions: ExternalGuardrailRegion[];
  profileName: string; // Prisma AIRS: AI security profile name · Lakera Guard: project_id
  // Provider-specific wording, from the server's registry so the page never
  // hard-codes one vendor's terms for another.
  requiresProfile: boolean; // false for CrowdStrike AIDR and Cisco AI Defense: the policy rides on the key
  profileLabel: string; // what profileName is called: "AI security profile name" | "Project ID"
  keyLabel: string; // "API key" | "Collector token"
  vendor: string; // "Palo Alto Networks" | "CrowdStrike" — whose hosts the key is sent to
  failMode: "block" | "allow"; // what to do when the provider errors or times out
  apiKeySet: boolean;
  apiKeyLast4: string | null; // the key itself is write-only and never returned
  updatedAt: number | null; // epoch ms
}

export interface ExternalGuardrailsState {
  // false → the encryption secret or D1 binding is missing; `setupHint` says what to do
  configured: boolean;
  providers: ExternalGuardrailConfig[];
  pipeline: GuardrailPipelineConfig;
  setupHint?: string;
  error?: string;
  // Who may change these settings (src/accessAuth.ts). mode "open" = no admin list
  // is set, so anything Access lets in can write. Absent from an older Worker.
  access?: GuardrailAccess;
}

export type GuardrailAccess =
  | { canEdit: true; mode: "open" | "admin"; who: string | null }
  | { canEdit: false; mode: "admin"; who: string | null; reason: string };

// PUT body. Omitted fields are left unchanged. `apiKey` replaces the stored key
// (never echoed back); `clearApiKey: true` deletes it (and disables the provider).
export interface ExternalGuardrailUpdate {
  provider: ExternalGuardrailProvider;
  enabled?: boolean;
  region?: string;
  profileName?: string;
  failMode?: "block" | "allow";
  apiKey?: string;
  clearApiKey?: boolean;
}

// Which FIXED prompt a test scans. "pii" exists because a vendor may answer PII with an
// action neither other prompt triggers (Cato: "anonymize_action", seen 2026-10-06).
export type GuardrailTestSample = "benign" | "attack" | "pii";

// POST /api/external-guardrails/test — scans a fixed prompt with the
// SAVED configuration (it never sends an unsaved key).
export interface ExternalGuardrailTestResult {
  ok: boolean; // the provider answered with a verdict
  result: ExternalGuardrailResult;
  sample?: GuardrailTestSample; // which fixed prompt was scanned
  verified?: boolean; // this provider's parser has been checked against a real payload
  // The vendor response's field names, types and booleans — never text (src/responseShape.ts).
  // What an admin hands back so an unverified parser can be checked.
  responseShape?: { status: number; shape: unknown } | null;
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
  // `read`: set only when the row cap was hit. "none" = the bucket is older than the
  // oldest row read — NOT READ, never draw it as zero; "partial" = its count is a floor.
  series?: { t: string; block: number; log: number; other: number; read?: "partial" | "none" }[];
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
  outcome: "reply" | "guardrails" | "external" | "skipped" | "error"; // external = an external guardrail blocked it; skipped = guardrail-only, model not called
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
  series?: { t: string; reply: number; guardrails: number; external: number; skipped: number; error: number }[];
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
  /** AI Gateway Dynamic Route the run went through, or null. */
  dynamicRoute: string | null;
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
  external: number; // blocked by an external guardrail (Prisma AIRS)
  skipped: number; // of `reached`: passed every check but guardrail-only, so no model answered
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
  // `read`: as for Analytics.series — "none" buckets were never read (row cap), not zero.
  series?: { t: string; hit: number; miss: number; error: number; read?: "partial" | "none" }[];
  bucket?: "5m" | "hour" | "day";
  truncated?: boolean;
  error?: string;
}
