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

export interface ModelsResponse {
  default: string;
  models: Model[];
  defaultSystemPrompt: string;
  maxSystemPromptLen: number;
  gateways?: GatewayOption[]; // configured AI Gateways for the dropdown
  defaultGateway?: string; // id of the first configured gateway
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
  topRules?: { name: string; action: string; count: number }[];
  series?: { t: string; block: number; log: number; other: number }[];
  bucket?: "hour" | "day";
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
}
export interface PromptLog {
  configured: boolean;
  rows?: PromptLogRow[];
  total?: number;
  error?: string;
}

// GET /api/prompt-analytics — rollups computed as SQL GROUP BY inside D1.
export interface PromptAnalytics {
  configured: boolean;
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
  bucket?: "hour" | "day";
  firstTs?: number | null;
  lastTs?: number | null;
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
  bucket?: "hour" | "day";
  truncated?: boolean;
  error?: string;
}
