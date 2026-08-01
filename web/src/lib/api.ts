// Typed wrappers around the Worker's JSON endpoints.
import type {
  Analytics,
  ChatResponse,
  ChatTurn,
  GatewayAnalytics,
  GatewayMeta,
  ModelsResponse,
  Neurons,
  PromptAnalytics,
  PromptLog,
  Usage,
  Verdict,
  ZoneRules,
} from "./types";

export async function getModels(): Promise<ModelsResponse> {
  const r = await fetch("/api/models");
  return r.json();
}

// `tsMs` is the request's own epoch-ms timestamp when known (prompt-log rows
// carry it). It anchors the server's lookup window to when the request
// actually happened — without it the search is a window around *now*, which
// silently misses anything older than a few minutes.
export async function getVerdict(ray: string, tsMs?: number): Promise<Verdict> {
  const qs = new URLSearchParams({ ray });
  if (tsMs != null && Number.isFinite(tsMs)) qs.set("ts", String(Math.floor(tsMs)));
  const r = await fetch("/api/verdict?" + qs);
  return r.json();
}

// The zone's real WAF custom rules. `source` says whether these came from the
// zone ("live") or whether the caller should keep its static mirror
// ("fallback" — no token, missing "Zone → WAF → Read", or an API error).
export async function getZoneRules(): Promise<ZoneRules> {
  const r = await fetch("/api/zone-rules");
  return r.json();
}

export async function getNeurons(): Promise<Neurons> {
  const r = await fetch("/api/neurons");
  return r.json();
}

export async function getAnalytics(hours: number): Promise<Analytics> {
  const r = await fetch("/api/analytics?hours=" + hours);
  return r.json();
}

export async function getGatewayAnalytics(gatewayId: string, hours: number): Promise<GatewayAnalytics> {
  const qs = new URLSearchParams({ hours: String(hours) });
  if (gatewayId) qs.set("gatewayId", gatewayId);
  const r = await fetch("/api/gateway-analytics?" + qs);
  return r.json();
}

// Either a rolling window (`hours`, 0/absent = all time — the preset
// buttons) or an explicit range (`sinceMs`/`untilMs` — the custom date/time
// picker). When both are given the explicit range wins, matching the
// server's parseTimeWindow.
export interface TimeWindow {
  hours?: number;
  sinceMs?: number;
  untilMs?: number;
}

function timeWindowParams(w: TimeWindow): [string, string][] {
  const params: [string, string][] = [];
  if (w.sinceMs != null || w.untilMs != null) {
    if (w.sinceMs != null) params.push(["since", String(Math.floor(w.sinceMs))]);
    if (w.untilMs != null) params.push(["until", String(Math.floor(w.untilMs))]);
  } else if (w.hours) {
    params.push(["hours", String(w.hours)]); // 0/absent = all time
  }
  return params;
}

// Everything here narrows or orders rows in SQL — including sort and the text
// search, which the server owns so a page is a true window onto the whole
// table rather than a reordering of whichever rows happened to be fetched.
export interface PromptLogQuery extends TimeWindow {
  route?: string;
  outcome?: string | string[];
  q?: string;
  sort?: string;
  dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export async function getPromptLog(opts: PromptLogQuery = {}): Promise<PromptLog> {
  const qs = new URLSearchParams();
  if (opts.route) qs.set("route", opts.route);
  const outcome = Array.isArray(opts.outcome) ? opts.outcome.join(",") : opts.outcome;
  if (outcome) qs.set("outcome", outcome);
  if (opts.q) qs.set("q", opts.q);
  if (opts.sort) qs.set("sort", opts.sort);
  if (opts.dir) qs.set("dir", opts.dir);
  if (opts.limit) qs.set("limit", String(opts.limit));
  if (opts.offset) qs.set("offset", String(opts.offset));
  for (const [k, v] of timeWindowParams(opts)) qs.set(k, v);
  const r = await fetch("/api/prompt-log?" + qs);
  return r.json();
}

export async function getPromptAnalytics(window: TimeWindow = {}): Promise<PromptAnalytics> {
  const qs = new URLSearchParams(timeWindowParams(window));
  const r = await fetch("/api/prompt-analytics?" + qs);
  return r.json();
}

export async function clearPromptLog(): Promise<{ cleared?: boolean; error?: string }> {
  const r = await fetch("/api/prompt-log", { method: "DELETE" });
  return r.json();
}

export type GatewayBackoff = "constant" | "linear" | "exponential";

export interface ChatRequest {
  prompt: string;
  model?: string;
  systemPrompt?: string;
  history?: ChatTurn[];
  stream?: boolean;
  gateway?: boolean; // route inference through AI Gateway
  gatewayId?: string; // gateway only — which configured gateway to use
  skipCache?: boolean; // gateway only
  // Dynamic Routing: a route name configured in the gateway dashboard. Empty
  // → a plain gateway call with `model`. The route picks the model, so
  // `model` is ignored when this is set.
  dynamicRoute?: string;
  routeMetadata?: Record<string, string>;
  // Remaining per-request AI Gateway REST settings — gateway only, all no-ops
  // on a direct Workers AI call since it never goes through a gateway.
  cacheTtl?: number; // seconds
  cacheKey?: string;
  collectLog?: boolean;
  requestTimeoutMs?: number;
  maxAttempts?: number; // 1-5
  retryDelayMs?: number; // 0-5000
  backoff?: GatewayBackoff;
  // Skip writing this turn to the D1 prompt_log table. Both routes — unrelated
  // to AI Gateway's own request log (collectLog above).
  excludeFromLog?: boolean;
}

// Non-stream result: status + raw text + parsed JSON (block pages aren't JSON).
export interface ChatJsonResult {
  mode: "json";
  status: number;
  contentType: string;
  raw: string;
  data: ChatResponse | null;
}

// Stream result: the fully assembled text plus usage if the model emitted it,
// and gateway metadata if the trailing gateway event was present.
export interface ChatStreamResult {
  mode: "stream";
  status: number;
  ray: string | null;
  text: string;
  usage: Usage | null;
  gateway: GatewayMeta | null;
  // The model that actually generated the reply, read off each SSE chunk's
  // `model` field (OpenAI-shape chunks only — e.g. a Dynamic Route response).
  // null for the plain Workers AI binding stream, whose chunks carry no model.
  model: string | null;
}

export type ChatResult = ChatJsonResult | ChatStreamResult;

// POST /api/chat. With stream:true the server passes through the model's SSE
// stream; tokens are delivered via onToken as they arrive. Blocked requests
// (WAF acts before the Worker) come back as HTML/JSON regardless of the
// stream flag, so the content-type decides which path parses the response.
export async function postChat(
  body: ChatRequest,
  onToken?: (token: string) => void,
): Promise<ChatResult> {
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const contentType = res.headers.get("content-type") || "";
  const rayHeader = res.headers.get("cf-ray");

  if (!contentType.includes("text/event-stream")) {
    const raw = await res.text();
    let data: ChatResponse | null = null;
    try {
      data = JSON.parse(raw);
    } catch {
      /* not JSON (block page) */
    }
    if (data && rayHeader && !data.ray) data.ray = rayHeader;
    return {
      mode: "json",
      status: res.status,
      contentType,
      raw,
      data: data ?? (rayHeader ? { ray: rayHeader } : null),
    };
  }

  // SSE: lines of `data: {...}` ending with `data: [DONE]`. Token lives in
  // `response` (most models) or `choices[0].delta.content|reasoning`
  // (OpenAI-shape + reasoning models). Some models emit usage in a late chunk.
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let text = "";
  let usage: Usage | null = null;
  let gateway: GatewayMeta | null = null;
  let model: string | null = null;
  const handleLine = (line: string) => {
    if (!line.startsWith("data:")) return;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") return;
    try {
      const j = JSON.parse(payload) as {
        response?: unknown;
        model?: unknown;
        choices?: { delta?: { content?: unknown; reasoning?: unknown } }[];
        usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
        gateway?: GatewayMeta; // trailing event appended by the Worker for gateway routes
      };
      if (j.gateway) gateway = j.gateway;
      if (typeof j.model === "string" && j.model) model = j.model;
      const delta = j.choices?.[0]?.delta;
      const tok =
        typeof j.response === "string"
          ? j.response
          : typeof delta?.content === "string"
            ? delta.content
            : typeof delta?.reasoning === "string"
              ? delta.reasoning
              : "";
      if (tok) {
        text += tok;
        onToken?.(tok);
      }
      if (j.usage && typeof j.usage.prompt_tokens === "number") {
        usage = {
          prompt_tokens: j.usage.prompt_tokens,
          completion_tokens: j.usage.completion_tokens ?? 0,
          total_tokens: j.usage.total_tokens ?? 0,
          estimated: false,
        };
      }
    } catch {
      /* ignore partial / non-JSON lines */
    }
  };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) handleLine(line);
  }
  if (buffer) handleLine(buffer);

  return { mode: "stream", status: res.status, ray: rayHeader, text, usage, gateway, model };
}

