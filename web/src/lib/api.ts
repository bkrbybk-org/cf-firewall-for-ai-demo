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
  RedTeamRunDeleteResult,
  RedTeamRunDetail,
  RedTeamRunSaveResult,
  RedTeamRunsList,
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

// ── Red Team run persistence ────────────────────────────────────────────
// The Worker never scores anything here — a Red Team run is scored entirely
// client-side (web/src/hooks/useRedTeam.ts). This is only the save/list/
// fetch/delete surface for a run that has ALREADY finished, so "before" and
// "after" survive a reload and can be diffed (web/src/lib/redteam.ts:
// diffRuns). See src/redteamruns.ts for the server-side validation this body
// is checked against — every cap named there (500 attacks, string lengths,
// the RtResultState union) is enforced server-side regardless of what this
// client sends.

// One result as POSTed. `prompt` is the attack's full text, sent whole
// rather than pre-truncated by the client: the Worker redacts it
// (src/redact.ts) and truncates it to a preview server-side, the same way
// prompt_log redacts server-side rather than trusting the caller to have
// already done it. A custom CSV can contain anything a user pasted, so this
// is not optional.
export interface RedTeamResultInput {
  attackKey: string; // attackKey(attack) — the diffRuns join key, see ./redteam
  attackId: string; // display id only, e.g. "rt-01" / "csv-12"
  category: string;
  severity?: string | null;
  state: string; // RtResultState
  ray?: string | null;
  ts?: number | null;
  prompt: string;
}

export interface RedTeamRunSaveRequest {
  ts?: number; // epoch ms; server defaults to Date.now() if omitted
  label?: string | null;
  route: "direct" | "gateway";
  gatewayId?: string | null;
  guarded?: boolean;
  model?: string | null;
  corpusName: string;
  corpusSize: number; // the corpus the run was fired against — may exceed results.length on a stopped run
  corpusFingerprint: string; // corpusFingerprint(corpus), see ./redteam
  delayMs?: number;
  // The RtScore totals (web/src/lib/redteam.ts: scoreRun) computed client-side
  // over `results`. The server trusts and clamps these rather than
  // re-deriving them — see the comment in src/redteamruns.ts for why
  // recomputing them Worker-side would be scoring server-side, which the
  // brief this endpoint was built against explicitly rules out.
  total: number;
  scored: number;
  reached: number;
  stopped: number;
  denied: number;
  guardrails: number;
  pending: number;
  error: number;
  reachedPct: number;
  results: RedTeamResultInput[];
}

// POST /api/redteam-runs. 201 + { id } on success; { error } (400) if the
// server's validation rejected the body — e.g. an empty/oversized results
// array or a `state` outside the RtResultState union.
export async function saveRedTeamRun(run: RedTeamRunSaveRequest): Promise<RedTeamRunSaveResult> {
  const r = await fetch("/api/redteam-runs", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(run),
  });
  return r.json();
}

// GET /api/redteam-runs — every saved run's metadata (id, corpus info, RtScore
// totals), newest first. No results — fetch a run's results with
// getRedTeamRun below when the operator actually opens it.
export async function listRedTeamRuns(): Promise<RedTeamRunsList> {
  const r = await fetch("/api/redteam-runs");
  return r.json();
}

// GET /api/redteam-runs?id= — one run plus its full per-attack results.
// `run: null` (404) when the id doesn't exist, e.g. it was pruned by the
// server-side 50-run cap or already deleted.
export async function getRedTeamRun(id: number): Promise<RedTeamRunDetail> {
  const r = await fetch("/api/redteam-runs?id=" + encodeURIComponent(String(id)));
  return r.json();
}

// DELETE /api/redteam-runs?id= — removes the run and its results.
export async function deleteRedTeamRun(id: number): Promise<RedTeamRunDeleteResult> {
  const r = await fetch("/api/redteam-runs?id=" + encodeURIComponent(String(id)), { method: "DELETE" });
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

