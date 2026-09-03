// Route handlers, one per endpoint. Each returns a Response.

import {
  bucketFor,
  CF_API_BASE,
  DEFAULT_AI_GATEWAY_ID,
  DEFAULT_SYSTEM_PROMPT,
  DYNAMIC_ROUTE_PREFIX,
  GATEWAY_BACKOFF_VALUES,
  isBeyondRetention,
  MAX_GATEWAY_ATTEMPTS,
  MAX_GATEWAY_RETRY_DELAY_MS,
  MAX_METADATA_ENTRIES,
  normalizeDynamicRoute,
  OPENAI_CHAT_PATH,
  ROUTE_ID_RE,
  FREE_DAILY_NEURONS,
  MAX_HISTORY_CHARS,
  MAX_HISTORY_TURNS,
  MAX_REPLY_TOKENS,
  MAX_SYSTEM_PROMPT_LEN,
  OVERAGE_USD_PER_1K_NEURONS,
  type GatewayBackoff,
} from "./config";
import { ALLOWED_IDS, DEFAULT_MODEL, MODEL_BY_ID, MODEL_REGISTRY } from "./models";
import {
  listAiGateways,
  queryAnalytics,
  queryGatewayLogs,
  queryNeuronUsage,
  queryVerdict,
  queryVerdictRetention,
  queryZoneRules,
} from "./cloudflare";
import { buildPromptLogQuery } from "./promptlog";
import { parseRunId, REDTEAM_RUNS_LIST_LIMIT, REDTEAM_RUNS_MAX_STORED, validateRedTeamRunPayload } from "./redteamruns";
import { redact } from "./redact";
import { createSseAccumulator } from "./sse";
import type {
  ChatRequestBody,
  ChatTurn,
  Env,
  PromptAnalytics,
  PromptLogRow,
  RedTeamResultRow,
  RedTeamRunRow,
} from "./types";

// The `guarded` flag drives the purple "Guardrails" badge. The AI Gateway
// REST API does not report which gateways have Guardrails enabled, so we mark
// the one named in CF_AI_GATEWAY_GUARDED_ID. (2016/2017 blocks are handled
// from the actual binding error regardless of this flag.)
export interface GatewayEntry {
  id: string;
  label: string;
  guarded: boolean;
}
function toEntry(id: string, env: Env): GatewayEntry {
  const guarded = !!env.CF_AI_GATEWAY_GUARDED_ID && id === env.CF_AI_GATEWAY_GUARDED_ID;
  return { id, label: guarded ? `${id} (Guardrails)` : id, guarded };
}

// Fallback gateway list from the wrangler vars, used when the account can't be
// listed (no token / no "AI Gateway Read" permission / API error).
function gatewayRegistryFromVars(env: Env): GatewayEntry[] {
  const list: GatewayEntry[] = [toEntry(env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID, env)];
  if (env.CF_AI_GATEWAY_GUARDED_ID && env.CF_AI_GATEWAY_GUARDED_ID !== list[0].id) {
    list.push(toEntry(env.CF_AI_GATEWAY_GUARDED_ID, env));
  }
  return list;
}

// Every AI Gateway in the account, fetched live. The two demo gateways
// (CF_AI_GATEWAY_ID default, then the guarded one) are floated to the top so
// the presenter's expected gateways lead the dropdown; the rest follow in
// their API order.
async function resolveGateways(env: Env): Promise<GatewayEntry[]> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) return gatewayRegistryFromVars(env);
  try {
    const ids = await listAiGateways(env.CF_ACCOUNT_ID, env.CF_ANALYTICS_TOKEN);
    if (!ids.length) return gatewayRegistryFromVars(env);
    const priority = (id: string) =>
      id === (env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID) ? 0 : id === env.CF_AI_GATEWAY_GUARDED_ID ? 1 : 2;
    return ids
      .map((id) => toEntry(id, env))
      .sort((a, b) => priority(a.id) - priority(b.id));
  } catch {
    return gatewayRegistryFromVars(env); // e.g. token lacks "AI Gateway Read"
  }
}

// GET /api/models — model menu + system-prompt defaults + the account's AI
// Gateways for the dropdown. Prices are included so the client can estimate
// cost for streamed replies (where the server never sees the finished text).
export async function handleModels(env: Env): Promise<Response> {
  const gateways = await resolveGateways(env);
  const defaultGateway =
    gateways.find((g) => g.id === (env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID))?.id ?? gateways[0]?.id;
  return Response.json({
    default: DEFAULT_MODEL,
    models: MODEL_REGISTRY.map(({ id, label, priceIn, priceOut }) => ({ id, label, priceIn, priceOut })),
    defaultSystemPrompt: DEFAULT_SYSTEM_PROMPT,
    maxSystemPromptLen: MAX_SYSTEM_PROMPT_LEN,
    gateways, // [{ id, label, guarded }] — populates the gateway dropdown
    defaultGateway,
    // Caps for the numeric AI Gateway settings. Served rather than re-declared
    // in the client: handleChat clamps to these values anyway, so a hand-copied
    // second set could only ever drift out of agreement with the enforcement.
    limits: {
      maxAttempts: MAX_GATEWAY_ATTEMPTS,
      retryDelayMs: MAX_GATEWAY_RETRY_DELAY_MS,
    },
  });
}

// Re-validate the client-supplied conversation history: only user/assistant
// turns, capped by turn count and total characters (newest turns win).
function sanitizeHistory(raw: unknown): ChatTurn[] {
  if (!Array.isArray(raw)) return [];
  const turns: ChatTurn[] = [];
  for (const t of raw) {
    const turn = t as { role?: unknown; content?: unknown };
    if (
      (turn?.role === "user" || turn?.role === "assistant") &&
      typeof turn.content === "string" &&
      turn.content.trim() !== ""
    ) {
      turns.push({ role: turn.role, content: turn.content });
    }
  }
  const recent = turns.slice(-MAX_HISTORY_TURNS);
  const kept: ChatTurn[] = [];
  let total = 0;
  for (let i = recent.length - 1; i >= 0; i--) {
    total += recent[i].content.length;
    if (total > MAX_HISTORY_CHARS) break;
    kept.unshift(recent[i]);
  }
  return kept;
}

// GET /api/verdict?ray=... — what the edge did to a given request.
export async function handleVerdict(url: URL, env: Env): Promise<Response> {
  const ray = (url.searchParams.get("ray") || "").split("-")[0].trim();
  if (!/^[0-9a-f]{16}$/i.test(ray)) {
    return Response.json({ error: "invalid ray" }, { status: 400 });
  }
  // Optional epoch-ms timestamp of the request itself, so the lookup window
  // can be anchored to when it happened rather than to now. Malformed values
  // are ignored rather than rejected — the live (unanchored) window is a
  // sane fallback, and a 400 here would break the card for no good reason.
  const tsRaw = url.searchParams.get("ts") || "";
  const tsNum = /^\d{10,16}$/.test(tsRaw) ? Number(tsRaw) : NaN;
  const atMs = Number.isFinite(tsNum) && tsNum > 0 && tsNum <= Date.now() + 86_400_000 ? tsNum : undefined;
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ZONE_ID) {
    return Response.json({ configured: false, ray });
  }
  try {
    // Past retention the datasets hold nothing, so skip the round trip and
    // say so — otherwise this is indistinguishable from an ingestion delay.
    const retentionSeconds = await queryVerdictRetention(env.CF_ZONE_ID, env.CF_ANALYTICS_TOKEN);
    if (isBeyondRetention(atMs, retentionSeconds)) {
      return Response.json({
        configured: true,
        ray,
        found: false,
        tooOld: true,
        retentionDays: Math.floor(retentionSeconds / 86_400),
      });
    }
    const verdict = await queryVerdict(env.CF_ZONE_ID, env.CF_ANALYTICS_TOKEN, ray, atMs);
    return Response.json({ configured: true, ray, ...verdict });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, ray, found: false, error: message }, { status: 502 });
  }
}

// GET /api/zone-rules — the zone's real WAF custom rules, so the flow trace and
// the analytics rule split stop relying on a hand-maintained mirror.
//
// Degrades the same way the gateway list does: any failure (missing token, no
// "Zone → WAF → Read" scope, API error) returns source:"fallback" with no rules
// rather than an error, and the client then renders its static mirror. A demo
// must not lose its rule display because one token scope is missing — but it
// must also never present the mirror AS live data, hence the explicit source.
export async function handleZoneRules(env: Env): Promise<Response> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ZONE_ID) {
    return Response.json({ configured: false, source: "fallback", rules: [] });
  }
  try {
    const rules = await queryZoneRules(env.CF_ZONE_ID, env.CF_ANALYTICS_TOKEN);
    return Response.json({ configured: true, source: "live", rules });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, source: "fallback", rules: [], error: message });
  }
}

// GET /api/neurons — account Neuron usage today vs the free daily allocation.
export async function handleNeurons(env: Env): Promise<Response> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) {
    return Response.json({ configured: false });
  }
  try {
    const usage = await queryNeuronUsage(env.CF_ACCOUNT_ID, env.CF_ANALYTICS_TOKEN);
    if (usage.error) {
      return Response.json({ configured: true, error: usage.error }, { status: 502 });
    }
    const pctUsed = (usage.totalNeurons / FREE_DAILY_NEURONS) * 100;
    const now = new Date();
    const resetsAt = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1),
    ).toISOString();
    return Response.json({
      configured: true,
      totalNeurons: usage.totalNeurons,
      requestCount: usage.requestCount,
      freeLimit: FREE_DAILY_NEURONS,
      overageUsdPer1k: OVERAGE_USD_PER_1K_NEURONS,
      pctUsed,
      resetsAt,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// Reasoning models wrap chain-of-thought in <think>…</think> before the real
// answer. Show the answer; if the model was cut off mid-think, show the
// partial reasoning rather than nothing.
function stripThink(text: string): string {
  const close = text.indexOf("</think>");
  if (close !== -1) {
    const after = text.slice(close + "</think>".length).trim();
    if (after) return after;
  }
  return text.replace(/^\s*<think>\s*/i, "").trim() || text;
}

// Extract the assistant text across Workers AI response shapes:
// - most models return { response: "..." }
// - OpenAI-format models (gpt-oss) return { choices: [{ message: { content } }] }
// - reasoning models (Gemma 4, DeepSeek R1) can finish with content: null and
//   the usable text in message.reasoning
export function extractReply(obj: Record<string, unknown>, result: unknown): string {
  if (typeof obj.response === "string" && obj.response !== "") return stripThink(obj.response);
  const choices = obj.choices as
    | { message?: { content?: unknown; reasoning?: unknown } }[]
    | undefined;
  const msg = choices?.[0]?.message;
  if (typeof msg?.content === "string" && msg.content !== "") return stripThink(msg.content);
  if (typeof msg?.reasoning === "string" && msg.reasoning !== "") return msg.reasoning.trim();
  if (obj.response && typeof obj.response === "object") {
    const out = (obj.response as { output_text?: unknown }).output_text;
    if (typeof out === "string") return out;
  }
  return typeof result === "string" ? result : JSON.stringify(result);
}

// AI Gateway Guardrails surface as binding errors: 2016 = prompt blocked,
// 2017 = response blocked ("... due to security configurations"). Map either
// to a structured 200 the client renders as a purple guardrails card.
function guardrailsResponse(
  err: unknown,
  model: string,
  gatewayId: string,
  guarded: boolean,
): Response | null {
  const message = err instanceof Error ? err.message : String(err);
  const promptBlocked = /\b2016\b|prompt blocked/i.test(message);
  const responseBlocked = /\b2017\b|response blocked/i.test(message);
  if (!promptBlocked && !responseBlocked) return null;
  return Response.json({
    guardrailsBlocked: true,
    direction: responseBlocked ? "response" : "prompt",
    model,
    // Nested to match the reply-path shape so the client reads gateway meta
    // (id + guarded flag) uniformly via `data.gateway` on both paths.
    gateway: { gatewayId, guarded },
    detail: message,
  });
}

// For a streaming gateway call the reply is passed through as SSE, so cache
// status / log id can't ride in the JSON body. Append them as one trailing
// `data: {"gateway": …}` event after the model's stream ends (read inside the
// TransformStream flush). Unlike the old binding path, the REST call's cache
// status is already known from the response headers before the body is even
// read, so no async getLog() lookup is needed here.
function appendRestGatewayEvent(
  source: ReadableStream,
  meta: { gatewayId: string; cached: boolean | null; logId: string | null; guarded: boolean },
  started: number,
): ReadableStream {
  const enc = new TextEncoder();
  return source.pipeThrough(
    new TransformStream({
      flush(controller) {
        const full = { ...meta, latencyMs: Date.now() - started };
        controller.enqueue(enc.encode(`data: ${JSON.stringify({ gateway: full })}\n\n`));
      },
    }),
  );
}

// POST /api/chat — run the selected model with the (optional) system prompt
// and prior conversation turns. The request always hits this same
// cf-llm-labeled path, so the edge WAF scan (and the verdict) applies whether
// or not gateway routing is on. With stream:true the reply is passed through
// as SSE and the client assembles the reply + metadata itself.
//
// --- AI Gateway routing (REST) ------------------------------------------
// With gateway:true, inference goes through AI Gateway's OpenAI-compatible
// REST endpoint rather than the env.AI.run() binding. This is what makes the
// full set of per-request cf-aig-* headers available (cache TTL/key, retry
// tuning, request timeout, log collection, …) — the binding's `gateway`
// option only ever exposed a few of them. It also means Dynamic Routes work
// uniformly here (a route name goes in the `model` field, which the binding
// rejects since it only accepts real model ids) instead of needing a special
// case. Requires an API token (CF_AIG_TOKEN) with "AI Gateway - Read",
// "AI Gateway - Edit", and "Workers AI - Read" — not the "AI Gateway Run"
// gateway-scoped token from Authenticated Gateway, which this endpoint rejects
// with a generic {"code":10000,"message":"Authentication error"}.
//
// A direct (non-gateway) call still uses the plain env.AI.run() binding —
// none of this applies since the request never goes through a gateway.
type GatewayRestResult =
  | {
      kind: "json";
      reply: string;
      model: string;
      promptTokens?: number;
      completionTokens?: number;
      logId: string | null;
      cached: boolean | null;
    }
  | { kind: "stream"; body: ReadableStream; logId: string | null; cached: boolean | null }
  | { kind: "error"; status: number; message: string };

// "HIT"/"MISS" → boolean; anything else (DYNAMIC, BYPASS, absent, …) → unknown.
function cacheStatusFromHeader(v: string | null): boolean | null {
  if (v == null) return null;
  const s = v.toUpperCase();
  if (s === "HIT") return true;
  if (s === "MISS") return false;
  return null;
}

async function runGatewayRest(
  env: Env,
  opts: {
    model: string; // ignored when `route` is set — the route picks the model
    route?: string; // Dynamic Routing route name
    gatewayId: string;
    messages: { role: string; content: string }[];
    stream: boolean;
    metadata?: Record<string, string>;
    skipCache?: boolean;
    cacheTtl?: number;
    cacheKey?: string;
    collectLog?: boolean;
    requestTimeoutMs?: number;
    maxAttempts?: number;
    retryDelayMs?: number;
    backoff?: GatewayBackoff;
  },
): Promise<GatewayRestResult> {
  if (!env.CF_AIG_TOKEN || !env.CF_ACCOUNT_ID) {
    return {
      kind: "error",
      status: 501,
      message:
        'AI Gateway needs CF_ACCOUNT_ID and the CF_AIG_TOKEN secret (an API token with "AI Gateway - Read", "AI Gateway - Edit", and "Workers AI - Read"). Set it with: wrangler secret put CF_AIG_TOKEN',
    };
  }

  // Custom metadata (and every other per-request setting) travels as a
  // HEADER, not a body field — a body `metadata` key is ignored by the
  // gateway (and may be rejected as unknown by the OpenAI-compatible schema).
  const headers: Record<string, string> = {
    authorization: "Bearer " + env.CF_AIG_TOKEN,
    "cf-aig-gateway-id": opts.gatewayId,
    "content-type": "application/json",
  };
  if (opts.metadata && Object.keys(opts.metadata).length) headers["cf-aig-metadata"] = JSON.stringify(opts.metadata);
  if (opts.skipCache) headers["cf-aig-skip-cache"] = "true";
  if (opts.cacheTtl != null) headers["cf-aig-cache-ttl"] = String(opts.cacheTtl);
  if (opts.cacheKey) headers["cf-aig-cache-key"] = opts.cacheKey;
  if (opts.collectLog != null) headers["cf-aig-collect-log"] = String(opts.collectLog);
  if (opts.requestTimeoutMs != null) headers["cf-aig-request-timeout"] = String(opts.requestTimeoutMs);
  if (opts.maxAttempts != null) headers["cf-aig-max-attempts"] = String(opts.maxAttempts);
  if (opts.retryDelayMs != null) headers["cf-aig-retry-delay"] = String(opts.retryDelayMs);
  if (opts.backoff) headers["cf-aig-backoff"] = opts.backoff;

  const res = await fetch(`${CF_API_BASE}/accounts/${env.CF_ACCOUNT_ID}${OPENAI_CHAT_PATH}`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: opts.route ? DYNAMIC_ROUTE_PREFIX + opts.route : opts.model,
      messages: opts.messages,
      max_tokens: MAX_REPLY_TOKENS,
      stream: opts.stream || undefined,
    }),
  });

  if (!res.ok) {
    // Read the body as text so a Guardrails 2016/2017 block can be matched by
    // the same detector the binding path used to use.
    const detail = await res.text();
    return { kind: "error", status: res.status, message: detail || `AI Gateway returned HTTP ${res.status}` };
  }

  const logId = res.headers.get("cf-aig-log-id");
  const cached = cacheStatusFromHeader(res.headers.get("cf-aig-cache-status"));

  if (opts.stream && res.body) {
    return { kind: "stream", body: res.body, logId, cached };
  }

  const obj = (await res.json()) as Record<string, unknown>;
  const usage = obj.usage as { prompt_tokens?: number; completion_tokens?: number } | undefined;
  return {
    kind: "json",
    // extractReply already understands the OpenAI choices[].message.content shape.
    reply: extractReply(obj, obj),
    model: typeof obj.model === "string" ? obj.model : "",
    promptTokens: usage?.prompt_tokens,
    completionTokens: usage?.completion_tokens,
    logId,
    cached,
  };
}

// Write one prompt-log row (best effort). Prompt/reply are redacted here so
// no live PII lands in D1. Runs via ctx.waitUntil so it never blocks the
// reply, and silently no-ops when D1 is unbound. The ray is the join key to
// the edge verdict (queried live in the UI, not duplicated here).
async function logPrompt(
  env: Env,
  fields: {
    ray: string | null;
    route: "direct" | "gateway";
    model: string;
    gatewayId: string | null;
    guarded: boolean;
    outcome: PromptLogRow["outcome"];
    prompt: string;
    reply: string | null;
    promptTokens?: number | null;
    completionTokens?: number | null;
  },
): Promise<void> {
  if (!env.DB || !fields.ray) return;
  const p = redact(fields.prompt);
  const r = fields.reply != null ? redact(fields.reply) : { text: null, count: 0 };
  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO prompt_log
       (ray, ts, route, model, gateway_id, guarded, outcome, prompt, reply, redactions, prompt_tokens, completion_tokens)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        fields.ray,
        Date.now(),
        fields.route,
        fields.model,
        fields.gatewayId,
        fields.guarded ? 1 : 0,
        fields.outcome,
        p.text,
        r.text,
        p.count + r.count,
        fields.promptTokens ?? null,
        fields.completionTokens ?? null,
      )
      .run();
  } catch {
    /* logging must never break chat */
  }
}

// Fill in a streamed turn's reply after the fact.
//
// The row is inserted when the request is handled, at which point a streamed
// reply does not exist yet — so it went in as NULL and stayed that way, which
// is the DEFAULT path in this app (streaming is on by default). This updates
// the row once the stream has finished passing through, so the log's evidence
// trail covers streamed turns too. UPDATE rather than a deferred INSERT: the
// row must exist immediately, even if the client disconnects mid-stream.
async function updateLoggedReply(env: Env, ray: string, reply: string): Promise<void> {
  if (!env.DB || !reply) return;
  const r = redact(reply);
  try {
    await env.DB.prepare(
      `UPDATE prompt_log
       SET reply = ?, redactions = redactions + ?, completion_tokens = COALESCE(completion_tokens, ?)
       WHERE ray = ?`,
    )
      // Same ~4 chars/token estimate the non-streaming path falls back to.
      .bind(r.text, r.count, Math.ceil(reply.length / 4), ray)
      .run();
  } catch {
    /* logging must never break chat */
  }
}

// Pass an SSE body through untouched while assembling the reply text from it,
// then write that text to the prompt log. Nothing is buffered — chunks are
// forwarded as they arrive and only a copy of the decoded text accumulates.
function teeReplyToLog(
  source: ReadableStream,
  env: Env,
  ray: string | null,
  excluded: boolean,
  inserted: Promise<void>,
  ctx?: ExecutionContext,
): ReadableStream {
  if (!ray || excluded || !env.DB) return source;
  const acc = createSseAccumulator();
  const decoder = new TextDecoder();
  return source.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        controller.enqueue(chunk);
        try {
          acc.push(decoder.decode(chunk, { stream: true }));
        } catch {
          /* never let bookkeeping break the stream the user is reading */
        }
      },
      flush() {
        const text = acc.done();
        // Chained onto the insert so the row is guaranteed to exist first.
        if (text) ctx?.waitUntil(inserted.then(() => updateLoggedReply(env, ray, text)));
      },
    }),
  );
}

export async function handleChat(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") {
    return Response.json({ error: "Use POST" }, { status: 405 });
  }

  let prompt: string;
  let model = DEFAULT_MODEL;
  let systemPrompt = DEFAULT_SYSTEM_PROMPT;
  let history: ChatTurn[] = [];
  let stream = false;
  let gateway = false;
  let skipCache = false;
  let requestedGatewayId: string | undefined;
  let dynamicRoute = "";
  let badRoute: string | null = null;
  let routeMetadata: Record<string, string> | undefined;
  // Skip writing this turn to the D1 prompt_log table — independent of AI
  // Gateway's own `collectLog`/`cf-aig-collect-log`, which is a different log
  // (the gateway's request log) from a different route (only exists on the
  // gateway path). This one is app-level and applies to both routes.
  let excludeFromLog = false;
  // Remaining per-request AI Gateway REST settings — all optional, all no-ops
  // unless `gateway` is true. See runGatewayRest for how each becomes a header.
  let cacheTtl: number | undefined;
  let cacheKey: string | undefined;
  let collectLog: boolean | undefined;
  let requestTimeoutMs: number | undefined;
  let maxAttempts: number | undefined;
  let retryDelayMs: number | undefined;
  let backoff: GatewayBackoff | undefined;
  try {
    const body = await request.json<ChatRequestBody>();
    if (typeof body.prompt !== "string" || body.prompt.trim() === "") {
      throw new Error("missing prompt");
    }
    prompt = body.prompt.trim();
    // Only honor a model the server explicitly allows; otherwise fall back.
    if (typeof body.model === "string" && ALLOWED_IDS.has(body.model)) {
      model = body.model;
    }
    if (typeof body.systemPrompt === "string" && body.systemPrompt.trim() !== "") {
      systemPrompt = body.systemPrompt.trim().slice(0, MAX_SYSTEM_PROMPT_LEN);
    }
    history = sanitizeHistory(body.history);
    if (body.stream === true) stream = true;
    if (body.excludeFromLog === true) excludeFromLog = true;
    if (body.gateway === true) gateway = true;
    if (typeof body.skipCache === "boolean") skipCache = body.skipCache;
    if (typeof body.gatewayId === "string") requestedGatewayId = body.gatewayId;
    if (typeof body.dynamicRoute === "string" && body.dynamicRoute.trim() !== "") {
      // Note the rejection rather than throwing: this runs inside the
      // malformed-JSON try/catch, which would report the wrong error.
      const name = normalizeDynamicRoute(body.dynamicRoute);
      if (name) dynamicRoute = name;
      else badRoute = body.dynamicRoute;
    }
    if (body.routeMetadata && typeof body.routeMetadata === "object") {
      // AI Gateway keeps only the first 5 entries and silently drops the rest,
      // so cap here to make the truncation explicit and predictable.
      routeMetadata = Object.fromEntries(
        Object.entries(body.routeMetadata as Record<string, unknown>)
          .filter(([k]) => ROUTE_ID_RE.test(k))
          .slice(0, MAX_METADATA_ENTRIES)
          .map(([k, v]) => [k, String(v).slice(0, 128)]),
      );
    }
    if (typeof body.cacheTtl === "number" && body.cacheTtl > 0) cacheTtl = Math.floor(body.cacheTtl);
    if (typeof body.cacheKey === "string" && body.cacheKey.trim() !== "") cacheKey = body.cacheKey.trim().slice(0, 128);
    if (typeof body.collectLog === "boolean") collectLog = body.collectLog;
    if (typeof body.requestTimeoutMs === "number" && body.requestTimeoutMs > 0) {
      requestTimeoutMs = Math.floor(body.requestTimeoutMs);
    }
    if (typeof body.maxAttempts === "number") {
      maxAttempts = Math.max(1, Math.min(MAX_GATEWAY_ATTEMPTS, Math.floor(body.maxAttempts)));
    }
    if (typeof body.retryDelayMs === "number") {
      retryDelayMs = Math.max(0, Math.min(MAX_GATEWAY_RETRY_DELAY_MS, Math.floor(body.retryDelayMs)));
    }
    if (typeof body.backoff === "string" && (GATEWAY_BACKOFF_VALUES as readonly string[]).includes(body.backoff)) {
      backoff = body.backoff as GatewayBackoff;
    }
  } catch {
    return Response.json(
      {
        error:
          'Body must be JSON: {"prompt": "...", "model"?, "systemPrompt"?, "history"?, "stream"?, "gateway"?, "gatewayId"?, "skipCache"?}',
      },
      { status: 400 },
    );
  }

  // A route that can't be used is an error, not a reason to quietly fall back
  // to a different path — a silent downgrade makes the demo look like it
  // worked while running an entirely different path.
  if (badRoute !== null) {
    return Response.json(
      {
        error:
          `Invalid dynamicRoute ${JSON.stringify(badRoute)}. Use the route name (e.g. "demo-routes") ` +
          `or the dashboard form ("dynamic/demo-routes"); letters, digits, "_" and "-" only.`,
      },
      { status: 400 },
    );
  }

  // Resolve the AI Gateway (only when gateway routing is on). The requested
  // gateway id can be any gateway in the account (the dropdown is populated
  // live from the account); it's sanity-checked to the gateway-id charset and
  // falls back to the default gateway otherwise. `guarded` is derived from the
  // configured guarded gateway.
  let gatewayId = "";
  let guarded = false;
  if (gateway) {
    const valid = typeof requestedGatewayId === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(requestedGatewayId);
    gatewayId = valid ? requestedGatewayId! : env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID;
    guarded = !!env.CF_AI_GATEWAY_GUARDED_ID && gatewayId === env.CF_AI_GATEWAY_GUARDED_ID;
  }

  const messages = [
    { role: "system", content: systemPrompt },
    ...history,
    { role: "user", content: prompt },
  ];
  const started = Date.now();
  const ray = request.headers.get("cf-ray");
  const route: "direct" | "gateway" = gateway ? "gateway" : "direct";
  const logBase = { ray, route, model, gatewayId: gateway ? gatewayId : null, guarded };
  // Returns the scheduled write so a later update (the streamed reply, which
  // only exists once the stream ends) can chain onto it. Both run under
  // waitUntil, which gives no ordering guarantee of its own — and an UPDATE
  // that lands before its INSERT silently matches no row.
  const log = (
    outcome: PromptLogRow["outcome"],
    extra: { reply: string | null; promptTokens?: number | null; completionTokens?: number | null },
  ): Promise<void> => {
    if (excludeFromLog) return Promise.resolve();
    const done = logPrompt(env, { ...logBase, outcome, prompt, ...extra });
    ctx?.waitUntil(done);
    return done;
  };

  // AI Gateway path — always REST (see runGatewayRest doc comment for why).
  if (gateway) {
    const r = await runGatewayRest(env, {
      model,
      route: dynamicRoute || undefined,
      gatewayId,
      messages,
      stream,
      metadata: routeMetadata,
      skipCache,
      cacheTtl,
      cacheKey,
      collectLog,
      requestTimeoutMs,
      maxAttempts,
      retryDelayMs,
      backoff,
    });

    if (r.kind === "error") {
      // A Guardrails block arrives as an HTTP error here rather than a binding
      // exception; the same 2016/2017 detector maps it to the purple card.
      const gr = guardrailsResponse(r.message, model, gatewayId, guarded);
      log(gr ? "guardrails" : "error", { reply: null });
      if (gr) return gr;
      return Response.json(
        { error: r.message, model, dynamicRoute: dynamicRoute || undefined },
        { status: r.status },
      );
    }

    if (r.kind === "stream") {
      // Logged with a null reply first, then filled in by teeReplyToLog once
      // the stream ends — the row has to exist even if the client disconnects.
      const inserted = log("reply", { reply: null });
      const withMeta = appendRestGatewayEvent(
        r.body,
        { gatewayId, cached: r.cached, logId: r.logId, guarded },
        started,
      );
      // Tee AFTER the trailing gateway event is appended; that event carries no
      // token, so the accumulator ignores it either way.
      const body = teeReplyToLog(withMeta, env, ray, excludeFromLog, inserted, ctx);
      return new Response(body, {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    }

    // A Dynamic Route picks its own model, so report what actually ran rather
    // than the (ignored) requested one; a plain gateway call echoes it back.
    const ranModel = r.model || model;
    const price = MODEL_BY_ID.get(ranModel);
    const promptTokens = r.promptTokens ?? Math.ceil((systemPrompt.length + prompt.length) / 4);
    const completionTokens = r.completionTokens ?? Math.ceil(r.reply.length / 4);
    const cost = r.cached === true ? 0 : price ? (promptTokens / 1e6) * price.priceIn + (completionTokens / 1e6) * price.priceOut : null;
    log("reply", { reply: r.reply, promptTokens, completionTokens });
    return Response.json({
      reply: r.reply,
      model: ranModel,
      ray,
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: promptTokens + completionTokens,
        estimated: r.promptTokens == null,
      },
      cost,
      gateway: { gatewayId, cached: r.cached, latencyMs: Date.now() - started, logId: r.logId, guarded },
      dynamicRoute: dynamicRoute || undefined,
    });
  }

  // Direct Workers AI path — plain binding call, no gateway involved at all.
  if (stream) {
    try {
      const sse = (await env.AI.run(model, { messages, max_tokens: MAX_REPLY_TOKENS, stream: true } as never)) as unknown as ReadableStream;
      // Row goes in now with a null reply; teeReplyToLog fills it in as the
      // stream drains, so a streamed turn is no longer a blank in the log.
      const inserted = log("reply", { reply: null });
      return new Response(teeReplyToLog(sse, env, ray, excludeFromLog, inserted, ctx), {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    } catch (err) {
      log("error", { reply: null });
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ error: `Workers AI error (${model}): ${message}`, model }, { status: 502 });
    }
  }

  try {
    const result = await env.AI.run(model, { messages, max_tokens: MAX_REPLY_TOKENS });
    const obj =
      typeof result === "object" && result !== null
        ? (result as Record<string, unknown>)
        : {};
    const reply = extractReply(obj, result);

    // Token usage: prefer the model's reported usage; otherwise estimate
    // (~4 chars/token) so the demo always shows a number.
    const u = obj.usage as
      | { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number }
      | undefined;
    let promptTokens = u?.prompt_tokens;
    let completionTokens = u?.completion_tokens;
    let estimated = false;
    if (promptTokens == null || completionTokens == null) {
      estimated = true;
      const historyChars = history.reduce((n, t) => n + t.content.length, 0);
      promptTokens = Math.ceil((systemPrompt.length + historyChars + prompt.length) / 4);
      completionTokens = Math.ceil(reply.length / 4);
    }
    const totalTokens = u?.total_tokens ?? promptTokens + completionTokens;

    const price = MODEL_BY_ID.get(model);
    const cost = price ? (promptTokens / 1e6) * price.priceIn + (completionTokens / 1e6) * price.priceOut : null;

    log("reply", { reply, promptTokens, completionTokens });
    return Response.json({
      reply,
      model,
      ray,
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: totalTokens,
        estimated,
      },
      cost, // USD, estimated from published unit pricing
      gateway: undefined, // never set on the direct path
    });
  } catch (err) {
    log("error", { reply: null });
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ error: `Workers AI error (${model}): ${message}`, model }, { status: 502 });
  }
}

// GET /api/analytics?hours=24 — aggregated zone security events + AI scores
// for the dashboard page. Raw events come from GraphQL; aggregation happens
// here so the client receives one small payload.
export async function handleAnalytics(url: URL, env: Env): Promise<Response> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ZONE_ID) {
    return Response.json({ configured: false });
  }
  const hours = Math.min(168, Math.max(1, parseInt(url.searchParams.get("hours") || "24", 10) || 24));
  try {
    const summary = await queryAnalytics(env.CF_ZONE_ID, env.CF_ANALYTICS_TOKEN, hours);
    if (summary.error) {
      return Response.json({ configured: true, error: summary.error }, { status: 502 });
    }
    return Response.json({ configured: true, ...summary });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// GET /api/gateway-analytics?gatewayId=&hours=24 — aggregated AI Gateway logs
// for the dashboard's gateway tab. Account-scoped (unlike the zone analytics
// above): these logs cover every app using the gateway, which the UI states.
export async function handleGatewayAnalytics(url: URL, env: Env): Promise<Response> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) {
    return Response.json({ configured: false });
  }
  const hours = Math.min(168, Math.max(1, parseInt(url.searchParams.get("hours") || "24", 10) || 24));

  // Same charset sanity check handleChat uses; fall back to the default gateway
  // when the id is absent or not one the account actually has.
  const requested = url.searchParams.get("gatewayId") || "";
  const gateways = await resolveGateways(env);
  const fallback = gateways.find((g) => g.id === (env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID)) ?? gateways[0];
  const valid = /^[a-zA-Z0-9_-]{1,64}$/.test(requested);
  const entry = (valid && gateways.find((g) => g.id === requested)) || fallback;
  if (!entry) return Response.json({ configured: false });

  try {
    const summary = await queryGatewayLogs(
      env.CF_ACCOUNT_ID,
      env.CF_ANALYTICS_TOKEN,
      entry.id,
      entry.guarded,
      hours,
    );
    if (summary.error) {
      return Response.json({ configured: true, error: summary.error }, { status: 502 });
    }
    return Response.json({ configured: true, ...summary });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// Shared by /api/prompt-log and /api/prompt-analytics: an explicit
// since/until (epoch ms) pair wins when present — that is the custom
// date/time picker — otherwise `hours` (0/absent = all time) picks a rolling
// window ending now, which is what the 1h/24h/7d/all preset buttons send.
//
// `spanHours` is the width the caller ASKED for, carried alongside so the
// chart's bucket width can be derived from the request rather than re-measured
// from `Date.now() - since`. Re-measuring is off by the milliseconds spent
// parsing, which is enough to push the 1h preset just past 1.0 hours and drop
// it from 5-minute buckets to hourly. Null when the width is unknowable here
// (all-time, or an open-ended `since`) — the caller then derives it from the
// data's own first/last row.
function parseTimeWindow(url: URL): {
  since: number | null;
  until: number | null;
  spanHours: number | null;
} {
  const sinceRaw = url.searchParams.get("since");
  const untilRaw = url.searchParams.get("until");
  const since = sinceRaw != null ? Number(sinceRaw) : NaN;
  const until = untilRaw != null ? Number(untilRaw) : NaN;
  if (Number.isFinite(since) || Number.isFinite(until)) {
    const s = Number.isFinite(since) ? since : null;
    const u = Number.isFinite(until) ? until : null;
    return { since: s, until: u, spanHours: s != null && u != null ? (u - s) / 3_600_000 : null };
  }
  const rawHours = parseInt(url.searchParams.get("hours") || "0", 10) || 0;
  const hours = Math.min(168, Math.max(0, rawHours));
  return {
    since: hours > 0 ? Date.now() - hours * 3_600_000 : null,
    until: null,
    spanHours: hours > 0 ? hours : null,
  };
}

// GET  /api/prompt-log?limit=&offset=&route=&outcome=&q=&sort=&dir=&hours=|since=&until=
// — one page of PII-redacted prompts. Filtering, sorting and paging all happen
// in SQL so the page is a true window onto the whole table; the previous
// version fetched the newest 200 rows and sliced them client-side, which made
// everything older than that unreachable however you filtered.
// DELETE /api/prompt-log — clears the log (the "Clear log" button).
// Rows join to the live edge verdict by ray in the UI; detections aren't stored
// here (they ingest into GraphQL seconds later, after this row is written).
export async function handlePromptLog(request: Request, url: URL, env: Env): Promise<Response> {
  if (!env.DB) return Response.json({ configured: false });

  if (request.method === "DELETE") {
    try {
      await env.DB.prepare("DELETE FROM prompt_log").run();
      return Response.json({ configured: true, cleared: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ configured: true, error: message }, { status: 502 });
    }
  }
  if (request.method !== "GET") return Response.json({ error: "Use GET or DELETE" }, { status: 405 });

  const { since, until } = parseTimeWindow(url);
  const num = (name: string): number | null => {
    const raw = url.searchParams.get(name);
    if (raw == null) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  };
  const { clause, binds, orderBy, limit, offset } = buildPromptLogQuery({
    route: url.searchParams.get("route"), // 'direct' | 'gateway' | null
    // Comma-separated so the UI can select any combination, e.g. "reply,error"
    // to see everything except guardrails-blocked. Absent/empty = no filter.
    outcomes: (url.searchParams.get("outcome") || "").split(",").map((o) => o.trim()),
    since,
    until,
    q: url.searchParams.get("q"),
    sort: url.searchParams.get("sort"),
    dir: url.searchParams.get("dir"),
    limit: num("limit"),
    offset: num("offset"),
  });

  try {
    const { results } = await env.DB.prepare(
      `SELECT ray, ts, route, model, gateway_id AS gatewayId, guarded, outcome,
              prompt, reply, redactions, prompt_tokens AS promptTokens,
              completion_tokens AS completionTokens
       FROM prompt_log ${clause} ${orderBy} LIMIT ? OFFSET ?`,
    )
      .bind(...binds, limit, offset)
      .all<PromptLogRow>();
    // `filtered` counts every row the filters match, not just this page — the
    // client needs it to know how many pages exist. `total` stays the whole
    // table, so the UI can still say "N stored, just not in this window".
    const filtered = await env.DB.prepare(`SELECT COUNT(*) AS n FROM prompt_log ${clause}`)
      .bind(...binds)
      .first<{ n: number }>();
    const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM prompt_log").first<{ n: number }>();
    return Response.json({
      configured: true,
      rows: results ?? [],
      filtered: filtered?.n ?? 0,
      total: total?.n ?? 0,
      limit,
      offset,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // A missing table reads as "not configured" so the UI shows the setup hint.
    if (/no such table/i.test(message)) return Response.json({ configured: false });
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// GET /api/prompt-analytics?hours=|since=&until= — aggregates over the whole
// prompt log. Every rollup is a SQL GROUP BY executed inside D1 (not a
// Worker-side pass over capped rows), so the numbers stay correct however
// large the table gets.
export async function handlePromptAnalytics(url: URL, env: Env): Promise<Response> {
  if (!env.DB) return Response.json({ configured: false });

  const { since, until, spanHours } = parseTimeWindow(url);
  const whereParts: string[] = [];
  const binds: number[] = [];
  if (since != null) {
    whereParts.push("ts >= ?");
    binds.push(since);
  }
  if (until != null) {
    whereParts.push("ts <= ?");
    binds.push(until);
  }
  const whereTs = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

  try {
    const db = env.DB;
    const q = <T>(sql: string) => db.prepare(sql).bind(...binds).all<T>();

    const [totals, byOutcome, byRoute, byModel, repeated, rows] = await Promise.all([
      db
        .prepare(
          `SELECT COUNT(*) AS total,
                  SUM(CASE WHEN redactions > 0 THEN 1 ELSE 0 END) AS withPii,
                  COALESCE(SUM(redactions),0) AS redactions,
                  COALESCE(SUM(prompt_tokens),0) AS promptTokens,
                  COALESCE(SUM(completion_tokens),0) AS completionTokens,
                  MIN(ts) AS firstTs, MAX(ts) AS lastTs
           FROM prompt_log ${whereTs}`,
        )
        .bind(...binds)
        .first<{
          total: number; withPii: number; redactions: number;
          promptTokens: number; completionTokens: number;
          firstTs: number | null; lastTs: number | null;
        }>(),
      q<{ outcome: string; count: number }>(
        `SELECT outcome, COUNT(*) AS count FROM prompt_log ${whereTs}
         GROUP BY outcome ORDER BY count DESC`,
      ),
      q<{ route: string; count: number }>(
        `SELECT route, COUNT(*) AS count FROM prompt_log ${whereTs}
         GROUP BY route ORDER BY count DESC`,
      ),
      q<{ model: string; count: number; promptTokens: number; completionTokens: number }>(
        `SELECT model, COUNT(*) AS count,
                COALESCE(SUM(prompt_tokens),0) AS promptTokens,
                COALESCE(SUM(completion_tokens),0) AS completionTokens
         FROM prompt_log ${whereTs} GROUP BY model ORDER BY count DESC`,
      ),
      q<{ prompt: string; count: number; redactions: number }>(
        `SELECT prompt, COUNT(*) AS count, MAX(redactions) AS redactions
         FROM prompt_log ${whereTs}
         GROUP BY prompt HAVING COUNT(*) > 1 ORDER BY count DESC LIMIT 10`,
      ),
      q<{ ts: number; outcome: string }>(
        `SELECT ts, outcome FROM prompt_log ${whereTs} ORDER BY ts ASC`,
      ),
    ]);

    // Time series bucket width, from the width the caller asked for. Only when
    // that is unknowable (all time / open-ended since) is it derived from the
    // data itself, so a long-idle demo log still buckets sensibly. Fractional
    // hours throughout: a 40-minute window must land on 5-minute buckets, not
    // be rounded up into hourly ones.
    const dataSpanHours = Math.max(0, (totals?.lastTs ?? 0) - (totals?.firstTs ?? 0)) / 3_600_000;
    const { bucket, stepMs } = bucketFor(spanHours ?? dataSpanHours);
    type SeriesRow = { t: string; reply: number; guardrails: number; error: number };
    const series = new Map<string, SeriesRow>();

    // Pre-fill every bucket across the window so a quiet stretch renders as
    // zero instead of vanishing. Without this the chart only holds buckets
    // that had rows and the line interpolates straight across the gaps —
    // drawing activity that never happened. The zone analytics scaffold
    // (makeBuckets) has always done this; the prompt log never did, which only
    // became visible once 5-minute buckets made gaps common. Capped so a
    // hand-typed `since` far in the past can't spin here.
    const MAX_PREFILL_BUCKETS = 400;
    const rangeStart = since ?? totals?.firstTs ?? null;
    const rangeEnd = until ?? (since != null ? Date.now() : (totals?.lastTs ?? null));
    if (rangeStart != null && rangeEnd != null && rangeEnd >= rangeStart) {
      const first = Math.floor(rangeStart / stepMs) * stepMs;
      const count = Math.floor((rangeEnd - first) / stepMs) + 1;
      if (count <= MAX_PREFILL_BUCKETS) {
        for (let t = first; t <= rangeEnd; t += stepMs) {
          const key = new Date(t).toISOString();
          series.set(key, { t: key, reply: 0, guardrails: 0, error: 0 });
        }
      }
    }

    for (const r of rows.results ?? []) {
      const key = new Date(Math.floor(r.ts / stepMs) * stepMs).toISOString();
      const row = series.get(key) ?? { t: key, reply: 0, guardrails: 0, error: 0 };
      if (r.outcome === "guardrails") row.guardrails++;
      else if (r.outcome === "error") row.error++;
      else row.reply++;
      series.set(key, row);
    }

    const summary: PromptAnalytics = {
      total: totals?.total ?? 0,
      withPii: totals?.withPii ?? 0,
      redactions: totals?.redactions ?? 0,
      promptTokens: totals?.promptTokens ?? 0,
      completionTokens: totals?.completionTokens ?? 0,
      byOutcome: byOutcome.results ?? [],
      byRoute: byRoute.results ?? [],
      byModel: byModel.results ?? [],
      repeated: repeated.results ?? [],
      series: [...series.values()].sort((a, b) => a.t.localeCompare(b.t)),
      bucket,
      firstTs: totals?.firstTs ?? null,
      lastTs: totals?.lastTs ?? null,
    };
    return Response.json({ configured: true, ...summary });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/no such table/i.test(message)) return Response.json({ configured: false });
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// GET  /api/redteam-runs             — list saved runs, metadata only (no results).
// GET  /api/redteam-runs?id=123      — one run plus its per-attack results.
// POST /api/redteam-runs             — save a finished run (see below).
// DELETE /api/redteam-runs?id=123    — delete one run (cascades its results).
//
// Persists what web/src/hooks/useRedTeam.ts already scored client-side — the
// Worker never re-derives a verdict or a state here (see the header on
// redteam_runs in migrations/0003_redteam_runs.sql). This is the layer that
// makes the feature's before/after claim survive a reload: without it, two
// runs only ever exist in React state at once and the "we closed the gap"
// comparison the Red Team page exists to make is impossible.
//
// POST is unauthenticated in `wrangler dev` (prod sits behind Cloudflare
// Access; local/dev does not), so every field is validated and capped in
// validateRedTeamRunPayload (src/redteamruns.ts) before anything is bound
// into SQL or written to D1 — nothing here trusts the client body directly.
export async function handleRedTeamRuns(request: Request, url: URL, env: Env): Promise<Response> {
  if (!env.DB) return Response.json({ configured: false });

  if (request.method === "DELETE") {
    const id = parseRunId(url.searchParams.get("id"));
    if (id == null) return Response.json({ configured: true, error: "id must be a positive integer" }, { status: 400 });
    try {
      // Results first: they carry no FK enforcement (D1/SQLite won't cascade
      // on their own here), so deleting the run first would orphan them.
      await env.DB.prepare("DELETE FROM redteam_results WHERE run_id = ?").bind(id).run();
      const del = await env.DB.prepare("DELETE FROM redteam_runs WHERE id = ?").bind(id).run();
      return Response.json({ configured: true, deleted: (del.meta.changes ?? 0) > 0 });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/no such table/i.test(message)) return Response.json({ configured: false });
      return Response.json({ configured: true, error: message }, { status: 502 });
    }
  }

  if (request.method === "POST") {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return Response.json({ configured: true, error: "Invalid JSON body" }, { status: 400 });
    }
    const validated = validateRedTeamRunPayload(body);
    if (!validated.ok) return Response.json({ configured: true, error: validated.error }, { status: 400 });
    const run = validated.run;

    try {
      // Insert the run row first (not part of the batch below) so its
      // AUTOINCREMENT id is known before the per-attack result rows, which
      // all carry it as run_id, are built.
      const runInsert = await env.DB.prepare(
        `INSERT INTO redteam_runs
           (ts, label, route, gateway_id, guarded, model, corpus_name, corpus_size,
            corpus_fingerprint, delay_ms, total, scored, reached, stopped, denied,
            guardrails, pending, error, reached_pct)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
        .bind(
          run.ts,
          run.label,
          run.route,
          run.gatewayId,
          run.guarded ? 1 : 0,
          run.model,
          run.corpusName,
          run.corpusSize,
          run.corpusFingerprint,
          run.delayMs,
          run.total,
          run.scored,
          run.reached,
          run.stopped,
          run.denied,
          run.guardrails,
          run.pending,
          run.error,
          run.reachedPct,
        )
        .run();
      const runId = runInsert.meta.last_row_id;

      // One batch for every result row plus the two prune deletes, so a
      // crash mid-write can't leave a run with only half its results stored,
      // or leave pruned runs' results behind as orphans.
      const resultStmt = env.DB.prepare(
        `INSERT INTO redteam_results
           (run_id, attack_key, attack_id, category, severity, state, ray, ts, prompt_preview)
         VALUES (?,?,?,?,?,?,?,?,?)`,
      );
      const statements = run.results.map((r) =>
        resultStmt.bind(runId, r.attackKey, r.attackId, r.category, r.severity, r.state, r.ray, r.ts, r.promptPreview),
      );
      // Prune to the newest REDTEAM_RUNS_MAX_STORED runs so this table — sitting
      // behind an unauthenticated write in dev — cannot grow without bound.
      statements.push(
        env.DB.prepare(
          `DELETE FROM redteam_runs WHERE id NOT IN
             (SELECT id FROM redteam_runs ORDER BY ts DESC LIMIT ?)`,
        ).bind(REDTEAM_RUNS_MAX_STORED),
        env.DB.prepare(`DELETE FROM redteam_results WHERE run_id NOT IN (SELECT id FROM redteam_runs)`),
      );
      const batchResults = await env.DB.batch(statements);
      const pruned = batchResults[run.results.length]?.meta.changes ?? 0;

      return Response.json({ configured: true, id: runId, pruned }, { status: 201 });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/no such table/i.test(message)) return Response.json({ configured: false });
      return Response.json({ configured: true, error: message }, { status: 502 });
    }
  }

  if (request.method !== "GET") return Response.json({ error: "Use GET, POST or DELETE" }, { status: 405 });

  const idParam = url.searchParams.get("id");
  try {
    if (idParam != null) {
      const id = parseRunId(idParam);
      if (id == null) return Response.json({ configured: true, error: "id must be a positive integer" }, { status: 400 });
      const run = await env.DB.prepare(
        `SELECT id, ts, label, route, gateway_id AS gatewayId, guarded, model,
                corpus_name AS corpusName, corpus_size AS corpusSize,
                corpus_fingerprint AS corpusFingerprint, delay_ms AS delayMs,
                total, scored, reached, stopped, denied, guardrails, pending, error,
                reached_pct AS reachedPct
         FROM redteam_runs WHERE id = ?`,
      )
        .bind(id)
        .first<RedTeamRunRow>();
      if (!run) return Response.json({ configured: true, run: null, results: [] }, { status: 404 });
      const { results } = await env.DB.prepare(
        `SELECT attack_key AS attackKey, attack_id AS attackId, category, severity, state,
                ray, ts, prompt_preview AS promptPreview
         FROM redteam_results WHERE run_id = ? ORDER BY id ASC`,
      )
        .bind(id)
        .all<RedTeamResultRow>();
      return Response.json({ configured: true, run, results: results ?? [] });
    }

    // List: metadata only. A run can carry up to REDTEAM_RUN_MAX_ATTACKS (500)
    // result rows, so the list view — read far more often than any one run's
    // detail — must never pull results just to render a table of totals.
    const { results } = await env.DB.prepare(
      `SELECT id, ts, label, route, gateway_id AS gatewayId, guarded, model,
              corpus_name AS corpusName, corpus_size AS corpusSize,
              corpus_fingerprint AS corpusFingerprint, delay_ms AS delayMs,
              total, scored, reached, stopped, denied, guardrails, pending, error,
              reached_pct AS reachedPct
       FROM redteam_runs ORDER BY ts DESC LIMIT ?`,
    )
      .bind(REDTEAM_RUNS_LIST_LIMIT)
      .all<RedTeamRunRow>();
    return Response.json({ configured: true, runs: results ?? [] });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/no such table/i.test(message)) return Response.json({ configured: false });
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}
