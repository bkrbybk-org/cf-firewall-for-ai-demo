// Route handlers, one per endpoint. Each returns a Response.

import {
  DEFAULT_AI_GATEWAY_ID,
  DEFAULT_SYSTEM_PROMPT,
  FREE_DAILY_NEURONS,
  MAX_HISTORY_CHARS,
  MAX_HISTORY_TURNS,
  MAX_REPLY_TOKENS,
  MAX_SYSTEM_PROMPT_LEN,
  OVERAGE_USD_PER_1K_NEURONS,
} from "./config";
import { ALLOWED_IDS, DEFAULT_MODEL, MODEL_BY_ID, MODEL_REGISTRY } from "./models";
import { listAiGateways, queryAnalytics, queryGatewayLogs, queryNeuronUsage, queryVerdict } from "./cloudflare";
import { redact } from "./redact";
import type { ChatRequestBody, ChatTurn, Env, PromptAnalytics, PromptLogRow } from "./types";

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
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ZONE_ID) {
    return Response.json({ configured: false, ray });
  }
  try {
    const verdict = await queryVerdict(env.CF_ZONE_ID, env.CF_ANALYTICS_TOKEN, ray);
    return Response.json({ configured: true, ray, ...verdict });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ configured: true, ray, found: false, error: message }, { status: 502 });
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
// TransformStream flush, once the upstream stream is fully consumed).
function appendGatewayEvent(
  source: ReadableStream,
  env: Env,
  gatewayId: string,
  guarded: boolean,
  started: number,
): ReadableStream {
  const enc = new TextEncoder();
  return source.pipeThrough(
    new TransformStream({
      async flush(controller) {
        const logId = env.AI.aiGatewayLogId ?? null;
        let cached: boolean | null = null;
        if (logId) {
          try {
            const log = (await env.AI.gateway(gatewayId).getLog(logId)) as { cached?: boolean };
            if (typeof log?.cached === "boolean") cached = log.cached;
          } catch {
            /* log not yet available */
          }
        }
        const meta = { gatewayId, cached, latencyMs: Date.now() - started, logId, guarded };
        controller.enqueue(enc.encode(`data: ${JSON.stringify({ gateway: meta })}\n\n`));
      },
    }),
  );
}

// POST /api/chat — run the selected model with the (optional) system prompt
// and prior conversation turns. With gateway:true the inference is routed
// through AI Gateway (env.AI.run(..., { gateway })) so cache status / latency /
// log id / Guardrails come back too — but the request still hits this same
// cf-llm-labeled path, so the edge WAF scan (and the verdict) applies either
// way. With stream:true the reply is passed through as SSE and the client
// assembles the reply + metadata itself.
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
    if (body.gateway === true) gateway = true;
    if (typeof body.skipCache === "boolean") skipCache = body.skipCache;
    if (typeof body.gatewayId === "string") requestedGatewayId = body.gatewayId;
  } catch {
    return Response.json(
      {
        error:
          'Body must be JSON: {"prompt": "...", "model"?, "systemPrompt"?, "history"?, "stream"?, "gateway"?, "gatewayId"?, "skipCache"?}',
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
  let runOptions: { gateway: { id: string; skipCache: boolean } } | undefined;
  if (gateway) {
    const valid = typeof requestedGatewayId === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(requestedGatewayId);
    gatewayId = valid ? requestedGatewayId! : env.CF_AI_GATEWAY_ID || DEFAULT_AI_GATEWAY_ID;
    guarded = !!env.CF_AI_GATEWAY_GUARDED_ID && gatewayId === env.CF_AI_GATEWAY_GUARDED_ID;
    runOptions = { gateway: { id: gatewayId, skipCache } };
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
  const log = (
    outcome: PromptLogRow["outcome"],
    extra: { reply: string | null; promptTokens?: number | null; completionTokens?: number | null },
  ) => ctx?.waitUntil(logPrompt(env, { ...logBase, outcome, prompt, ...extra }));

  if (stream) {
    try {
      const sse = (await env.AI.run(
        model,
        { messages, max_tokens: MAX_REPLY_TOKENS, stream: true } as never,
        runOptions,
      )) as unknown as ReadableStream;
      // Streamed reply text isn't captured server-side; log the prompt only.
      log("reply", { reply: null });
      const body = gateway ? appendGatewayEvent(sse, env, gatewayId, guarded, started) : sse;
      return new Response(body, {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    } catch (err) {
      const gr = gateway ? guardrailsResponse(err, model, gatewayId, guarded) : null;
      log(gr ? "guardrails" : "error", { reply: null });
      if (gr) return gr;
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ error: `Workers AI error (${model}): ${message}`, model }, { status: 502 });
    }
  }

  try {
    const result = await env.AI.run(model, { messages, max_tokens: MAX_REPLY_TOKENS }, runOptions);
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

    // Gateway metadata (cache status, latency, log id) when routed via gateway.
    let gatewayMeta:
      | { gatewayId: string; cached: boolean | null; latencyMs: number; logId: string | null; guarded: boolean }
      | undefined;
    if (gateway) {
      const latencyMs = Date.now() - started;
      const logId = env.AI.aiGatewayLogId ?? null;
      let cached: boolean | null = null;
      if (logId) {
        try {
          const log = (await env.AI.gateway(gatewayId).getLog(logId)) as { cached?: boolean };
          if (typeof log?.cached === "boolean") cached = log.cached;
        } catch {
          /* log not yet available — leave cached = null */
        }
      }
      gatewayMeta = { gatewayId, cached, latencyMs, logId, guarded };
    }

    // A cache hit skips inference (free); otherwise estimate from pricing.
    const price = MODEL_BY_ID.get(model);
    const cost =
      gatewayMeta?.cached === true
        ? 0
        : price
          ? (promptTokens / 1e6) * price.priceIn + (completionTokens / 1e6) * price.priceOut
          : null;

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
      gateway: gatewayMeta, // present only when routed via AI Gateway
    });
  } catch (err) {
    const gr = gateway ? guardrailsResponse(err, model, gatewayId, guarded) : null;
    log(gr ? "guardrails" : "error", { reply: null });
    if (gr) return gr;
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

// GET  /api/prompt-log?limit=&route=&outcome= — recent PII-redacted prompts.
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

  const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get("limit") || "100", 10) || 100));
  const route = url.searchParams.get("route"); // 'direct' | 'gateway' | null
  const outcome = url.searchParams.get("outcome"); // 'reply' | 'guardrails' | 'error' | null
  const where: string[] = [];
  const binds: unknown[] = [];
  if (route === "direct" || route === "gateway") {
    where.push("route = ?");
    binds.push(route);
  }
  if (outcome === "reply" || outcome === "guardrails" || outcome === "error") {
    where.push("outcome = ?");
    binds.push(outcome);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  try {
    const { results } = await env.DB.prepare(
      `SELECT ray, ts, route, model, gateway_id AS gatewayId, guarded, outcome,
              prompt, reply, redactions, prompt_tokens AS promptTokens,
              completion_tokens AS completionTokens
       FROM prompt_log ${clause} ORDER BY ts DESC LIMIT ?`,
    )
      .bind(...binds, limit)
      .all<PromptLogRow>();
    const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM prompt_log").first<{ n: number }>();
    return Response.json({ configured: true, rows: results ?? [], total: total?.n ?? 0 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // A missing table reads as "not configured" so the UI shows the setup hint.
    if (/no such table/i.test(message)) return Response.json({ configured: false });
    return Response.json({ configured: true, error: message }, { status: 502 });
  }
}

// GET /api/prompt-analytics?hours= — aggregates over the whole prompt log.
// Every rollup is a SQL GROUP BY executed inside D1 (not a Worker-side pass
// over capped rows), so the numbers stay correct however large the table gets.
export async function handlePromptAnalytics(url: URL, env: Env): Promise<Response> {
  if (!env.DB) return Response.json({ configured: false });

  // hours=0 (or absent) means "all time" — the log is deliberately small and
  // presenters usually want the whole demo session, not a rolling window.
  const rawHours = parseInt(url.searchParams.get("hours") || "0", 10) || 0;
  const hours = Math.min(168, Math.max(0, rawHours));
  const since = hours > 0 ? Date.now() - hours * 3_600_000 : 0;
  const whereTs = "WHERE ts >= ?";

  try {
    const db = env.DB;
    const q = <T>(sql: string) => db.prepare(sql).bind(since).all<T>();

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
        .bind(since)
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

    // Time series. With hours=0 the span is derived from the data itself, so a
    // long-idle demo log still buckets sensibly.
    const spanMs = Math.max(1, (totals?.lastTs ?? 0) - (totals?.firstTs ?? 0));
    const spanHours = hours > 0 ? hours : Math.max(1, Math.ceil(spanMs / 3_600_000));
    const bucket: "hour" | "day" = spanHours <= 48 ? "hour" : "day";
    const stepMs = bucket === "hour" ? 3_600_000 : 86_400_000;
    const series = new Map<string, { t: string; reply: number; guardrails: number; error: number }>();
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
