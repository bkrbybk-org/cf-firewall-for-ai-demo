// Chat session state + the single send pipeline used by both the manual
// composer and the demo autopilot. Owns: message list, multi-turn history,
// streaming assembly, blocked/error handling.
//
// The message list and in-flight flag live in module-level stores (see
// lib/sessionStore.ts) rather than component state, so the conversation
// survives navigating to another tab and back, and is cleared by a refresh.
import { useCallback, useRef } from "react";
import { postChat, type GatewayBackoff } from "../lib/api";
import { fmtTime } from "../lib/format";
import { parseMetadata } from "../lib/metadata";
import { createStore, nextMsgId, useStore } from "../lib/sessionStore";
import type { ChatTurn, GatewayMeta, Model, Usage } from "../lib/types";

export type Route = "direct" | "gateway";

// Every AI Gateway per-request REST setting, minus the request itself. All of
// these are gateway-only — a direct Workers AI call never goes through a
// gateway, so none of them have any effect on that route.
export interface GatewaySettings {
  cacheTtl?: number;
  cacheKey?: string;
  collectLog?: boolean;
  requestTimeoutMs?: number;
  maxAttempts?: number;
  retryDelayMs?: number;
  backoff?: GatewayBackoff;
}

// Snapshot of the send-time controls — attached to the user message so the
// verdict trace can show exactly what was requested, even after the controls
// have since changed for the next turn.
export interface RequestConfig extends GatewaySettings {
  stream: boolean;
  multiTurn: boolean;
  route: Route;
  gatewayId?: string;
  skipCache?: boolean;
  dynamicRoute?: string;
  routeMetadata?: Record<string, string>;
  excludeFromLog?: boolean;
}

export type Msg =
  | { id: number; kind: "user"; text: string; ts: string; cfg?: RequestConfig }
  | {
      id: number;
      kind: "assistant";
      text: string;
      ts: string;
      streaming?: boolean;
      meta: {
        model?: string;
        ray?: string | null;
        usage?: Usage;
        cost?: number | null;
        gateway?: GatewayMeta; // set when this reply was routed via AI Gateway
        dynamicRoute?: string; // set when a dynamic route chose the model
      };
      ray?: string;
    }
  | {
      id: number;
      kind: "blocked";
      ts: string;
      ray?: string;
      raw: string;
      contentType: string;
      detection?: string;
      reason?: string;
    }
  | {
      id: number;
      kind: "guardrails"; // AI Gateway Guardrails block (error 2016/2017)
      ts: string;
      ray?: string;
      direction?: "prompt" | "response";
      detail?: string;
      guarded?: boolean;
      gateway?: GatewayMeta; // which gateway blocked (for the flow trace)
    }
  | { id: number; kind: "error"; text: string; ts: string }

export interface TurnResult {
  kind: "reply" | "blocked" | "error";
  ray?: string;
}

// Multi-turn context = completed user→assistant pairs only. A blocked user
// prompt has no assistant reply and is deliberately dropped — resending an
// attack prompt inside history would get every later turn blocked too.
function buildHistory(msgs: Msg[]): ChatTurn[] {
  const out: ChatTurn[] = [];
  for (let i = 0; i < msgs.length - 1; i++) {
    const q = msgs[i];
    const a = msgs[i + 1];
    if (q.kind === "user" && a.kind === "assistant") {
      out.push({ role: "user", content: q.text });
      out.push({ role: "assistant", content: a.text });
    }
  }
  return out;
}

function estimateUsage(systemPrompt: string, history: ChatTurn[], prompt: string, reply: string): Usage {
  const historyChars = history.reduce((n, t) => n + t.content.length, 0);
  const prompt_tokens = Math.ceil((systemPrompt.length + historyChars + prompt.length) / 4);
  const completion_tokens = Math.ceil(reply.length / 4);
  return { prompt_tokens, completion_tokens, total_tokens: prompt_tokens + completion_tokens, estimated: true };
}

function estimateCost(models: Model[], modelId: string, usage: Usage): number | null {
  const m = models.find((x) => x.id === modelId);
  if (!m || m.priceIn == null || m.priceOut == null) return null;
  return (usage.prompt_tokens / 1e6) * m.priceIn + (usage.completion_tokens / 1e6) * m.priceOut;
}

// Session state, kept outside the component tree so it survives tab switches.
const chatMessages = createStore<Msg[]>([]);
const chatBusy = createStore(false);

// Module-scope helpers: always read/write the live store, so they stay correct
// across unmount/remount (navigating away mid-send and back).
const push = (m: Msg) => chatMessages.set((prev) => [...prev, m]);
const patch = (id: number, fn: (m: Msg) => Msg) =>
  chatMessages.set((prev) => prev.map((m) => (m.id === id ? fn(m) : m)));

export function useChat(cfg: {
  models: Model[];
  model: string;
  systemPrompt: string;
  stream: boolean;
  multiTurn: boolean; // when off, no history[] is sent — each turn is independent
  route: Route;
  gatewayId: string;
  skipCache: boolean;
  dynamicRoute: string;
  routeMetadata: string; // "k=v,k=v" as typed in the UI; parsed before sending
  gatewaySettings: GatewaySettings; // remaining per-request AI Gateway REST settings
  excludeFromLog: boolean; // skip writing this turn to the D1 prompt_log table
  onSent?: () => void;
}) {
  const messages = useStore(chatMessages);
  const busy = useStore(chatBusy);
  // sendPrompt stays identity-stable (autopilot holds it across steps) but
  // always reads the latest settings through this ref.
  const cfgRef = useRef(cfg);
  cfgRef.current = cfg;

  const nextId = () => nextMsgId();

  const clear = useCallback(() => chatMessages.set([]), []);

  const sendPrompt = useCallback(async (text: string): Promise<TurnResult> => {
    const prompt = text.trim();
    if (!prompt || chatBusy.get()) return { kind: "error" };
    const {
      models,
      model,
      systemPrompt,
      stream,
      multiTurn,
      route,
      gatewayId,
      skipCache,
      dynamicRoute,
      routeMetadata,
      gatewaySettings,
      excludeFromLog,
    } = cfgRef.current;
    const gateway = route === "gateway";
    chatBusy.set(true);
    const history = multiTurn ? buildHistory(chatMessages.get()) : [];
    const reqCfg: RequestConfig = {
      stream,
      multiTurn,
      route,
      gatewayId: gateway ? gatewayId || undefined : undefined,
      skipCache: gateway ? skipCache : undefined,
      dynamicRoute: gateway && dynamicRoute ? dynamicRoute : undefined,
      routeMetadata: gateway ? parseMetadata(routeMetadata) : undefined,
      ...(gateway ? gatewaySettings : {}),
      excludeFromLog: excludeFromLog || undefined,
    };
    push({ id: nextId(), kind: "user", text: prompt, ts: fmtTime(), cfg: reqCfg });

    let outcome: TurnResult = { kind: "error" };
    try {
      const asstId = nextId();
      let streamStarted = false;
      const result = await postChat(
        {
          prompt,
          model: model || undefined,
          systemPrompt: systemPrompt || undefined,
          history: history.length ? history : undefined,
          stream: stream || undefined,
          gateway: gateway || undefined,
          gatewayId: gateway ? gatewayId || undefined : undefined,
          skipCache: gateway ? skipCache : undefined,
          dynamicRoute: gateway && dynamicRoute ? dynamicRoute : undefined,
          routeMetadata: gateway ? parseMetadata(routeMetadata) : undefined,
          ...(gateway ? gatewaySettings : {}),
          excludeFromLog: excludeFromLog || undefined,
        },
        (tok) => {
          if (!streamStarted) {
            streamStarted = true;
            push({
              id: asstId,
              kind: "assistant",
              text: tok,
              ts: fmtTime(),
              streaming: true,
              meta: { model, dynamicRoute: gateway && dynamicRoute ? dynamicRoute : undefined },
            });
          } else {
            patch(asstId, (m) => (m.kind === "assistant" ? { ...m, text: m.text + tok } : m));
          }
        },
      );

      if (result.mode === "stream") {
        const ray = result.ray?.split("-")[0] || undefined;
        // A Dynamic Route's SSE chunks carry the real model in `model`; the
        // plain binding stream doesn't, so fall back to what was requested.
        const ranModel = result.model || model;
        const usage = result.usage ?? estimateUsage(systemPrompt, history, prompt, result.text);
        const gwMeta = result.gateway ?? undefined;
        // A cache HIT skips inference → free; otherwise estimate from pricing.
        const cost = gwMeta?.cached === true ? 0 : estimateCost(models, ranModel, usage);
        const routeMeta = gateway && dynamicRoute ? dynamicRoute : undefined;
        if (!result.text) {
          push({ id: nextId(), kind: "error", text: "Empty streamed reply from the model.", ts: fmtTime() });
          outcome = { kind: "error", ray };
        } else {
          if (!streamStarted) {
            push({ id: asstId, kind: "assistant", text: result.text, ts: fmtTime(), meta: { model: ranModel, dynamicRoute: routeMeta } });
          }
          patch(asstId, (m) =>
            m.kind === "assistant"
              ? { ...m, streaming: false, ray, meta: { model: ranModel, ray, usage, cost, gateway: gwMeta, dynamicRoute: routeMeta } }
              : m,
          );
          outcome = { kind: "reply", ray };
        }
      } else {
        const { status, contentType, raw, data } = result;
        const ray = data?.ray?.split("-")[0] || undefined;
        if (status === 403) {
          push({
            id: nextId(),
            kind: "blocked",
            ts: fmtTime(),
            ray,
            raw,
            contentType,
            // Only attribute the block when the response actually says so (a
            // WAF rule answering with our custom JSON). A bare 403 with an
            // HTML body proves nothing about WHO refused it — Cloudflare
            // Access returns exactly that — and blaming the WAF there made
            // the demo credit AI Security for rejections it never made.
            detection: data?.blocked ? data.detection : undefined,
            reason: data?.reason,
          });
          outcome = { kind: "blocked", ray };
        } else if (data?.guardrailsBlocked) {
          push({
            id: nextId(),
            kind: "guardrails",
            ts: fmtTime(),
            ray,
            direction: data.direction,
            detail: data.detail,
            guarded: data.gateway?.guarded ?? false,
            gateway: data.gateway ?? undefined,
          });
          outcome = { kind: "blocked", ray };
        } else if (status >= 200 && status < 300 && data?.reply) {
          const gwMeta = data.gateway ?? undefined;
          const cost = gwMeta?.cached === true ? 0 : data.cost;
          push({
            id: asstId,
            kind: "assistant",
            text: data.reply,
            ts: fmtTime(),
            meta: { model: data.model, ray, usage: data.usage, cost, gateway: gwMeta, dynamicRoute: data.dynamicRoute },
            ray,
          });
          outcome = { kind: "reply", ray };
        } else {
          push({ id: nextId(), kind: "error", text: data?.error || `HTTP ${status}`, ts: fmtTime() });
          outcome = { kind: "error", ray };
        }
      }
    } catch (err) {
      push({ id: nextId(), kind: "error", text: "Network error: " + err, ts: fmtTime() });
    } finally {
      chatBusy.set(false);
      cfgRef.current.onSent?.();
    }
    return outcome;
  }, []);

  const turnCount = buildHistory(messages).length / 2;

  return { messages, busy, sendPrompt, clear, turnCount };
}
