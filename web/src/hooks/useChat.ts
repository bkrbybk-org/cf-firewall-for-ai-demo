// Chat session state + the single send pipeline used by both the manual
// composer and the demo autopilot. Owns: message list, multi-turn history,
// streaming assembly, blocked/error handling.
//
// The message list and in-flight flag live in module-level stores (see
// lib/sessionStore.ts) rather than component state, so the conversation
// survives navigating to another tab and back, and is cleared by a refresh.
import { useCallback, useRef } from "react";
import { postChat } from "../lib/api";
import { fmtTime } from "../lib/format";
import { createStore, nextMsgId, useStore } from "../lib/sessionStore";
import type { ChatTurn, GatewayMeta, Model, Usage } from "../lib/types";

export type Route = "direct" | "gateway";

export type Msg =
  | { id: number; kind: "user"; text: string; ts: string }
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

// "plan=paid, orgId=acme" → { plan: "paid", orgId: "acme" }. Feeds the
// Conditional nodes of a dynamic route; malformed pairs are dropped.
function parseMetadata(raw: string): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const pair of raw.split(",")) {
    const i = pair.indexOf("=");
    if (i < 1) continue;
    const k = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (k && v) out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
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
    const { models, model, systemPrompt, stream, multiTurn, route, gatewayId, skipCache, dynamicRoute, routeMetadata } =
      cfgRef.current;
    const gateway = route === "gateway";
    chatBusy.set(true);
    const history = multiTurn ? buildHistory(chatMessages.get()) : [];
    push({ id: nextId(), kind: "user", text: prompt, ts: fmtTime() });

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
          routeMetadata: gateway && dynamicRoute ? parseMetadata(routeMetadata) : undefined,
        },
        (tok) => {
          if (!streamStarted) {
            streamStarted = true;
            push({ id: asstId, kind: "assistant", text: tok, ts: fmtTime(), streaming: true, meta: { model } });
          } else {
            patch(asstId, (m) => (m.kind === "assistant" ? { ...m, text: m.text + tok } : m));
          }
        },
      );

      if (result.mode === "stream") {
        const ray = result.ray?.split("-")[0] || undefined;
        const usage = result.usage ?? estimateUsage(systemPrompt, history, prompt, result.text);
        const gwMeta = result.gateway ?? undefined;
        // A cache HIT skips inference → free; otherwise estimate from pricing.
        const cost = gwMeta?.cached === true ? 0 : estimateCost(models, model, usage);
        if (!result.text) {
          push({ id: nextId(), kind: "error", text: "Empty streamed reply from the model.", ts: fmtTime() });
          outcome = { kind: "error", ray };
        } else {
          if (!streamStarted) {
            push({ id: asstId, kind: "assistant", text: result.text, ts: fmtTime(), meta: { model } });
          }
          patch(asstId, (m) =>
            m.kind === "assistant"
              ? { ...m, streaming: false, ray, meta: { model, ray, usage, cost, gateway: gwMeta } }
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
            detection: data?.blocked ? data.detection : "waf",
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
