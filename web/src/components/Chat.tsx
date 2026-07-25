import { useEffect, useMemo, useRef } from "react";
import { Eraser, SendHorizontal, ShieldBan, ShieldX } from "lucide-react";
import { fmtCost } from "../lib/format";
import type { GatewayOption, Model } from "../lib/types";
import type { Msg, Route } from "../hooks/useChat";
import { ExportButton } from "./ExportButton";
import { Verdict } from "./Verdict";

function CacheBadge({ cached }: { cached?: boolean | null }) {
  if (cached === true)
    return <span className="rounded-full border border-cf-green bg-cf-green/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-green">CACHE HIT</span>;
  if (cached === false)
    return <span className="rounded-full border border-cf-amber bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber">CACHE MISS</span>;
  return <span className="rounded-full border border-line px-2 py-0.5 text-[10.5px] font-bold text-muted">cache: ?</span>;
}

function GuardrailsCard({ m }: { m: Extract<Msg, { kind: "guardrails" }> }) {
  return (
    <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border border-cf-purple/60 bg-cf-purple/10 p-4 text-sm shadow-sm">
      <div className="mb-1.5 flex items-center gap-2 font-bold text-cf-purple">
        <ShieldBan size={16} /> Blocked by AI Gateway Guardrails
      </div>
      <div className="leading-relaxed text-text">
        {m.direction === "response"
          ? "The model's response was blocked before reaching you (error 2017)."
          : "The prompt was blocked before reaching the model (error 2016)."}{" "}
        This moderation runs at the <b>gateway layer</b> — a separate control from the edge WAF{" "}
        <code className="font-mono">cf.llm.*</code> rules (whose verdict still appears below, since both routes hit the
        same scanned endpoint).
      </div>
      {m.detail && <div className="mt-2 font-mono text-[11px] break-words text-muted">{m.detail}</div>}
    </div>
  );
}

const DETECTION_LABELS: Record<string, string> = {
  pii: "PII detected in prompt",
  injection: "Prompt injection attempt",
  unsafe_topic: "Unsafe topic detected",
  waf: "Blocked by Cloudflare WAF",
};

function TypingDots() {
  return (
    <div className="flex items-center gap-1 self-start px-3 py-2 text-muted">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 animate-bounce rounded-full bg-muted"
          style={{ animationDelay: `${i * 0.15}s` }}
        />
      ))}
    </div>
  );
}

function Stamp({ side, ts }: { side: "user" | "assistant"; ts: string }) {
  return (
    <div className={`text-[10.5px] text-subtle ${side === "user" ? "self-end pr-1.5" : "self-start pl-2"}`}>{ts}</div>
  );
}

function BlockedCard({ m }: { m: Extract<Msg, { kind: "blocked" }> }) {
  const isJson = m.contentType.includes("json");
  let body = m.raw;
  if (isJson) {
    try {
      body = JSON.stringify(JSON.parse(m.raw), null, 2);
    } catch {
      /* leave raw */
    }
  }
  const label = (m.detection && DETECTION_LABELS[m.detection]) || "Request blocked";
  return (
    <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border border-cf-red/60 bg-cf-red/10 p-4 text-sm shadow-sm">
      <div className="mb-1.5 flex items-center gap-2 font-bold text-cf-red">
        <ShieldX size={16} /> Blocked at the Cloudflare edge
      </div>
      <div className="leading-relaxed text-text">
        {label} — {m.reason || "Blocked by Cloudflare AI Security for Apps"}
      </div>
      <div className="mt-2 text-xs text-muted">
        The prompt never reached the LLM.{m.ray ? <> ray <span className="font-mono">{m.ray}</span>.</> : null} See the
        edge verdict below.
      </div>
      {m.raw && (
        <details className="mt-2.5">
          <summary className="cursor-pointer list-none text-[11.5px] text-muted hover:text-text">
            ▸ View raw response ({isJson ? "JSON" : "HTML"})
          </summary>
          {!isJson && (
            <div className="mt-1.5 text-[11px] text-muted">
              Cloudflare's default block page, not a custom JSON body — set the WAF rule response to Custom JSON for a
              structured card.
            </div>
          )}
          <pre className="mt-1.5 max-h-64 overflow-auto rounded-lg border border-line bg-bg p-2.5 font-mono text-[11px] whitespace-pre-wrap break-words text-muted">
            {body}
          </pre>
        </details>
      )}
    </div>
  );
}

export function Chat({
  models,
  selectedModel,
  onModelChange,
  stream,
  onStreamChange,
  multiTurn,
  onMultiTurnChange,
  route,
  onRouteChange,
  gateways,
  gatewayId,
  onGatewayIdChange,
  skipCache,
  onSkipCacheChange,
  messages,
  busy,
  turnCount,
  onSend,
  onClear,
  input,
  setInput,
  systemPrompt,
}: {
  models: Model[];
  selectedModel: string;
  onModelChange: (id: string) => void;
  stream: boolean;
  onStreamChange: (v: boolean) => void;
  multiTurn: boolean;
  onMultiTurnChange: (v: boolean) => void;
  route: Route;
  onRouteChange: (r: Route) => void;
  gateways: GatewayOption[];
  gatewayId: string;
  onGatewayIdChange: (id: string) => void;
  skipCache: boolean;
  onSkipCacheChange: (v: boolean) => void;
  messages: Msg[];
  busy: boolean;
  turnCount: number;
  onSend: (text: string) => void;
  onClear: () => void;
  input: string;
  setInput: (v: string) => void;
  systemPrompt: string;
}) {
  const gateway = route === "gateway";
  const endRef = useRef<HTMLDivElement>(null);
  const modelLabels = useMemo(() => Object.fromEntries(models.map((m) => [m.id, m.label])), [models]);

  // Keep the view pinned to the bottom, including while tokens stream in.
  const streamingChars = messages.reduce((n, m) => n + (m.kind === "assistant" && m.streaming ? m.text.length : 0), 0);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length, busy, streamingChars]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const prompt = input.trim();
    if (!prompt || busy) return;
    setInput("");
    onSend(prompt);
  }

  // The user prompt that produced the message at `idx` — shown in the flow trace.
  const promptBefore = (idx: number): string | undefined => {
    for (let i = idx - 1; i >= 0; i--) {
      const m = messages[i];
      if (m.kind === "user") return m.text;
    }
    return undefined;
  };

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-3.5 p-4">
      <div className="flex flex-1 flex-col gap-2 overflow-y-auto p-1.5">
        {messages.length === 0 && (
          <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl rounded-bl-md border border-line bg-surface px-4 py-3 text-sm shadow-sm">
            Hi! I'm an LLM behind Cloudflare. Pick an attack from the library on the right — Cloudflare inspects each
            prompt at the edge and blocks it <i>before it ever reaches me</i>. Start with the green baseline to see a
            normal answer. I remember the conversation, so multi-turn attacks are fair game too. Use the{" "}
            <b>Route</b> control to send through Workers AI directly or via <b>AI Gateway</b> (caching + Guardrails) —
            either way the edge WAF scans the prompt, so the verdict shows for both.
          </div>
        )}

        {messages.map((m, idx) => {
          if (m.kind === "user")
            return (
              <div key={m.id} className="contents">
                <div className="animate-rise max-w-[min(80%,720px)] self-end rounded-2xl rounded-br-md bg-gradient-to-br from-accent to-accent-hover px-4 py-2.5 text-sm font-medium whitespace-pre-wrap text-[#1a1206] shadow-sm">
                  {m.text}
                </div>
                <Stamp side="user" ts={m.ts} />
              </div>
            );
          if (m.kind === "assistant")
            return (
              <div key={m.id} className="contents">
                <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl rounded-bl-md border border-line bg-surface px-4 py-2.5 text-sm whitespace-pre-wrap shadow-sm">
                  {m.text}
                  {m.streaming && <span className="ml-0.5 inline-block h-3.5 w-1.5 animate-pulse rounded-sm bg-accent align-middle" />}
                </div>
                {!m.streaming && (
                  <>
                    <Stamp side="assistant" ts={m.ts} />
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 self-start pl-2 text-[11px] text-muted">
                      {m.meta.gateway && (
                        <>
                          <CacheBadge cached={m.meta.gateway.cached} />
                          {m.meta.gateway.guarded && (
                            <span className="rounded-full border border-cf-purple/60 bg-cf-purple/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-purple">
                              GUARDRAILS
                            </span>
                          )}
                        </>
                      )}
                      {m.meta.model && <span>via {modelLabels[m.meta.model] || m.meta.model}</span>}
                      {m.meta.gateway?.latencyMs != null && (
                        <span>
                          · latency <b className="font-mono text-text">{m.meta.gateway.latencyMs} ms</b>
                        </span>
                      )}
                      {m.meta.ray && (
                        <span>
                          · ray <span className="font-mono text-text">{m.meta.ray}</span>
                        </span>
                      )}
                      {m.meta.usage && (
                        <span>
                          · {m.meta.usage.estimated ? "~" : ""}
                          {m.meta.usage.total_tokens} tok ({m.meta.usage.prompt_tokens} in /{" "}
                          {m.meta.usage.completion_tokens} out)
                        </span>
                      )}
                      {fmtCost(m.meta.cost) && <span>· {m.meta.gateway?.cached ? "$0 (cached)" : fmtCost(m.meta.cost)}</span>}
                      {m.meta.gateway?.logId && (
                        <span>
                          · log <span className="font-mono">{m.meta.gateway.logId}</span>
                        </span>
                      )}
                    </div>
                    {m.ray && <Verdict ray={m.ray} prompt={promptBefore(idx)} gateway={m.meta.gateway} />}
                  </>
                )}
              </div>
            );
          if (m.kind === "blocked")
            return (
              <div key={m.id} className="contents">
                <BlockedCard m={m} />
                <Stamp side="assistant" ts={m.ts} />
                {m.ray && <Verdict ray={m.ray} prompt={promptBefore(idx)} />}
              </div>
            );
          if (m.kind === "guardrails")
            return (
              <div key={m.id} className="contents">
                <GuardrailsCard m={m} />
                <Stamp side="assistant" ts={m.ts} />
                {m.ray && (
                  <Verdict
                    ray={m.ray}
                    prompt={promptBefore(idx)}
                    gateway={m.gateway}
                    guardrails={{ direction: m.direction, detail: m.detail }}
                  />
                )}
              </div>
            );
          return (
            <div
              key={m.id}
              className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border border-cf-red/60 bg-cf-red/10 px-4 py-2.5 text-sm text-cf-red"
            >
              {m.text}
            </div>
          );
        })}
        {busy && !messages.some((m) => m.kind === "assistant" && m.streaming) && <TypingDots />}
        <div ref={endRef} />
      </div>

      <div className="flex flex-wrap items-center gap-3.5 text-[13px] text-muted">
        <label htmlFor="model" className="flex items-center gap-1.5">
          Model
          <select
            id="model"
            value={selectedModel}
            onChange={(e) => onModelChange(e.target.value)}
            className="max-w-80 rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] text-text outline-none focus:border-accent"
          >
            {models.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        {/* Route toggle: Workers AI (direct) ↔ AI Gateway */}
        <div className="inline-flex overflow-hidden rounded-full border border-line">
          {(["direct", "gateway"] as Route[]).map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => onRouteChange(r)}
              className={`px-3 py-1.5 text-[12.5px] transition ${
                route === r ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {r === "direct" ? "Workers AI" : "AI Gateway"}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={stream}
            onChange={(e) => onStreamChange(e.target.checked)}
            className="h-4 w-4 accent-accent"
          />
          stream replies
        </label>
        <label
          className="flex items-center gap-1.5"
          title="When off, each prompt is sent standalone — no history[], so the model can't recall earlier turns (multi-turn attacks like Crescendo won't build across messages)"
        >
          <input
            type="checkbox"
            checked={multiTurn}
            onChange={(e) => onMultiTurnChange(e.target.checked)}
            className="h-4 w-4 accent-accent"
          />
          multi-turn
        </label>
        {gateway && (
          <>
            {gateways.length > 0 && (
              <label htmlFor="gatewayId" className="flex items-center gap-1.5">
                Gateway
                <select
                  id="gatewayId"
                  value={gatewayId}
                  onChange={(e) => onGatewayIdChange(e.target.value)}
                  className="rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] text-text outline-none focus:border-accent"
                >
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="flex items-center gap-1.5" title="Bypass the gateway cache for this request">
              <input
                type="checkbox"
                checked={skipCache}
                onChange={(e) => onSkipCacheChange(e.target.checked)}
                className="h-4 w-4 accent-accent"
              />
              skip cache
            </label>
          </>
        )}
        {turnCount > 0 && (
          <span className="text-subtle">
            {turnCount} turn{turnCount === 1 ? "" : "s"} {multiTurn ? "of context" : "in transcript (multi-turn off — not sent)"}
          </span>
        )}
        {messages.length > 0 && (
          <span className="ml-auto flex items-center gap-2">
            <ExportButton messages={messages} systemPrompt={systemPrompt} />
            <button
              type="button"
              onClick={onClear}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-[12px] text-muted transition hover:border-accent hover:text-text disabled:opacity-50"
            >
              <Eraser size={13} /> Clear conversation
            </button>
          </span>
        )}
      </div>

      {gateway && (
        <div className="-mt-1.5 text-[11.5px] text-subtle">
          Routed through AI Gateway. Cache HIT needs an identical request body, so streaming and prior turns weaken it —
          for a clean HIT, clear the conversation and send the same prompt twice. The edge WAF still scans this route, so
          the verdict shows below each reply.
        </div>
      )}

      <form onSubmit={submit} className="flex gap-2.5">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          autoComplete="off"
          placeholder="Type a prompt, or load one from the Attack Library →"
          className="flex-1 rounded-xl border border-line bg-surface px-4 py-3 text-sm text-text shadow-sm outline-none transition placeholder:text-subtle focus:border-accent focus:ring-2 focus:ring-accent/25"
        />
        <button
          type="submit"
          disabled={busy}
          className="flex items-center gap-2 rounded-xl bg-gradient-to-br from-accent to-accent-hover px-5 text-sm font-bold text-[#1a1206] shadow-sm transition hover:brightness-105 active:scale-97 disabled:opacity-50"
        >
          <SendHorizontal size={16} /> Send
        </button>
      </form>
    </div>
  );
}
