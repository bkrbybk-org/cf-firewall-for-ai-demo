// Booth mode's architecture strip, pinned above the chat: the path every prompt takes, swept while a turn is in
// flight, then replayed up to the layer where the latest turn ended. The states, the caption and what may be claimed
// while waiting all come from lib/boothFlow.ts; this file only draws them.
import type { CSSProperties, ReactNode } from "react";
import { Bot, Cloud, MessageSquareText, Network, ScanSearch, ShieldCheck, X } from "lucide-react";
import type { Msg, Route } from "../hooks/useChat";
import { boothFlow, type FlowNode, type FlowNodeState } from "../lib/boothFlow";

const ICON: Record<FlowNode["key"], ReactNode> = {
  source: <MessageSquareText size={18} />,
  edge: <Cloud size={18} />,
  external: <ScanSearch size={18} />,
  gatewayGuardrails: <Network size={18} />,
  model: <Bot size={18} />,
  replyCheck: <ShieldCheck size={18} />,
};

// The same colour language as the per-turn strip (BoothTurn): green = stopped (the demo's headline), amber dashed =
// flagged, struck through = never reached.
const NODE: Record<FlowNodeState, string> = {
  idle: "border-line bg-surface text-text",
  through: "border-line bg-surface text-text",
  pending: "border-accent/50 bg-surface text-text",
  stopped: "border-cf-green bg-cf-green/15 text-cf-green-ink ring-4 ring-cf-green/20",
  flagged: "border-dashed border-cf-amber bg-cf-amber/10 text-cf-amber-ink",
  unavailable: "border-dashed border-line bg-surface text-muted",
  reached: "border-accent bg-accent/10 text-text ring-4 ring-accent/15",
  passed: "border-line bg-surface text-text",
  notReached: "border-line bg-surface-2 text-subtle opacity-60",
  off: "border-dashed border-line bg-surface-2 text-subtle opacity-60",
};

const WORD: Partial<Record<FlowNodeState, string>> = {
  through: "let through",
  pending: "checking…",
  stopped: "stopped it",
  flagged: "flagged",
  unavailable: "no verdict",
  reached: "answered",
  passed: "passed",
  notReached: "not reached",
  off: "off",
};

export function BoothFlow({ messages, busy, route }: { messages: Msg[]; busy: boolean; route: Route }) {
  const v = boothFlow(messages, busy, route);
  const n = v.nodes.length;
  // Node centres sit at (i + ½) / n of the width; the rail runs from the first centre to the last.
  const at = (i: number) => `${((i + 0.5) / n) * 100}%`;
  const edgePad = `${(0.5 / n) * 100}%`;
  return (
    <section
      aria-label="How a prompt travels"
      className="mx-auto w-full max-w-3xl shrink-0 rounded-2xl border border-line bg-surface-2/60 px-3 pt-3 pb-2.5"
    >
      {/* `relative` contains the absolutely placed rail, sweep and packet (and the sr-only words) — house rule. */}
      <div className="relative">
        <div aria-hidden className="absolute top-[19px] h-0.5 rounded-full bg-line" style={{ left: edgePad, right: edgePad }} />
        {v.phase === "inFlight" && (
          <div aria-hidden className="booth-sweep absolute top-[18px] h-1 rounded-full" style={{ left: edgePad, right: edgePad }} />
        )}
        {v.to != null && v.to > 0 && (
          <div
            key={`rail-${v.turnId}`}
            aria-hidden
            className={`booth-grow absolute top-[18px] h-1 origin-left rounded-full ${v.stopped ? "bg-cf-green" : "bg-accent"}`}
            style={{ left: edgePad, width: `${(v.to / n) * 100}%` }}
          />
        )}
        {v.phase === "inFlight" && (
          <span
            aria-hidden
            className="booth-packet absolute top-[13px] h-3.5 w-3.5 -translate-x-1/2 rounded-full bg-accent ring-4 ring-accent/25"
            style={{ "--from": at(0), "--to": at(n - 1) } as CSSProperties}
          />
        )}
        {v.to != null && v.phase !== "inFlight" && (
          <span
            key={`packet-${v.turnId}`}
            aria-hidden
            className={`booth-land absolute top-[11px] grid h-[18px] w-[18px] -translate-x-1/2 place-items-center rounded-full text-white ${
              v.stopped ? "bg-cf-green" : "bg-accent"
            } ${v.phase === "answering" ? "animate-pulse" : ""}`}
            style={{ "--from": at(0), "--to": at(v.to), left: at(v.to) } as CSSProperties}
          >
            {v.stopped && <X size={12} strokeWidth={3} />}
          </span>
        )}
        <ol className="relative grid" style={{ gridTemplateColumns: `repeat(${n}, minmax(0, 1fr))` }}>
          {v.nodes.map((node, i) => (
            <li key={node.key} title={node.title || undefined} className="flex min-w-0 flex-col items-center gap-1 text-center">
              <span
                className={`relative z-[1] grid h-10 w-10 place-items-center rounded-xl border-2 transition-colors duration-300 ${NODE[node.state]} ${
                  v.phase === "inFlight" && i > 0 ? "booth-scan" : ""
                } ${v.phase === "done" ? "booth-reveal" : ""}`}
                style={v.phase === "done" ? ({ animationDelay: `${i * 110}ms` } as CSSProperties) : undefined}
              >
                {ICON[node.key]}
              </span>
              <span className={`text-[12.5px] leading-tight font-semibold ${node.state === "notReached" || node.state === "off" ? "text-subtle line-through decoration-1" : "text-text"}`}>
                {node.label}
              </span>
              <span className="hidden text-[11px] leading-tight text-muted sm:block">
                {WORD[node.state] && v.phase !== "idle" ? WORD[node.state] : node.sub}
              </span>
              <span className="sr-only">{WORD[node.state] ? ` — ${WORD[node.state]}` : ""}</span>
            </li>
          ))}
        </ol>
      </div>
      <p aria-live="polite" className="mt-1.5 text-center text-[13px] font-semibold text-muted">
        {v.caption}
      </p>
    </section>
  );
}
