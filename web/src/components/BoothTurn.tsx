// Booth mode (Settings → Your preferences, or the header toggle): one large verdict banner per chat turn instead of
// the detailed cards, ray ids, tokens, cost and flow trace. Rendering only — the words and the strip states come from
// lib/boothView.ts, which takes them from the same sources the detailed view uses.
import type { ReactNode } from "react";
import { CheckCircle2, CircleSlash, Eye, ShieldBan, ShieldCheck, TriangleAlert } from "lucide-react";
import type { Route } from "../hooks/useChat";
import type { CellState } from "../lib/controlMatrix";
import { boothBanner, boothStrip, rayOf, type BoothIcon, type BoothTone, type TurnMsg } from "../lib/boothView";
import { useEdgeKnowledge } from "../lib/verdictStore";
import { ExternalGuardrailBadges } from "./ExternalGuardrailCard";

const TONE: Record<BoothTone, string> = {
  // Green: a Cloudflare control stopped it at the edge — the headline of this demo.
  edge: "border-cf-green/60 bg-cf-green/10 text-cf-green-ink",
  // Amber, dashed like the strip's "flagged": the edge saw it and only logged it.
  detected: "border-dashed border-cf-amber bg-cf-amber/10 text-cf-amber-ink",
  vendor: "border-cf-amber/60 bg-cf-amber/10 text-cf-amber-ink",
  inline: "border-cf-purple/60 bg-cf-purple/10 text-cf-purple",
  reached: "border-line bg-surface text-text",
  neutral: "border-line bg-surface-2 text-text",
  error: "border-cf-red/50 bg-cf-red/10 text-cf-red",
};

const ICON: Record<BoothIcon, ReactNode> = {
  blocked: <ShieldBan size={26} />,
  detected: <Eye size={26} />,
  refused: <CircleSlash size={26} />,
  passed: <ShieldCheck size={26} />,
  reached: <CheckCircle2 size={26} />,
  error: <TriangleAlert size={26} />,
};

const STRIP: Record<CellState, string> = {
  stopped: "border-cf-green bg-cf-green/15 font-bold text-cf-green-ink",
  flagged: "border-dashed border-cf-amber bg-cf-amber/10 text-cf-amber-ink",
  unavailable: "border-dashed border-line text-muted",
  reached: "border-line bg-surface-2 font-semibold text-text",
  passed: "border-line text-text",
  pending: "border-line text-muted",
  notReached: "border-line text-subtle line-through decoration-1",
  off: "border-line text-subtle opacity-60",
};

export function BoothTurn({ m, route }: { m: TurnMsg; route: Route }) {
  const streaming = m.kind === "assistant" && !!m.streaming;
  // The background edge lookup (lib/boothTally.ts) — "pending" until it lands, which reads as a plain pass here.
  const edge = useEdgeKnowledge(streaming ? undefined : rayOf(m));
  const banner = streaming ? null : boothBanner(m, route, edge);
  const strip = streaming ? [] : boothStrip(m, route, edge);
  const pipeline = m.kind === "assistant" ? m.meta.externalGuardrails : "pipeline" in m ? m.pipeline : undefined;
  const replyPipeline = m.kind === "assistant" ? m.meta.replyGuardrails : m.kind === "replyWithheld" ? m.replyPipeline : undefined;
  return (
    <div className="animate-rise flex max-w-[min(92%,760px)] flex-col gap-2 self-start">
      {m.kind === "assistant" && (
        <div className="rounded-2xl rounded-bl-md border border-line bg-surface px-5 py-3.5 text-[17px] leading-relaxed whitespace-pre-wrap shadow-sm">
          {m.text}
          {streaming && <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse rounded-sm bg-accent align-middle" />}
        </div>
      )}
      {banner && (
        <div role="status" className={`flex items-start gap-3.5 rounded-2xl border-2 px-5 py-4 shadow-sm ${TONE[banner.tone]}`}>
          <span className="mt-0.5 shrink-0">{ICON[banner.icon]}</span>
          <div className="min-w-0">
            <div className="text-[22px] leading-tight font-extrabold tracking-tight">{banner.title}</div>
            {banner.by && <div className="mt-1 text-[15px] font-semibold opacity-90">{banner.by}</div>}
            {banner.why && <div className="mt-0.5 text-[14px] text-text">{banner.why}</div>}
          </div>
        </div>
      )}
      {strip.length > 0 && (
        <ol className="flex flex-wrap items-center gap-1.5 pl-1 text-[13px]" aria-label="What each layer did">
          {strip.map((s, i) => (
            <li key={s.label} className="flex items-center gap-1.5" title={s.title}>
              {i > 0 && (
                <span aria-hidden className="text-subtle">
                  →
                </span>
              )}
              <span className={`rounded-full border px-2.5 py-0.5 ${STRIP[s.state]}`}>
                {s.label}
                <span className="sr-only"> — {s.state}</span>
              </span>
            </li>
          ))}
        </ol>
      )}
      {!streaming && (pipeline || replyPipeline) && (
        <div className="flex flex-wrap items-center gap-1.5 pl-1">
          {pipeline && <ExternalGuardrailBadges pipeline={pipeline} />}
          {replyPipeline && <ExternalGuardrailBadges pipeline={replyPipeline} />}
        </div>
      )}
    </div>
  );
}
