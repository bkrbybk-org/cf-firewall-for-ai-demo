import { useEffect, useState } from "react";
import { Search } from "lucide-react";
import { pollVerdict, verdictOutcome, type Outcome, type PollResult } from "../lib/verdict";
import { FlowTrace, type GuardrailsBlock } from "./FlowTrace";
import type { GatewayMeta, Verdict as VerdictData } from "../lib/types";

type Status = { phase: "pending"; tries: number } | PollResult;

const TONE: Record<string, string> = {
  neutral: "border-line bg-surface text-muted",
};

// Card frame per outcome — colored border/tint only; body text stays neutral
// so the coloring reads as an accent, not a wall of red.
const CARD: Record<Outcome, string> = {
  block: "border-cf-red/40 bg-cf-red/[0.06]",
  challenge: "border-cf-amber/40 bg-cf-amber/[0.06]",
  log: "border-cf-amber/40 bg-cf-amber/[0.06]",
  allow: "border-cf-green/40 bg-cf-green/[0.06]",
};

// Filled action badge so the outcome pops at a glance.
const PILL: Record<Outcome, { label: string; cls: string }> = {
  block: { label: "BLOCKED", cls: "bg-cf-red text-white" },
  challenge: { label: "CHALLENGE", cls: "bg-cf-amber text-[#241a04]" },
  log: { label: "LOGGED", cls: "bg-cf-amber text-[#241a04]" },
  allow: { label: "ALLOWED", cls: "bg-cf-green text-[#04140d]" },
};

// Plain-language summary of what actually happened — the headline of the card.
function summaryLine(cls: Outcome, ruleCount: number, gateway?: GatewayMeta, guardrails?: GuardrailsBlock): string {
  if (guardrails) {
    return guardrails.direction === "response"
      ? "Model replied, but the gateway withheld it — response moderation (2017)."
      : "Stopped at the gateway — prompt moderation (2016). The model never ran.";
  }
  if (cls === "block") return "Blocked at the edge — 403. The prompt never reached the model.";
  if (cls === "challenge") return "Challenged at the edge before reaching the model.";
  if (cls === "log")
    return `Reached the model — ${ruleCount} log-only rule${ruleCount === 1 ? "" : "s"} flagged it for analytics.`;
  return gateway ? "Reached the model via AI Gateway — no rule matched." : "Reached the model — no rule matched.";
}

function VerdictBody({
  d,
  prompt,
  gateway,
  guardrails,
}: {
  d: VerdictData;
  prompt?: string;
  gateway?: GatewayMeta;
  guardrails?: GuardrailsBlock;
}) {
  const cls = verdictOutcome(d);
  const ruleCount = d.rules?.length ?? 0;
  const summary = summaryLine(cls, ruleCount, gateway, guardrails);

  // AI Gateway Guardrails is a separate control from the edge WAF, so its block
  // gets a purple badge instead of the edge action pill.
  const guarded = !!guardrails;
  const pill = guarded
    ? { label: `GUARDRAILS · ${guardrails!.direction === "response" ? "2017" : "2016"}`, cls: "bg-cf-purple text-[#1a0f33]" }
    : PILL[cls];
  const cardCls = guarded ? "border-cf-purple/40 bg-cf-purple/[0.06]" : CARD[cls];

  return (
    <div className={`animate-rise rounded-xl border px-3.5 py-3 ${cardCls}`}>
      {/* Header: action badge · plain-language outcome · ray */}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold tracking-wide ${pill.cls}`}>
          {pill.label}
        </span>
        <span className="text-[12px] font-medium text-text">{summary}</span>
        {d.ray && <span className="ml-auto font-mono text-[11px] text-subtle">ray {d.ray}</span>}
      </div>

      {/* The flow trace IS the body — every detection lives in its node. */}
      <div className="mt-3">
        <FlowTrace d={d} prompt={prompt} gateway={gateway} guardrails={guardrails} />
      </div>
    </div>
  );
}

export function Verdict({
  ray,
  prompt,
  gateway,
  guardrails,
}: {
  ray: string;
  prompt?: string;
  gateway?: GatewayMeta;
  guardrails?: GuardrailsBlock;
}) {
  const [status, setStatus] = useState<Status>({ phase: "pending", tries: 0 });

  useEffect(() => {
    if (!ray) return;
    const poll = pollVerdict(ray, (tries) => setStatus({ phase: "pending", tries }));
    poll.promise.then(setStatus);
    return poll.cancel;
  }, [ray]);

  if (status.phase === "done")
    return <VerdictBody d={status.data} prompt={prompt} gateway={gateway} guardrails={guardrails} />;

  let text: string;
  if (status.phase === "pending") text = `checking Cloudflare edge log… (${status.tries})`;
  else if (status.phase === "disabled") text = `live edge log disabled — set CF_ANALYTICS_TOKEN (ray ${status.ray ?? ""})`;
  else text = status.message;

  return (
    <div className={`flex items-center gap-1.5 rounded-xl border px-3 py-2 text-[11.5px] ${TONE.neutral} ${status.phase === "pending" ? "opacity-80" : ""}`}>
      <Search size={12} /> {text}
    </div>
  );
}
