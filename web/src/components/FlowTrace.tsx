// Vertical request-flow trace: user prompt → AI Security scan → WAF rules →
// outcome. This IS the verdict card body (always shown, no toggle) — every
// detection lives in its node, so nothing is repeated elsewhere. Driven by
// verdict data plus the static ZONE_RULES list (unmatched rules shown dimmed).
import { useState } from "react";
import {
  Ban,
  Check,
  ChevronDown,
  Eye,
  Hand,
  Route,
  ScanLine,
  Server,
  ShieldBan,
  ShieldCheck,
  ShieldHalf,
  Sparkles,
  User,
} from "lucide-react";
import { ZONE_RULES } from "../lib/data";
import { topicLabel } from "../lib/format";
import { verdictOutcome } from "../lib/verdict";
import type { GatewayMeta, Verdict as VerdictData, VerdictRule } from "../lib/types";

type NodeTone = "ok" | "warn" | "flag" | "dead" | "guard";

const NODE: Record<NodeTone, string> = {
  ok: "border-cf-green/60 bg-cf-green/10 text-cf-green",
  warn: "border-cf-amber/60 bg-cf-amber/10 text-cf-amber",
  flag: "border-cf-red/60 bg-cf-red/10 text-cf-red",
  dead: "border-line bg-surface-2 text-subtle",
  guard: "border-cf-purple/60 bg-cf-purple/10 text-cf-purple",
};

type ChipTone = "ok" | "warn" | "flag" | "mute";
const CHIP: Record<ChipTone, string> = {
  ok: "border-cf-green/50 text-cf-green",
  warn: "border-cf-amber/50 text-cf-amber",
  flag: "border-cf-red/50 text-cf-red",
  mute: "border-line-strong text-subtle",
};

// Compact detection pill used inside the AI Security scan node.
function MiniChip({ tone, children }: { tone: ChipTone; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10.5px] font-medium ${CHIP[tone]}`}>
      {children}
    </span>
  );
}

// Custom-topic match bars. The raw model score is inverted (lower = stronger
// match), so we surface "match strength" = 100 − score: higher = stronger, and
// the bar width now agrees with the number. Sorted strongest-first.
function TopicBars({ topics }: { topics: { label: string; score: number }[] }) {
  const rows = topics
    .map((t) => ({ label: t.label, strength: Math.max(0, Math.min(100, 100 - t.score)) }))
    .sort((a, b) => b.strength - a.strength);
  return (
    <div className="mt-2 flex flex-col gap-1.5">
      <div className="text-[9.5px] font-semibold uppercase tracking-wider text-subtle">
        custom topics · match strength
      </div>
      {rows.map((t) => (
        <div key={t.label} className="flex items-center gap-2.5 text-[11px]">
          <span className="min-w-0 flex-1 truncate text-text">{t.label}</span>
          <div className="h-1.5 w-28 overflow-hidden rounded-full bg-surface-2">
            <div className="h-full rounded-full bg-cf-amber" style={{ width: `${Math.max(4, t.strength)}%` }} />
          </div>
          <span className="w-7 text-right font-mono text-muted">{t.strength}</span>
        </div>
      ))}
    </div>
  );
}

// dashed-rail gradients keyed by which layer severed the flow.
const CUT_RAIL: Record<"red" | "purple", string> = {
  red: "bg-[repeating-linear-gradient(to_bottom,rgba(255,92,92,.55)_0_4px,transparent_4px_8px)]",
  purple: "bg-[repeating-linear-gradient(to_bottom,rgba(146,105,255,.6)_0_4px,transparent_4px_8px)]",
};

function Step({
  tone,
  icon: Icon,
  last,
  cut,
  cutColor = "red",
  children,
}: {
  tone: NodeTone;
  icon: React.ElementType;
  last?: boolean;
  cut?: boolean; // dashed rail — the flow was severed here
  cutColor?: "red" | "purple";
  children: React.ReactNode;
}) {
  return (
    <div className="flex gap-3">
      <div className="flex w-7 shrink-0 flex-col items-center">
        <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-full border ${NODE[tone]}`}>
          <Icon size={13} />
        </span>
        {!last && (
          <span
            className={`w-px flex-1 ${cut ? CUT_RAIL[cutColor] : "bg-line-strong"}`}
            style={{ minHeight: 10 }}
          />
        )}
      </div>
      <div className={`min-w-0 flex-1 ${last ? "" : "pb-3.5"}`}>{children}</div>
    </div>
  );
}

const Title = ({ children }: { children: React.ReactNode }) => (
  <div className="text-[12px] font-semibold text-text">{children}</div>
);
const Sub = ({ children }: { children: React.ReactNode }) => (
  <div className="mt-0.5 text-[11px] leading-relaxed text-muted">{children}</div>
);

// One row in the WAF rule checklist.
function RuleRow({
  name,
  action,
  matched,
  summary,
}: {
  name: string;
  action: string;
  matched: boolean;
  summary?: string;
}) {
  const block = /block|drop/i.test(action);
  const cls = !matched
    ? "text-subtle"
    : block
      ? "bg-cf-red/10 text-cf-red"
      : "bg-cf-amber/10 text-cf-amber";
  const Icon = !matched ? Check : block ? Ban : Eye;
  return (
    <div className={`flex items-center gap-2 px-2.5 py-1 text-[11px] ${cls}`} title={summary}>
      <Icon size={12} className="shrink-0" />
      <span className="min-w-0 flex-1 truncate">{name}</span>
      <span className="shrink-0 font-mono text-[10px]">
        {matched ? (block ? "BLOCK ✕" : "LOG") : "no match"}
      </span>
    </div>
  );
}

export type GuardrailsBlock = { direction?: "prompt" | "response"; detail?: string };

export function FlowTrace({
  d,
  prompt,
  gateway,
  guardrails,
}: {
  d: VerdictData;
  prompt?: string;
  gateway?: GatewayMeta;
  guardrails?: GuardrailsBlock; // set when AI Gateway Guardrails blocked (2016/2017)
}) {
  const [showMisses, setShowMisses] = useState(false);

  const matched: VerdictRule[] = d.rules ?? [];
  const matchedNames = matched.map((r) => (r.description || r.ruleId).toLowerCase());
  const isMatched = (name: string) => matchedNames.some((m) => m === name.toLowerCase());
  // Matched rules not in our static list (account-level rules etc.) still show.
  const extraMatched = matched.filter(
    (r) => !ZONE_RULES.some((z) => z.name.toLowerCase() === (r.description || r.ruleId).toLowerCase()),
  );
  const misses = ZONE_RULES.filter((z) => !isMatched(z.name));
  const hitCount = matched.length;

  const outcome = verdictOutcome(d);
  const blocked = outcome === "block";
  const ai = d.ai;
  const scored = ai && d.scored;
  const score = ai?.injectionScore ?? null;
  const attack = score != null && score < 20;
  const hardFlag = scored && (attack || ai!.piiCategories.length > 0 || ai!.unsafeTopicCategories.length > 0);
  const softFlag = scored && ai!.customTopicCategories.length > 0;
  const scanTone: NodeTone = !scored ? "dead" : hardFlag ? "flag" : softFlag ? "warn" : "ok";

  return (
    <div>
      <Step tone="ok" icon={User}>
        <Title>User prompt</Title>
        {prompt && <Sub>“{prompt.length > 140 ? prompt.slice(0, 140) + "…" : prompt}”</Sub>}
        <Sub>
          <span className="font-mono">POST /api/chat</span>
          {d.ray && (
            <>
              {" "}
              · ray <span className="font-mono">{d.ray}</span>
            </>
          )}
        </Sub>
      </Step>

      <Step tone={scanTone} icon={ScanLine}>
        <Title>AI Security scan</Title>
        {scored ? (
          <>
            <div className="mt-1 flex flex-wrap gap-1.5">
              <MiniChip tone={attack ? "flag" : "ok"}>
                injection {score} · {attack ? "likely attack" : "clean"}
              </MiniChip>
              {ai!.piiCategories.length ? (
                <MiniChip tone="flag">PII · {ai!.piiCategories.join(", ")}</MiniChip>
              ) : (
                <MiniChip tone="mute">PII none</MiniChip>
              )}
              {ai!.unsafeTopicCategories.length ? (
                <MiniChip tone="flag">unsafe · {ai!.unsafeTopicCategories.map(topicLabel).join(", ")}</MiniChip>
              ) : (
                <MiniChip tone="mute">no unsafe topics</MiniChip>
              )}
              {ai!.customTopicCategories.length === 0 && <MiniChip tone="mute">no custom topics</MiniChip>}
            </div>
            {ai!.customTopicCategories.length > 0 && <TopicBars topics={ai!.customTopicCategories} />}
          </>
        ) : (
          <Sub>not scored — {ai ? (d.cfLlmLabeled ? "AI Security not enabled" : "endpoint not labeled cf-llm") : "scores still ingesting"}</Sub>
        )}
      </Step>

      <Step tone={hitCount ? "flag" : "ok"} icon={ShieldHalf} cut={blocked}>
        <Title>
          WAF custom rules{" "}
          <span className="font-normal text-subtle">
            · {ZONE_RULES.length + extraMatched.length} evaluated · {hitCount} matched
          </span>
        </Title>
        <div className="mt-1.5 overflow-hidden rounded-lg border border-line">
          {ZONE_RULES.filter((z) => isMatched(z.name)).map((z) => (
            <RuleRow key={z.name} name={z.name} action={z.action} matched summary={z.summary} />
          ))}
          {extraMatched.map((r) => (
            <RuleRow key={r.ruleId} name={r.description || r.ruleId} action={r.action} matched />
          ))}
          {hitCount === 0 && (
            <div className="px-2.5 py-1 text-[11px] text-cf-green">no rule matched — request allowed</div>
          )}
          {misses.length > 0 &&
            (showMisses ? (
              misses.map((z) => <RuleRow key={z.name} name={z.name} action={z.action} matched={false} summary={z.summary} />)
            ) : (
              <button
                type="button"
                onClick={() => setShowMisses(true)}
                className="flex w-full items-center gap-2 px-2.5 py-1 text-left text-[11px] text-subtle transition hover:text-text"
              >
                <ChevronDown size={12} /> {misses.length} more rule{misses.length === 1 ? "" : "s"} — no match
              </button>
            ))}
        </div>
      </Step>

      {blocked ? (
        <Step tone="flag" icon={Hand} last>
          <Title>
            <span className="text-cf-red">Blocked at the edge — 403</span>
          </Title>
          <Sub>Worker never executed · the prompt never reached Workers AI.</Sub>
        </Step>
      ) : guardrails ? (
        // Edge WAF allowed/logged the request, but AI Gateway Guardrails (a
        // separate control at the gateway layer) blocked it. 2016 = prompt
        // moderation (model never runs); 2017 = response moderation (model
        // ran, reply withheld).
        <>
          <Step tone="ok" icon={Server}>
            <Title>Worker</Title>
            <Sub>
              edge allowed{outcome === "log" ? " (log-only rules flagged it — visible in analytics)" : ""} ·
              routed via AI Gateway ·{" "}
              <span className="font-mono">env.AI.run(model, inputs, {"{ gateway }"})</span>
            </Sub>
          </Step>
          {guardrails.direction === "response" ? (
            <>
              <Step tone="ok" icon={Sparkles}>
                <Title>Workers AI</Title>
                <Sub>model generated a reply — returned through the gateway.</Sub>
              </Step>
              <Step tone="guard" icon={ShieldBan} last>
                <Title>
                  <span className="text-cf-purple">Blocked by AI Gateway Guardrails — 2017</span>
                </Title>
                <Sub>
                  {gateway?.gatewayId && (
                    <>
                      <span className="font-mono">{gateway.gatewayId}</span> ·{" "}
                    </>
                  )}
                  response moderation withheld the reply — it never reached the user.
                </Sub>
              </Step>
            </>
          ) : (
            <>
              <Step tone="guard" icon={ShieldBan} cut cutColor="purple">
                <Title>
                  <span className="text-cf-purple">Blocked by AI Gateway Guardrails — 2016</span>
                </Title>
                <Sub>
                  {gateway?.gatewayId && (
                    <>
                      <span className="font-mono">{gateway.gatewayId}</span> ·{" "}
                    </>
                  )}
                  prompt moderation blocked the request at the gateway.
                </Sub>
              </Step>
              <Step tone="dead" icon={Sparkles} last>
                <Title>Workers AI</Title>
                <Sub>never reached — the model did not run.</Sub>
              </Step>
            </>
          )}
        </>
      ) : (
        <>
          <Step tone="ok" icon={Server}>
            <Title>Worker</Title>
            <Sub>
              request allowed{outcome === "log" ? " (flagged by log-only rules — visible in analytics)" : ""} ·{" "}
              <span className="font-mono">
                env.AI.run(model, inputs{gateway ? ", { gateway }" : ""})
              </span>
            </Sub>
          </Step>
          {gateway && (
            <Step tone={gateway.guarded ? "flag" : "ok"} icon={Route}>
              <Title>
                AI Gateway
                {gateway.guarded && (
                  <span className="ml-1.5 inline-flex items-center gap-1 rounded-full border border-cf-purple/60 bg-cf-purple/10 px-1.5 py-px align-middle text-[9.5px] font-bold text-cf-purple">
                    <ShieldCheck size={9} /> GUARDRAILS
                  </span>
                )}
              </Title>
              <Sub>
                {gateway.gatewayId && <span className="font-mono">{gateway.gatewayId}</span>}
                {gateway.gatewayId && " · "}
                cache{" "}
                <span className={gateway.cached ? "text-cf-green" : "text-subtle"}>
                  {gateway.cached == null ? "unknown" : gateway.cached ? "HIT" : "MISS"}
                </span>
                {gateway.latencyMs != null && <> · {gateway.latencyMs} ms</>}
                {gateway.logId && (
                  <>
                    {" "}
                    · log <span className="font-mono">{gateway.logId}</span>
                  </>
                )}
                {gateway.guarded && " · moderation checked (would show a purple block card above on a 2016/2017 hit)"}
              </Sub>
            </Step>
          )}
          <Step tone="ok" icon={Sparkles} last>
            <Title>Workers AI</Title>
            <Sub>model generated the reply above.</Sub>
          </Step>
        </>
      )}
    </div>
  );
}
