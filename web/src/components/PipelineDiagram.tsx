// "Traffic flow" panel for the Guardrails page: the request path drawn FROM the
// saved pipeline config, with the few controls that edit it. It is not a
// free-form editor on purpose — two stages can never move:
//   - the edge WAF runs at Cloudflare's edge, before the Worker is invoked, so
//     the Worker has no say in its position;
//   - AI Gateway Guardrails run inside the model call (gateway route only), so
//     they always sit with the model.
// Only the external guardrails between them are configurable.
//
// Like the provider cards, nothing here is optimistic: every control calls the
// server and the page replaces its state with what comes back, so a node only
// ever shows a setting the server actually accepted.
import { Fragment, useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Lock,
  Merge,
  Split,
} from "lucide-react";
import { Switch } from "./Switch";
import type {
  ExternalGuardrailConfig,
  ExternalGuardrailProvider,
  ExternalGuardrailsState,
  GuardrailPipelineMode,
  GuardrailPipelineUpdate,
} from "../lib/types";

// Each handler resolves to the server's error message, or null on success — the
// page owns the fetch and the state swap, this component owns busy + display.
export interface PipelineDiagramProps {
  state: ExternalGuardrailsState;
  onToggle: (provider: ExternalGuardrailProvider, enabled: boolean) => Promise<string | null>;
  onPipeline: (update: GuardrailPipelineUpdate) => Promise<string | null>;
}

const MODES: { id: GuardrailPipelineMode; label: string }[] = [
  { id: "sequential", label: "Sequential" },
  { id: "parallel", label: "Parallel" },
];

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// Why a guardrail cannot be switched ON right now, or null when it can. The
// server enforces the same rules (HTTP 400); stating them here lets the node
// say so before the click instead of after a rejected request.
function cannotEnableReason(p: ExternalGuardrailConfig): string | null {
  if (!p.supported) return "Not yet supported — this provider cannot be enabled";
  // "API key" keeps its acronym; "Collector token" reads lower-case mid-sentence.
  const key = /^[A-Z]{2}/.test(p.keyLabel) ? p.keyLabel : p.keyLabel.toLowerCase();
  if (!p.apiKeySet) return `Needs a saved ${key} — add it in the provider card below`;
  // Only providers that name a profile per request need one (Prisma AIRS, Lakera Guard).
  if (p.requiresProfile && !p.profileName.trim()) {
    const what = p.profileLabel === "Project ID" ? "a project ID" : "an AI security profile name";
    return `Needs ${what} — save one in the provider card below`;
  }
  return null;
}

// Arrows point down in the stacked (narrow) layout and right in the horizontal
// one, so one element serves both and the flow reads the same at every width.
function Arrow({ dim }: { dim?: boolean }) {
  return (
    <span aria-hidden="true" className={`flex shrink-0 justify-center text-subtle ${dim ? "opacity-40" : ""}`}>
      <ArrowDown size={16} className="xl:hidden" />
      <ArrowRight size={16} className="hidden xl:block" />
    </span>
  );
}

function EndPill({ children, dim }: { children: React.ReactNode; dim?: boolean }) {
  return (
    <div
      className={`shrink-0 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-center text-[12px] font-semibold text-text ${
        dim ? "opacity-60" : ""
      }`}
    >
      {children}
    </div>
  );
}

function FlowChip({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex shrink-0 items-center justify-center gap-1.5 rounded-full border border-cf-amber/40 bg-cf-amber/10 px-2.5 py-1 text-[11px] font-semibold text-cf-amber">
      {icon}
      {children}
    </div>
  );
}

function ProviderNode({
  p,
  index,
  movable,
  last,
  busy,
  onToggle,
  onMove,
}: {
  p: ExternalGuardrailConfig;
  index: number;
  movable: boolean;
  last: boolean;
  busy: boolean;
  onToggle: () => void;
  onMove: (delta: -1 | 1) => void;
}) {
  const on = p.supported && p.enabled;
  const blocked = cannotEnableReason(p);
  // Turning OFF is always allowed; the missing-key/profile rules only gate ON.
  const toggleDisabled = busy || !p.supported || (!on && blocked != null);
  const tip = on ? "Click to disable" : (blocked ?? "Click to enable");
  return (
    <div
      title={toggleDisabled && !busy ? tip : undefined}
      className={`flex w-full min-w-0 flex-col rounded-xl border xl:w-48 ${
        on ? "border-cf-amber/60 bg-cf-amber/10" : "border-dashed border-line bg-surface-2"
      }`}
    >
      <button
        type="button"
        aria-pressed={on}
        disabled={toggleDisabled}
        onClick={onToggle}
        title={tip}
        className={`flex flex-1 flex-col gap-1 rounded-xl px-3 py-2 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed ${
          on ? "" : "opacity-60"
        }`}
      >
        <span className="text-[12.5px] leading-snug font-bold text-text">{p.label}</span>
        {!p.supported ? (
          <span className="text-[11px] font-semibold text-subtle">Not yet supported</span>
        ) : on ? (
          <span className="text-[11px] font-semibold text-cf-green">Enabled</span>
        ) : (
          <span className="text-[11px] font-semibold text-muted">Disabled — skipped in the flow</span>
        )}
        {p.supported && (
          <span
            className="text-[11px] text-muted"
            title={
              p.failMode === "block"
                ? "If this guardrail errors or times out, the prompt is blocked"
                : "If this guardrail errors or times out, the prompt goes on unscanned by it"
            }
          >
            {p.failMode === "block" ? "fail closed" : "fail open"}
          </span>
        )}
        {p.supported && !on && blocked && <span className="text-[11px] text-subtle">{blocked}</span>}
      </button>
      {movable && (
        <div className="flex items-center justify-between border-t border-line px-2 py-1">
          <span className="text-[10.5px] text-subtle">step {index + 1}</span>
          <span className="flex gap-1">
            <button
              type="button"
              disabled={busy || index === 0}
              onClick={() => onMove(-1)}
              aria-label={`Run ${p.label} earlier`}
              title="Run earlier"
              className="rounded-md border border-line bg-surface p-0.5 text-muted transition-colors hover:border-line-strong hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronUp size={14} className="xl:hidden" />
              <ChevronLeft size={14} className="hidden xl:block" />
            </button>
            <button
              type="button"
              disabled={busy || last}
              onClick={() => onMove(1)}
              aria-label={`Run ${p.label} later`}
              title="Run later"
              className="rounded-md border border-line bg-surface p-0.5 text-muted transition-colors hover:border-line-strong hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronDown size={14} className="xl:hidden" />
              <ChevronRight size={14} className="hidden xl:block" />
            </button>
          </span>
        </div>
      )}
    </div>
  );
}

export function PipelineDiagram({ state, onToggle, onPipeline }: PipelineDiagramProps) {
  const { pipeline, providers } = state;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // One in-flight write at a time: each reply replaces the whole state, so two
  // overlapping saves could land out of order and show a setting that is stale.
  async function run(fn: () => Promise<string | null>) {
    setBusy(true);
    setErr(null);
    try {
      const e = await fn();
      if (e) setErr(e);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  // Providers in pipeline order. Any provider the order omits is appended so the
  // diagram never hides one, and the order we send back always lists every
  // provider exactly once, which is what the server requires.
  const byId = new Map(providers.map((p) => [p.provider, p]));
  const ordered: ExternalGuardrailConfig[] = [
    ...pipeline.order.map((id) => byId.get(id)).filter((p): p is ExternalGuardrailConfig => !!p),
    ...providers.filter((p) => !pipeline.order.includes(p.provider)),
  ];
  const isOn = (p: ExternalGuardrailConfig) => p.supported && p.enabled;
  const active = ordered.filter(isOn);
  const sequential = pipeline.mode === "sequential";
  const skipModel = pipeline.guardrailOnly;

  function move(i: number, delta: -1 | 1) {
    const ids = ordered.map((p) => p.provider);
    const j = i + delta;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    void run(() => onPipeline({ order: ids }));
  }

  const summary =
    `Prompt, then the edge WAF, then ` +
    (active.length === 0
      ? "no external guardrail"
      : active.map((p) => p.label).join(sequential ? ", then " : " and ") + (sequential ? "" : ", in parallel")) +
    (skipModel ? ", then the model is skipped." : ", then the model with AI Gateway Guardrails, then the reply.");

  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">Traffic flow</h2>
      <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
        Drawn from the saved settings. The locked stages cannot move; the guardrails between them can be switched on
        and off, run one after another or all at once, and put in a different order.
      </p>

      {skipModel && (
        // Global switch that changes what every chat and Red Team run does, so
        // it is stated at the top of the panel rather than left to the toggle.
        <div role="status" className="mt-3 flex items-start gap-2.5 rounded-xl border border-cf-amber/60 bg-cf-amber/10 px-3.5 py-2.5">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-cf-amber" />
          <p className="text-[12.5px] leading-relaxed font-semibold text-text">
            Guardrail-only mode is ON — chat and Red Team runs will not call the model. AI Gateway Guardrails do not
            run either.
          </p>
        </div>
      )}

      <p className="sr-only">{summary}</p>
      <div className="mt-4 flex flex-col items-stretch gap-1 xl:flex-row xl:items-center xl:gap-1.5">
        <EndPill>Prompt</EndPill>
        <Arrow />

        <div className="w-full shrink-0 rounded-xl border border-cf-red/50 bg-cf-red/10 px-3 py-2 xl:w-40">
          <div className="flex items-center gap-1.5 text-[12.5px] font-bold text-cf-red">
            <Lock size={12} /> Edge WAF
          </div>
          <div className="mt-1 text-[11px] leading-snug text-muted">
            Runs at Cloudflare's edge, before the Worker — it cannot be moved from here.
          </div>
        </div>
        <Arrow />

        <div className="flex min-w-0 flex-col gap-2 rounded-2xl border border-dashed border-cf-amber/60 p-3">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-[11px] font-bold tracking-wider text-cf-amber uppercase">External guardrails</span>
            <span className="text-[11px] text-subtle">{sequential ? "one after another" : "all at once"}</span>
          </div>
          {active.length === 0 && (
            <div className="text-[12px] leading-snug text-muted">
              No external guardrail enabled — prompts go straight from the edge to the model
              {skipModel ? ", and with guardrail-only on they stop there (an edge-only test)." : "."}
            </div>
          )}
          {sequential ? (
            <div className="flex flex-col items-stretch gap-1 xl:flex-row xl:items-center xl:gap-1.5">
              {ordered.map((p, i) => (
                <Fragment key={p.provider}>
                  {i > 0 && <Arrow dim={!isOn(ordered[i - 1]) || !isOn(p)} />}
                  <ProviderNode
                    p={p}
                    index={i}
                    movable={ordered.length > 1}
                    last={i === ordered.length - 1}
                    busy={busy}
                    onToggle={() => void run(() => onToggle(p.provider, !isOn(p)))}
                    onMove={(d) => move(i, d)}
                  />
                </Fragment>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-stretch gap-1 xl:flex-row xl:items-center xl:gap-2">
              <FlowChip icon={<Split size={12} />}>fan out</FlowChip>
              <div className="flex flex-col gap-2">
                {ordered.map((p, i) => (
                  <ProviderNode
                    key={p.provider}
                    p={p}
                    index={i}
                    // Order only decides listing order when they all run at once,
                    // so the arrows are offered in sequential mode alone.
                    movable={false}
                    last={i === ordered.length - 1}
                    busy={busy}
                    onToggle={() => void run(() => onToggle(p.provider, !isOn(p)))}
                    onMove={() => undefined}
                  />
                ))}
              </div>
              <FlowChip icon={<Merge size={12} />}>join · waits for all</FlowChip>
            </div>
          )}
          <div className="text-[11px] leading-snug text-subtle">
            {sequential
              ? "The first guardrail to stop a prompt ends the turn; later ones do not run. Latency adds up."
              : "The model runs only if every guardrail allows; the Worker waits for all of them. Latency is the slowest one."}
          </div>
        </div>
        <Arrow dim={skipModel} />

        <div
          className={`w-full shrink-0 rounded-xl border border-line bg-surface-2 px-3 py-2 xl:w-52 ${
            skipModel ? "border-dashed opacity-60" : ""
          }`}
        >
          <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[12.5px] font-bold text-text">
            <Lock size={12} />
            <span className={skipModel ? "line-through" : ""}>Model</span>
            {skipModel && (
              <span className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-1.5 py-px text-[10px] font-bold text-cf-amber">
                skipped
              </span>
            )}
          </div>
          <div className="mt-1.5">
            <span
              className={`rounded-full border border-cf-purple/60 bg-cf-purple/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-purple ${
                skipModel ? "line-through" : ""
              }`}
            >
              AI Gateway Guardrails
            </span>
          </div>
          <div className="mt-1.5 text-[11px] leading-snug text-muted">
            {skipModel
              ? "Neither runs: Gateway Guardrails are part of the model call."
              : "Gateway Guardrails run inside the model call (gateway route only), so they stay with it."}
          </div>
        </div>
        <Arrow dim={skipModel} />

        <EndPill dim={skipModel}>{skipModel ? "No reply — verdict only" : "Reply"}</EndPill>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-3 border-t border-line pt-3.5">
        <div role="group" aria-label="How the guardrails run" className="inline-flex overflow-hidden rounded-full border border-line">
          {MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              aria-pressed={pipeline.mode === m.id}
              disabled={busy}
              onClick={() => {
                if (pipeline.mode !== m.id) void run(() => onPipeline({ mode: m.id }));
              }}
              className={`px-3 py-1.5 text-[12.5px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-60 ${
                pipeline.mode === m.id ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
        <Switch
          checked={skipModel}
          onChange={(v) => void run(() => onPipeline({ guardrailOnly: v }))}
          disabled={busy}
          label="Guardrail-only (skip the model)"
          title="Test the edge WAF and the external guardrails without calling the model. Applies to chat and Red Team runs."
        />
      </div>
      <div aria-live="polite" className="empty:hidden">
        {err && (
          <div className="mt-3 flex items-start gap-1.5 text-[12px] text-cf-red">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span className="min-w-0 break-words">{err}</span>
          </div>
        )}
      </div>
    </section>
  );
}
