// Copy-pasteable Cloudflare control recommendations for a red-team run's
// reached-model categories, cross-referenced against the zone's actual WAF
// rules. Renders GapControl[] from lib/gapControls.ts — see that file's
// header for the score-inversion rule (`le`, never `ge`) and what fields this
// module will and won't invent.
//
// This is a reviewable starting point, never "apply this": there is no write
// path anywhere in this component, only strings the operator copies into the
// dashboard themselves. Self-contained beyond useZoneRules() — no fetching of
// its own, no props the caller has to assemble beyond corpus + results.
import { useState } from "react";
import { Check, Copy, ShieldAlert, ShieldCheck, Wrench } from "lucide-react";
import { Card } from "../analytics/primitives";
import { computeGapControls, type CoverageConfidence, type GapControl, type GapMechanism } from "../../lib/gapControls";
import { useZoneRules } from "../../hooks/useZoneRules";
import { isScored, type RedTeamAttack, type RtRunResult } from "../../lib/redteam";

const MECHANISM_LABEL: Record<GapMechanism, string> = {
  injection: "WAF · injection score",
  unsafe_topic: "WAF · unsafe topic",
  custom_topic_existing: "Dashboard · existing Custom Topic",
  custom_topic_new: "Dashboard · new Custom Topic needed",
  ai_gateway: "AI Gateway · Guardrails",
  unmapped: "unmapped",
};

const CONFIDENCE_LABEL: Record<CoverageConfidence, string> = {
  "live-expression": "live · expression match",
  "live-name": "live · name match",
  "fallback-name": "mirror · name match",
  none: "no match",
  "not-applicable": "n/a",
};

// Green only for the one case that is actually ground truth (a live rule's
// real expression). Everything else — including a live NAME match — is a
// weaker claim and is colored accordingly, per useZoneRules' own honesty
// standard: presenting a guess as verified is the failure this exists to avoid.
const CONFIDENCE_CLS: Record<CoverageConfidence, string> = {
  "live-expression": "border-cf-green/50 text-cf-green",
  "live-name": "border-cf-blue/50 text-cf-blue",
  "fallback-name": "border-cf-amber/50 text-cf-amber",
  none: "border-line text-subtle",
  "not-applicable": "border-line text-subtle",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex shrink-0 items-center gap-1 rounded-full border border-line px-2 py-1 text-[10.5px] text-muted transition hover:border-accent hover:text-accent"
    >
      {copied ? <Check size={11} className="text-cf-green" /> : <Copy size={11} />}
      {copied ? "copied" : "copy"}
    </button>
  );
}

function GapRow({ gap }: { gap: GapControl }) {
  return (
    <div className="rounded-xl border border-line px-3.5 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[12.5px] font-semibold text-text">{gap.category}</span>
        <span className="font-mono text-[11px] text-subtle tabular-nums">
          {gap.reached}/{gap.scored} reached this run
        </span>
        <span className="rounded-full border border-line px-1.5 py-px text-[10px] text-muted">{MECHANISM_LABEL[gap.mechanism]}</span>
        <span
          title={gap.coverage.note}
          className={`ml-auto rounded-full border px-1.5 py-px text-[10px] font-semibold ${CONFIDENCE_CLS[gap.coverage.confidence]}`}
        >
          {gap.coverage.exists ? `covered by '${gap.coverage.ruleName}'` : "no coverage found"} · {CONFIDENCE_LABEL[gap.coverage.confidence]}
        </span>
      </div>

      <p className="mt-1.5 text-[12px] leading-relaxed text-muted">{gap.recommendation}</p>

      {gap.expression ? (
        <div className="mt-2 flex items-start gap-2 rounded-lg border border-line bg-surface-2 px-2.5 py-2">
          <code className="flex-1 overflow-x-auto font-mono text-[11px] whitespace-pre text-text">{gap.expression}</code>
          <CopyButton text={gap.expression} />
        </div>
      ) : (
        gap.expressionNote && (
          <div className="mt-2 flex items-start gap-2 rounded-lg border border-cf-amber/30 bg-cf-amber/[0.06] px-2.5 py-2 text-[11.5px] text-muted">
            <ShieldAlert size={13} className="mt-px shrink-0 text-cf-amber" />
            <span>{gap.expressionNote}</span>
          </div>
        )
      )}
    </div>
  );
}

export function GapControls({
  corpus,
  results,
}: {
  corpus: RedTeamAttack[];
  results: Map<string, RtRunResult>;
}) {
  const zoneRules = useZoneRules();

  // Nothing to derive controls FROM yet — this is not the same state as "ran
  // and found no gaps" below, so it gets its own copy rather than reusing the
  // good-outcome message for something that never ran.
  if (results.size === 0) {
    return (
      <Card title="Close the gaps" subtitle="Run the corpus to get recommendations from this run's own results — not the PDF scan">
        <p className="text-[12px] text-subtle">No run yet.</p>
      </Card>
    );
  }

  const gaps = computeGapControls(corpus, results, zoneRules);
  const anyScored = [...results.values()].some((r) => isScored(r.state));

  return (
    <Card
      title="Close the gaps"
      subtitle={`Each category that reached the model in this run → the Cloudflare control that addresses it · checked against ${
        zoneRules.source === "live" ? "the live zone" : "the static mirror (source=fallback — CF_ANALYTICS_TOKEN lacks Zone→WAF→Read)"
      }`}
    >
      <div className="mb-2 flex items-start gap-2 rounded-lg border border-cf-blue/30 bg-cf-blue/[0.06] px-3 py-2 text-[11px] leading-relaxed text-muted">
        <ShieldAlert size={13} className="mt-px shrink-0 text-cf-blue" />
        <span>
          Reviewable starting point, not an apply button — every expression below is read-only and copies to the clipboard. Nothing here
          writes to the zone.
        </span>
      </div>

      {!anyScored ? (
        <div className="flex items-start gap-2.5 px-1 py-3 text-[12.5px] text-muted">
          <ShieldAlert size={16} className="mt-0.5 shrink-0 text-subtle" />
          <span>No scored edge verdicts yet in this run — results are still resolving, denied, or errored. Recommendations appear once at least one attack is scored.</span>
        </div>
      ) : gaps.length === 0 ? (
        <div className="flex items-start gap-2.5 px-1 py-3 text-[12.5px] text-muted">
          <ShieldCheck size={16} className="mt-0.5 shrink-0 text-cf-green" />
          <span>
            Nothing reached the model in this run — every scored attack was stopped at the edge. That is a real, good outcome, not an
            error; there is nothing to recommend.
          </span>
        </div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {gaps.map((g) => (
            <GapRow key={g.category} gap={g} />
          ))}
        </div>
      )}
    </Card>
  );
}

// Icon re-export so RedTeamPage can drop the old inline `Wrench` import if it
// wants to source the glyph from here instead — matches the RedTeamIcon
// pattern already used on the page.
export const GapControlsIcon = Wrench;
