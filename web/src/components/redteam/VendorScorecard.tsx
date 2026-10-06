// Side-by-side scoring of the edge WAF and every external guardrail on the same
// run. Renders the VendorScorecard from lib/vendorScorecard.ts and computes no
// score itself — that file's header explains the rule this view must not blur:
// a control is scored only over the attacks it actually scanned.
import { Link } from "react-router-dom";
import { TriangleAlert } from "lucide-react";
import { Card } from "../analytics/primitives";
import type { RedTeamAttack, RtRunResult } from "../../lib/redteam";
import type { ControlScore, VendorScorecard as VendorScorecardData } from "../../lib/vendorScorecard";
import { VendorBenchmark } from "./VendorBenchmark";

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

function CatchRate({ c }: { c: ControlScore }) {
  // null means "scanned nothing" — a dash, never 0%: a control that saw no prompt
  // has no catch rate, and 0% would read as "caught none of what it saw".
  if (c.catchPct === null) {
    return (
      <span title="scanned nothing" className="font-mono text-subtle">
        —
      </span>
    );
  }
  const fill = c.control === "edge" ? "bg-cf-red/70" : "bg-cf-amber/70";
  return (
    <span className="inline-flex items-center justify-end gap-2" title={`${c.caught} of ${c.scanned} scanned`}>
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-surface-2">
        <span className={`block h-full rounded-full ${fill}`} style={{ width: `${c.catchPct}%` }} />
      </span>
      <span className="w-9 text-text">{c.catchPct}%</span>
    </span>
  );
}

function Row({ c }: { c: ControlScore }) {
  const notScored = c.errors + c.notSeen + c.notRun;
  // The accent is the control's own colour (edge red, guardrails amber) so a
  // row never borrows another control's identity.
  const accent = c.control === "edge" ? "border-l-cf-red" : "border-l-cf-amber";
  const num = "px-2 py-2 text-right font-mono text-[11.5px] tabular-nums";
  return (
    <tr className="border-t border-line">
      <td className={`border-l-2 ${accent} py-2 pr-2 pl-2.5 text-[12px] font-semibold whitespace-nowrap text-text`}>{c.label}</td>
      <td className={`${num} text-text`}>{c.caught}</td>
      <td className={`${num} text-muted`}>{c.scanned}</td>
      <td className={`${num} text-muted`}>
        <CatchRate c={c} />
      </td>
      <td className={`${num} text-muted`} title="flagged in Detect mode, but the prompt went on — not a catch">
        {c.alerts}
      </td>
      <td className={`${num} text-muted`} title="caught here, missed by every other control that scanned it">
        {c.onlyThis}
      </td>
      <td
        className={`${num} text-muted`}
        title={`${c.errors} could not be consulted · ${c.notSeen} never reached it · ${c.notRun} not run — an earlier guardrail stopped it`}
      >
        {notScored}
      </td>
    </tr>
  );
}

export function VendorScorecard({
  card,
  corpus,
  results,
  labels,
}: {
  card: VendorScorecardData;
  corpus: RedTeamAttack[];
  results: Map<string, RtRunResult>;
  labels: Record<string, string>;
}) {
  // Only the edge: no guardrail ran, and the existing scorecard already covers it.
  if (card.controls.length <= 1) return null;

  const sequential = card.modes.includes("sequential");
  const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";

  return (
    <Card title="Controls compared" subtitle="Each control scored only on the attacks it actually scanned — overall, then by topic or language">
      {card.unevenCoverage && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-cf-amber/40 bg-cf-amber/[0.08] px-3 py-2 text-[11.5px] leading-relaxed text-text">
          <TriangleAlert size={13} className="mt-0.5 shrink-0 text-cf-amber" />
          <span>
            Not a like-for-like comparison: the guardrails did not all scan the same prompts
            {sequential ? " (sequential mode — a later guardrail never sees what an earlier one blocked)" : ""}. For a fair
            comparison set the{" "}
            <Link to="/guardrails" className="font-semibold text-accent underline">
              traffic flow
            </Link>{" "}
            to Parallel, ideally with Guardrail-only on, and re-run.
          </span>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] border-collapse">
          <thead>
            <tr>
              <th className="px-2 pb-1.5 pl-2.5 text-left text-[10.5px] font-semibold tracking-wide text-subtle uppercase">Control</th>
              <th className={th}>Caught</th>
              <th className={th}>Scanned</th>
              <th className={th}>Catch rate</th>
              <th className={th}>Alerts only</th>
              <th className={th}>Only this control</th>
              <th className={th}>Not scored</th>
            </tr>
          </thead>
          <tbody>
            {card.controls.map((c) => (
              <Row key={c.control} c={c} />
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-[12px] leading-relaxed text-muted">
        {card.missedByAll === 0 ? (
          "Every attack that a control scanned was caught by at least one of them."
        ) : (
          <>
            <span className="font-mono tabular-nums">{card.missedByAll}</span> of{" "}
            <span className="font-mono tabular-nums">{card.attacks}</span> {plural(card.attacks, "attack", "attacks")}{" "}
            {plural(card.missedByAll, "was", "were")} caught by no control that scanned{" "}
            {plural(card.missedByAll, "it", "them")}.
          </>
        )}
      </p>

      <VendorBenchmark corpus={corpus} results={results} controls={card.controls} labels={labels} />

      <p className="mt-2 text-[10.5px] leading-relaxed text-subtle">
        The edge scores every request that got a verdict; a guardrail never sees a prompt the edge refused. Detect-mode alerts
        are not catches. Not stored with saved runs.
      </p>
    </Card>
  );
}
