// Side-by-side scoring of the edge WAF and every external guardrail on the same
// run. Renders the VendorScorecard from lib/vendorScorecard.ts and computes no
// score itself — that file's header explains the rule this view must not blur:
// a control is scored only over the attacks it actually scanned.
import { Link } from "react-router-dom";
import { TriangleAlert } from "lucide-react";
import { Card } from "../analytics/primitives";
import type { RedTeamAttack, RtRunResult } from "../../lib/redteam";
import {
  balancedAccuracy,
  headToHead,
  type HeadToHead,
  type ControlScore,
  type FalseBlockScore,
  type VendorScorecard as VendorScorecardData,
} from "../../lib/vendorScorecard";
import { fmtInterval, wilson } from "../../lib/stats";
import { fmtMs, stageLatency, vendorLatency, type LatencyStat } from "../../lib/vendorLatency";
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
  // The margin of error under the rate (open item F): at this demo's sample sizes the
  // interval is wide, and showing it is what keeps "60% vs 40%" from reading as a win.
  const ci = wilson(c.caught, c.scanned);
  return (
    <span
      className="inline-flex flex-col items-end"
      title={`${c.caught} of ${c.scanned} scanned · 95% interval ${fmtInterval(ci)} (Wilson)`}
    >
      <span className="inline-flex items-center justify-end gap-2">
        <span className="h-1.5 w-14 overflow-hidden rounded-full bg-surface-2">
          <span className={`block h-full rounded-full ${fill}`} style={{ width: `${c.catchPct}%` }} />
        </span>
        <span className="w-9 text-text">{c.catchPct}%</span>
      </span>
      <span className="text-[10px] text-subtle">±95%: {fmtInterval(ci)}</span>
    </span>
  );
}

// Open item E: each pair of guardrails on the attacks BOTH scanned (lib/vendorScorecard.ts).
function HeadToHeadTable({ pairs }: { pairs: HeadToHead[] }) {
  if (pairs.length === 0) return null;
  const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";
  const num = "px-2 py-1.5 text-right font-mono text-[11.5px] tabular-nums";
  return (
    <div className="mt-4 border-t border-line pt-3">
      <h3 className="text-[12.5px] font-bold text-text">Head to head</h3>
      <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
        Each pair of guardrails on the attacks both scanned. Two equal catch rates can hide different catches — "only A"
        and "only B" are what each adds that the other misses; "neither" is the shared gap. An alert is not a catch.
      </p>
      {/* relative: scroll box (CLAUDE.md, scroll containers). */}
      <div className="relative mt-2 overflow-x-auto">
        <table className="w-full min-w-[520px] border-collapse">
          <thead>
            <tr>
              <th className={`${th} text-left`}>Pair</th>
              <th className={th}>Both scanned</th>
              <th className={th}>Both caught</th>
              <th className={th}>Only first</th>
              <th className={th}>Only second</th>
              <th className={th}>Neither</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((p) => (
              <tr key={`${p.a}|${p.b}`} className="border-t border-line">
                <td className="py-1.5 pr-2 pl-2 text-[12px] text-text">
                  <span className="font-semibold">{p.aLabel}</span> <span className="text-subtle">vs</span>{" "}
                  <span className="font-semibold">{p.bLabel}</span>
                </td>
                <td className={`${num} text-muted`}>{p.n}</td>
                <td className={`${num} text-text`}>{p.both}</td>
                <td className={`${num} text-text`} title={`caught by ${p.aLabel}, missed by ${p.bLabel}`}>
                  {p.onlyA}
                </td>
                <td className={`${num} text-text`} title={`caught by ${p.bLabel}, missed by ${p.aLabel}`}>
                  {p.onlyB}
                </td>
                <td className={`${num} ${p.neither > 0 ? "font-semibold text-text" : "text-muted"}`} title="missed by both">
                  {p.neither}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// False blocks on the harmless rows: "—" when this control checked none of them
// (the edge refused them first, or it errored) — never 0%.
function FalseBlockCell({ fb }: { fb: FalseBlockScore | undefined }) {
  if (!fb || fb.falseBlockPct === null) {
    return (
      <span className="text-subtle" title="checked none of the harmless prompts">
        —
      </span>
    );
  }
  const title =
    `${fb.blocked} of ${fb.checked} harmless prompts blocked` +
    (fb.alerts ? ` · ${fb.alerts} alerted but let through` : "") +
    (fb.notSeen ? ` · ${fb.notSeen} never reached it` : "") +
    (fb.errors ? ` · ${fb.errors} could not be consulted` : "");
  return (
    <span title={title}>
      <span className={fb.blocked > 0 ? "font-semibold text-text" : "text-text"}>{fb.falseBlockPct}%</span>{" "}
      <span className="text-[10px] text-muted">
        {fb.blocked}/{fb.checked}
      </span>
    </span>
  );
}

function Row({ c, fb, showFb, lat }: { c: ControlScore; fb?: FalseBlockScore; showFb: boolean; lat?: LatencyStat }) {
  const balanced = balancedAccuracy(c, fb);
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
      {showFb && (
        <>
          <td className={`${num} text-muted`}>
            <FalseBlockCell fb={fb} />
          </td>
          <td
            className={`${num} ${balanced === null ? "text-subtle" : "font-semibold text-text"}`}
            title={
              balanced === null
                ? "needs at least one attack and one harmless prompt scanned by this control"
                : "mean of catch rate (attacks) and pass rate (harmless prompts)"
            }
          >
            {balanced === null ? "—" : `${balanced}%`}
          </td>
        </>
      )}
      <td className={`${num} text-muted`}>
        <LatencyCell control={c.control} lat={lat} />
      </td>
    </tr>
  );
}

// p50 · p95 of this control's own calls (lib/vendorLatency.ts). The edge cannot be
// timed from the Worker — its scan runs before the Worker exists for the request — so
// it reads "not measurable", never 0 ms.
function LatencyCell({ control, lat }: { control: string; lat?: LatencyStat }) {
  if (control === "edge") {
    return (
      <span className="text-subtle" title="The edge scan runs before the Worker is invoked and is not exposed to it">
        not measurable
      </span>
    );
  }
  if (!lat || lat.n === 0) {
    const why = lat?.untimed ? "this run did not record timings" : lat?.errorsExcluded ? "every call errored" : "no call";
    return (
      <span className="text-subtle" title={why}>
        —
      </span>
    );
  }
  const title =
    `${lat.n} timed call${lat.n === 1 ? "" : "s"} · max ${fmtMs(lat.max)}` +
    (lat.errorsExcluded ? ` · ${lat.errorsExcluded} errored and are not counted (a timeout would time our cap, not the vendor)` : "") +
    " · nearest rank: at small n, p95 is usually the max";
  return (
    <span title={title}>
      <span className="text-text">{fmtMs(lat.p50)}</span> <span className="text-subtle">·</span> {fmtMs(lat.p95)}
      <span className="block text-[10px] text-subtle">
        n={lat.n}
        {lat.errorsExcluded ? ` · ${lat.errorsExcluded} err` : ""}
      </span>
    </span>
  );
}

export function VendorScorecard({
  card,
  corpus,
  benignCorpus,
  falseBlocks,
  benignBlocked,
  results,
  labels,
}: {
  card: VendorScorecardData; // attack rows only
  corpus: RedTeamAttack[]; // attack rows with a result
  benignCorpus: RedTeamAttack[]; // harmless rows with a result
  falseBlocks: FalseBlockScore[] | null; // null when the run had no harmless rows
  benignBlocked: number;
  results: Map<string, RtRunResult>;
  labels: Record<string, string>;
}) {
  // Only the edge and no harmless rows: no guardrail ran, and the scorecard above
  // already covers the edge alone. With harmless rows the edge's false blocks are
  // news the scorecard does not show, so the card stays.
  if (card.controls.length <= 1 && !falseBlocks) return null;
  const showFb = !!falseBlocks;
  const fbOf = (control: string) => falseBlocks?.find((f) => f.control === control);
  // Latency is about the call, not the prompt: attack and harmless rows both count.
  const all = [...results.values()];
  const latOf = (control: string) => (control === "edge" ? undefined : vendorLatency(all, control));
  const stages = stageLatency(all);
  // Attack rows only: a harmless prompt "caught" is a false block, not a catch.
  const attackIds = new Set(corpus.map((a) => a.id));
  const pairs = headToHead(
    all.filter((r) => attackIds.has(r.id)),
    card.controls.filter((c) => c.control !== "edge").map((c) => c.control),
    labels,
  );

  const sequential = card.modes.includes("sequential");
  const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";

  return (
    <Card title="Controls compared" subtitle="Each control scored only on the prompts it actually scanned — overall, then by topic or language">
      {card.unevenCoverage && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-cf-amber/40 bg-cf-amber/[0.08] px-3 py-2 text-[11.5px] leading-relaxed text-text">
          <TriangleAlert size={13} className="mt-0.5 shrink-0 text-cf-amber" />
          <span>
            Not a like-for-like comparison: the guardrails did not all scan the same prompts
            {sequential ? " (sequential mode — a later guardrail never sees what an earlier one blocked)" : ""}. For a fair
            comparison set the{" "}
            <Link to="/settings#traffic-flow" className="font-semibold text-accent underline">
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
              {showFb && <th className={th}>False blocks</th>}
              {showFb && <th className={th}>Balanced</th>}
              <th className={th} title="p50 · p95 of each guardrail's own call, as the Worker timed it">
                Latency p50 · p95
              </th>
            </tr>
          </thead>
          <tbody>
            {card.controls.map((c) => (
              <Row key={c.control} c={c} fb={fbOf(c.control)} showFb={showFb} lat={latOf(c.control)} />
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-[12px] leading-relaxed text-muted">
        {card.attacks === 0 ? (
          "No attack rows in this run — only harmless prompts, so there is no catch rate to report."
        ) : card.missedByAll === 0 ? (
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

      {/* The cost side: what the guardrail stage added before the model, per prompt. */}
      {stages.map(({ mode, stat }) => (
        <p key={mode} className="mt-1.5 text-[12px] leading-relaxed text-muted">
          {stat.n === 0 ? (
            <>
              Guardrail stage ({mode}): no timed prompts
              {stat.untimed ? " — this run did not record timings" : stat.errorsExcluded ? " — every stage had an error" : ""}.
            </>
          ) : (
            <>
              The guardrail stage added <span className="font-semibold text-text">{fmtMs(stat.p50)}</span> per prompt
              at the median, <span className="font-semibold text-text">{fmtMs(stat.p95)}</span> at p95 (
              {mode === "parallel" ? "parallel — it waits for the slowest guardrail" : "sequential — the calls add up"};
              n={stat.n}
              {stat.errorsExcluded ? `, ${stat.errorsExcluded} with an error not counted` : ""}).
            </>
          )}
        </p>
      ))}

      {/* Over-blocking: catch rate alone rewards a control that blocks everything. */}
      {falseBlocks ? (
        <p className="mt-1.5 text-[12px] leading-relaxed text-muted">
          <span className="font-mono tabular-nums">{benignBlocked}</span> of{" "}
          <span className="font-mono tabular-nums">{benignCorpus.length}</span> harmless{" "}
          {plural(benignCorpus.length, "prompt was", "prompts were")} blocked by at least one control — a user asking that
          would have been refused. <span className="text-text">Balanced</span> is the mean of catch rate and pass rate, so
          blocking everything scores 50%, not 100%.
        </p>
      ) : (
        <p className="mt-1.5 text-[11.5px] leading-relaxed text-subtle">
          Catch rate alone rewards a control that blocks everything. Upload a CSV with an{" "}
          <code className="font-mono">expected</code> column and some <code className="font-mono">allow</code> rows
          (harmless prompts) to measure false blocks too.
        </p>
      )}

      <HeadToHeadTable pairs={pairs} />

      <VendorBenchmark
        corpus={corpus}
        benignCorpus={benignCorpus}
        results={results}
        controls={card.controls}
        labels={labels}
      />

      <p className="mt-2 text-[10.5px] leading-relaxed text-subtle">
        The edge scores every request that got a verdict; a guardrail never sees a prompt the edge refused. Detect-mode alerts
        are not catches, and an alert on a harmless prompt is not a false block. Harmless rows are kept out of every attack
        score. Latency is each guardrail's own call from Cloudflare to the vendor, so it depends on the region chosen —
        vendors in different regions are not on equal footing; errored calls are left out. Saving the run keeps the verdicts,
        timings, topics and languages, so it can be redrawn from Saved runs.
      </p>
    </Card>
  );
}
