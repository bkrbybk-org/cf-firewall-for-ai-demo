// The benchmark half of "Controls compared": the same per-control scores split by
// topic or by language, as a grid — who is good at what. Renders the
// VendorBenchmark from lib/vendorBenchmark.ts and computes no score itself; that
// file's header explains when a row ranks its controls and when it refuses to.
//
// Two metrics when the run had harmless rows (a CSV's expected=allow): catch rate
// on the attacks, and false blocks on the harmless prompts. They are never mixed in
// one cell — the attack grid never sees a harmless row, and vice versa.
import { useMemo, useState } from "react";
import { ArrowDown, Trophy } from "lucide-react";
import type { RedTeamAttack, RtRunResult } from "../../lib/redteam";
import {
  BENCHMARK_MIN_N,
  vendorBenchmark,
  type BenchmarkCell,
  type BenchmarkGroupBy,
  type BenchmarkMetric,
  type BenchmarkRow,
} from "../../lib/vendorBenchmark";
import type { ControlScore } from "../../lib/vendorScorecard";

// Enough rows to read at a glance; a ThaiSafetyBench sample has ~20 topics.
const ROWS_COLLAPSED = 10;

const GROUPS: { id: BenchmarkGroupBy; label: string }[] = [
  { id: "topic", label: "Topic" },
  { id: "language", label: "Language" },
];

const METRICS: { id: BenchmarkMetric; label: string }[] = [
  { id: "catch", label: "Catch rate" },
  { id: "falseBlock", label: "False blocks" },
];

function Toggle<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { id: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex overflow-hidden rounded-full border border-line">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-pressed={value === o.id}
          onClick={() => onChange(o.id)}
          className={`px-3 py-1 text-[12px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
            value === o.id ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function Cell({ c, ranked, fb }: { c: BenchmarkCell; ranked: boolean; fb: boolean }) {
  const base = "px-2 py-1.5 text-right font-mono text-[11.5px] tabular-nums";
  if (c.catchPct === null) {
    // Scanned none of this row — a dash, never 0% (same rule as the table above).
    const why = c.notSeen > 0 ? "never reached this control" : c.errors > 0 ? "could not be consulted" : "not scanned";
    return (
      <td className={`${base} text-subtle`} title={why}>
        —
      </td>
    );
  }
  const small = c.scanned < BENCHMARK_MIN_N;
  const title =
    (fb ? `${c.caught} of ${c.scanned} harmless prompts blocked` : `${c.caught} of ${c.scanned} scanned caught`) +
    (c.alerts ? ` · ${c.alerts} alerted only` : "") +
    (c.errors ? ` · ${c.errors} could not be consulted` : "") +
    (c.notSeen ? ` · ${c.notSeen} never reached it` : "") +
    (small ? ` · fewer than ${BENCHMARK_MIN_N} scanned — too few to rank` : !ranked ? " · scanned different prompts from the ranked controls — not ranked" : "");
  // Heat is a single green ramp, and greener is better in both metrics: on harmless
  // rows it follows the PASS rate (100 − false blocks). The number carries the
  // meaning; the tint only makes strengths and gaps visible at a glance. A sample
  // too small to rank gets no tint, so it never looks like a result.
  const good = fb ? 100 - c.catchPct : c.catchPct;
  const tint = small ? undefined : `color-mix(in srgb, var(--green) ${Math.round(good * 0.3)}%, transparent)`;
  const srRank =
    c.rank === "best"
      ? fb
        ? "(fewest false blocks in this row)"
        : "(best in this row)"
      : fb
        ? "(most false blocks in this row)"
        : "(lowest in this row)";
  return (
    <td className={base} style={{ backgroundColor: tint }} title={title}>
      <span className="inline-flex items-center justify-end gap-1">
        {c.rank === "best" && <Trophy size={11} aria-hidden className="shrink-0 text-cf-green" />}
        {c.rank === "worst" && <ArrowDown size={11} aria-hidden className="shrink-0 text-muted" />}
        <span className={c.rank === "best" ? "font-bold text-text" : small ? "text-subtle" : "text-text"}>{c.catchPct}%</span>
        {c.rank && <span className="sr-only">{srRank}</span>}
      </span>
      <span className={`block text-[10px] ${small ? "text-subtle" : "text-muted"}`}>
        {c.caught}/{c.scanned}
      </span>
    </td>
  );
}

function Row({ row, fb }: { row: BenchmarkRow; fb: boolean }) {
  // Last column: attacks no control caught, or harmless prompts some control blocked.
  const tail = fb ? row.blockedByAny : row.missedByAll;
  return (
    <tr className="border-t border-line">
      <td className="sticky left-0 z-[1] max-w-[18rem] min-w-[8rem] bg-surface py-1.5 pr-2 pl-2.5 text-[12px] leading-snug text-text">
        <span className="line-clamp-2 break-words" title={row.key}>
          {row.key}
        </span>
      </td>
      <td className="px-2 py-1.5 text-right font-mono text-[11.5px] text-muted tabular-nums">{row.attacks}</td>
      {row.cells.map((c) => (
        <Cell key={c.control} c={c} ranked={row.ranked.includes(c.control)} fb={fb} />
      ))}
      <td
        className={`px-2 py-1.5 text-right font-mono text-[11.5px] tabular-nums ${tail > 0 ? "font-semibold text-text" : "text-muted"}`}
        title={
          fb
            ? "harmless prompts blocked by at least one control — a real user would have been refused"
            : "scanned by at least one control, caught by none"
        }
      >
        {tail}
      </td>
    </tr>
  );
}

export function VendorBenchmark({
  corpus,
  benignCorpus,
  results,
  controls,
  labels,
}: {
  corpus: RedTeamAttack[]; // attack rows with a result
  benignCorpus: RedTeamAttack[]; // harmless rows with a result (may be empty)
  results: Map<string, RtRunResult>;
  controls: ControlScore[];
  labels: Record<string, string>;
}) {
  const [groupBy, setGroupBy] = useState<BenchmarkGroupBy>("topic");
  const [chosenMetric, setMetric] = useState<BenchmarkMetric>("catch");
  const [expanded, setExpanded] = useState(false);
  // Falls back to catch rate when a later run has no harmless rows, rather than
  // showing an empty false-block grid behind a switch that is no longer offered.
  const hasBenign = benignCorpus.length > 0;
  const metric: BenchmarkMetric = hasBenign ? chosenMetric : "catch";
  const fb = metric === "falseBlock";
  const ids = useMemo(() => controls.map((c) => c.control), [controls]);
  const bench = useMemo(
    () => vendorBenchmark(fb ? benignCorpus : corpus, results, groupBy, ids, labels, metric),
    [fb, benignCorpus, corpus, results, groupBy, ids, labels, metric],
  );
  const noun = groupBy === "topic" ? "topic" : "language";
  const nouns = groupBy === "topic" ? "topics" : "languages";
  const shown = expanded ? bench.rows : bench.rows.slice(0, ROWS_COLLAPSED);
  const winners = bench.wins.filter((w) => w.wins > 0);
  const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";

  return (
    <div className="mt-4 border-t border-line pt-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h3 className="text-[12.5px] font-bold text-text">Benchmark by</h3>
        <Toggle
          label="Benchmark grouping"
          options={GROUPS}
          value={groupBy}
          onChange={(v) => {
            setGroupBy(v);
            setExpanded(false);
          }}
        />
        {hasBenign && (
          <Toggle
            label="Benchmark metric"
            options={METRICS}
            value={metric}
            onChange={(v) => {
              setMetric(v);
              setExpanded(false);
            }}
          />
        )}
        <span className="text-[11.5px] text-muted">
          {fb
            ? "share of harmless prompts each control blocked — lower is better"
            : "catch rate per control · each scored only on what it scanned"}
        </span>
      </div>

      {/* The headline: who won the most rows that were a fair contest. */}
      <p className="mt-2 text-[12px] leading-relaxed text-muted">
        {bench.rows.length === 0 ? (
          <>No {fb ? "harmless" : "attack"} prompts in this run.</>
        ) : bench.rankedRows === 0 ? (
          <>
            No {noun} had {BENCHMARK_MIN_N}+ {fb ? "harmless " : ""}prompts that two controls both scanned, so nothing is
            ranked yet — run more, ideally in Parallel with Guardrail-only on.
          </>
        ) : winners.length === 0 ? (
          <>
            Every control tied in {bench.rankedRows === 1 ? `the one ${noun}` : `all ${bench.rankedRows} ${nouns}`} that could
            be compared.
          </>
        ) : (
          <>
            <span className="font-semibold text-text">
              {fb ? `Fewest false blocks in most ${nouns}:` : `Best in most ${nouns}:`}
            </span>{" "}
            {winners.map((w, i) => (
              <span key={w.control}>
                {i > 0 && " · "}
                <span className="text-text">{w.label}</span> <span className="font-mono tabular-nums">{w.wins}</span>
              </span>
            ))}{" "}
            — of {bench.rankedRows} {bench.rankedRows === 1 ? noun : nouns} compared like for like (ties count for each).
          </>
        )}
      </p>

      {/* relative: the cells' sr-only text must not escape this scroll box (CLAUDE.md, scroll containers). The
          topic column is sticky so a row keeps its name while the controls scroll on a phone. */}
      {bench.rows.length > 0 && (
        <div className="relative mt-2 overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse">
            <thead>
              <tr>
                <th className="sticky left-0 z-[1] bg-surface px-2 pb-1.5 pl-2.5 text-left text-[10.5px] font-semibold tracking-wide text-subtle uppercase">
                  {groupBy === "topic" ? "Topic" : "Language"}
                </th>
                <th className={th}>{fb ? "Harmless" : "Attacks"}</th>
                {controls.map((c) => (
                  <th
                    key={c.control}
                    className={`${th} border-b-2 ${c.control === "edge" ? "border-b-cf-red/60" : "border-b-cf-amber/60"}`}
                  >
                    {c.label}
                  </th>
                ))}
                <th className={th}>{fb ? "Blocked by any" : "Missed by all"}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((row) => (
                <Row key={row.key} row={row} fb={fb} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {bench.rows.length > ROWS_COLLAPSED && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="mt-2 text-[12px] font-semibold text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {expanded ? "Show fewer" : `Show all ${bench.rows.length} ${nouns}`}
        </button>
      )}

      <p className="mt-2 text-[10.5px] leading-relaxed text-subtle">
        <Trophy size={10} aria-hidden className="mr-0.5 inline text-cf-green" /> {fb ? "fewest" : "best"} and{" "}
        <ArrowDown size={10} aria-hidden className="mr-0.5 inline" /> {fb ? "most false blocks" : "lowest"} are marked only
        between controls that scanned the same prompts in that row, and only over {BENCHMARK_MIN_N}+ of them — the edge sees
        every prompt while a guardrail sees only what the edge let through, so those are different tests. Untinted numbers
        are too few to rank.{" "}
        {groupBy === "topic"
          ? "Topic is the scan category, or the goal column of an uploaded CSV."
          : "Language is read from the prompt's writing system, not declared: Thai script is Thai, but Latin letters could be English or any Latin-script language. Prompts under 80% one script count as mixed."}
      </p>
    </div>
  );
}
