// The benchmark half of "Controls compared": the same per-control scores split by
// topic or by language, as a grid — who is good at what. Renders the
// VendorBenchmark from lib/vendorBenchmark.ts and computes no score itself; that
// file's header explains when a row ranks its controls and when it refuses to.
import { useMemo, useState } from "react";
import { ArrowDown, Trophy } from "lucide-react";
import type { RedTeamAttack, RtRunResult } from "../../lib/redteam";
import {
  BENCHMARK_MIN_N,
  vendorBenchmark,
  type BenchmarkCell,
  type BenchmarkGroupBy,
  type BenchmarkRow,
} from "../../lib/vendorBenchmark";
import type { ControlScore } from "../../lib/vendorScorecard";

// Enough rows to read at a glance; a ThaiSafetyBench sample has ~20 topics.
const ROWS_COLLAPSED = 10;

const GROUPS: { id: BenchmarkGroupBy; label: string }[] = [
  { id: "topic", label: "Topic" },
  { id: "language", label: "Language" },
];

function Cell({ c, ranked }: { c: BenchmarkCell; ranked: boolean }) {
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
    `${c.caught} of ${c.scanned} scanned caught` +
    (c.alerts ? ` · ${c.alerts} alerted only` : "") +
    (c.errors ? ` · ${c.errors} could not be consulted` : "") +
    (c.notSeen ? ` · ${c.notSeen} never reached it` : "") +
    (small ? ` · fewer than ${BENCHMARK_MIN_N} scanned — too few to rank` : !ranked ? " · scanned different prompts from the ranked controls — not ranked" : "");
  // Heat is a single green ramp on catch rate. The number carries the meaning; the
  // tint only makes a column of strengths and gaps visible at a glance. A sample
  // too small to rank gets no tint, so it never looks like a result.
  const tint = small ? undefined : `color-mix(in srgb, var(--green) ${Math.round(c.catchPct * 0.3)}%, transparent)`;
  return (
    <td className={base} style={{ backgroundColor: tint }} title={title}>
      <span className="inline-flex items-center justify-end gap-1">
        {c.rank === "best" && <Trophy size={11} aria-hidden className="shrink-0 text-cf-green" />}
        {c.rank === "worst" && <ArrowDown size={11} aria-hidden className="shrink-0 text-muted" />}
        <span className={c.rank === "best" ? "font-bold text-text" : small ? "text-subtle" : "text-text"}>{c.catchPct}%</span>
        {c.rank && <span className="sr-only">{c.rank === "best" ? "(best in this row)" : "(lowest in this row)"}</span>}
      </span>
      <span className={`block text-[10px] ${small ? "text-subtle" : "text-muted"}`}>
        {c.caught}/{c.scanned}
      </span>
    </td>
  );
}

function Row({ row }: { row: BenchmarkRow }) {
  return (
    <tr className="border-t border-line">
      <td className="sticky left-0 z-[1] max-w-[18rem] min-w-[8rem] bg-surface py-1.5 pr-2 pl-2.5 text-[12px] leading-snug text-text">
        <span className="line-clamp-2 break-words" title={row.key}>
          {row.key}
        </span>
      </td>
      <td className="px-2 py-1.5 text-right font-mono text-[11.5px] text-muted tabular-nums">{row.attacks}</td>
      {row.cells.map((c) => (
        <Cell key={c.control} c={c} ranked={row.ranked.includes(c.control)} />
      ))}
      <td
        className={`px-2 py-1.5 text-right font-mono text-[11.5px] tabular-nums ${row.missedByAll > 0 ? "font-semibold text-text" : "text-muted"}`}
        title="scanned by at least one control, caught by none"
      >
        {row.missedByAll}
      </td>
    </tr>
  );
}

export function VendorBenchmark({
  corpus,
  results,
  controls,
  labels,
}: {
  corpus: RedTeamAttack[];
  results: Map<string, RtRunResult>;
  controls: ControlScore[];
  labels: Record<string, string>;
}) {
  const [groupBy, setGroupBy] = useState<BenchmarkGroupBy>("topic");
  const [expanded, setExpanded] = useState(false);
  const ids = useMemo(() => controls.map((c) => c.control), [controls]);
  const bench = useMemo(() => vendorBenchmark(corpus, results, groupBy, ids, labels), [corpus, results, groupBy, ids, labels]);
  const noun = groupBy === "topic" ? "topic" : "language";
  const shown = expanded ? bench.rows : bench.rows.slice(0, ROWS_COLLAPSED);
  const winners = bench.wins.filter((w) => w.wins > 0);
  const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";

  return (
    <div className="mt-4 border-t border-line pt-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h3 className="text-[12.5px] font-bold text-text">Benchmark by</h3>
        <div role="group" aria-label="Benchmark grouping" className="inline-flex overflow-hidden rounded-full border border-line">
          {GROUPS.map((g) => (
            <button
              key={g.id}
              type="button"
              aria-pressed={groupBy === g.id}
              onClick={() => {
                setGroupBy(g.id);
                setExpanded(false);
              }}
              className={`px-3 py-1 text-[12px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                groupBy === g.id ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {g.label}
            </button>
          ))}
        </div>
        <span className="text-[11.5px] text-muted">catch rate per control · each scored only on what it scanned</span>
      </div>

      {/* The headline: who won the most rows that were a fair contest. */}
      <p className="mt-2 text-[12px] leading-relaxed text-muted">
        {bench.rankedRows === 0 ? (
          <>
            No {noun} had {BENCHMARK_MIN_N}+ prompts that two controls both scanned, so nothing is ranked yet — run more
            attacks, ideally in Parallel with Guardrail-only on.
          </>
        ) : winners.length === 0 ? (
          <>
            Every control tied in all {bench.rankedRows} {noun === "topic" ? "topics" : "languages"} that could be compared.
          </>
        ) : (
          <>
            <span className="font-semibold text-text">Best in most {noun === "topic" ? "topics" : "languages"}:</span>{" "}
            {winners.map((w, i) => (
              <span key={w.control}>
                {i > 0 && " · "}
                <span className="text-text">{w.label}</span> <span className="font-mono tabular-nums">{w.wins}</span>
              </span>
            ))}{" "}
            — of {bench.rankedRows} {bench.rankedRows === 1 ? noun : noun === "topic" ? "topics" : "languages"} compared like for
            like (ties count for each).
          </>
        )}
      </p>

      {/* relative: the cells' sr-only text must not escape this scroll box (CLAUDE.md, scroll containers). The
          topic column is sticky so a row keeps its name while the controls scroll on a phone. */}
      <div className="relative mt-2 overflow-x-auto">
        <table className="w-full min-w-[560px] border-collapse">
          <thead>
            <tr>
              <th className="sticky left-0 z-[1] bg-surface px-2 pb-1.5 pl-2.5 text-left text-[10.5px] font-semibold tracking-wide text-subtle uppercase">
                {groupBy === "topic" ? "Topic" : "Language"}
              </th>
              <th className={th}>Attacks</th>
              {controls.map((c) => (
                <th
                  key={c.control}
                  className={`${th} border-b-2 ${c.control === "edge" ? "border-b-cf-red/60" : "border-b-cf-amber/60"}`}
                >
                  {c.label}
                </th>
              ))}
              <th className={th}>Missed by all</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <Row key={row.key} row={row} />
            ))}
          </tbody>
        </table>
      </div>
      {bench.rows.length > ROWS_COLLAPSED && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="mt-2 text-[12px] font-semibold text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {expanded ? "Show fewer" : `Show all ${bench.rows.length} ${noun === "topic" ? "topics" : "languages"}`}
        </button>
      )}

      <p className="mt-2 text-[10.5px] leading-relaxed text-subtle">
        <Trophy size={10} aria-hidden className="mr-0.5 inline text-cf-green" /> best and{" "}
        <ArrowDown size={10} aria-hidden className="mr-0.5 inline" /> lowest are marked only between controls that scanned the
        same prompts in that row, and only over {BENCHMARK_MIN_N}+ of them — the edge sees every prompt while a guardrail sees
        only what the edge let through, so those are different tests. Untinted numbers are too few to rank.{" "}
        {groupBy === "topic"
          ? "Topic is the scan category, or the goal column of an uploaded CSV."
          : "Language is read from the prompt's writing system, not declared: Thai script is Thai, but Latin letters could be English or any Latin-script language. Prompts under 80% one script count as mixed."}
      </p>
    </div>
  );
}
