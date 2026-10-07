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
  rowAttacks,
  vendorBenchmark,
  type BenchmarkCell,
  type BenchmarkGroupBy,
  type BenchmarkMetric,
  type BenchmarkRow,
  type RowAttack,
} from "../../lib/vendorBenchmark";
import { fmtInterval } from "../../lib/stats";
import type { ControlScore, Verdict } from "../../lib/vendorScorecard";

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

function Cell({
  c,
  ranked,
  fb,
  selected,
  onSelect,
}: {
  c: BenchmarkCell;
  ranked: boolean;
  fb: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
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
    (c.ci ? ` · 95% interval ${fmtInterval(c.ci)}` : "") +
    (small ? ` · fewer than ${BENCHMARK_MIN_N} scanned — too few to rank` : !ranked ? " · scanned different prompts from the ranked controls — not ranked" : "") +
    " · click to see the prompts";
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
    <td className={`${base} p-0`} style={{ backgroundColor: tint }}>
      {/* A button: the cell opens the prompts behind it (open item D). */}
      <button
        type="button"
        onClick={onSelect}
        aria-pressed={selected}
        title={title}
        className={`block w-full px-2 py-1.5 text-right focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset ${
          selected ? "ring-2 ring-accent ring-inset" : "hover:bg-surface-2/60"
        }`}
      >
        <span className="inline-flex items-center justify-end gap-1">
          {c.rank === "best" && <Trophy size={11} aria-hidden className="shrink-0 text-cf-green" />}
          {c.rank === "worst" && <ArrowDown size={11} aria-hidden className="shrink-0 text-muted" />}
          <span className={c.rank === "best" ? "font-bold text-text" : small ? "text-subtle" : "text-text"}>{c.catchPct}%</span>
          {c.rank && <span className="sr-only">{srRank}</span>}
        </span>
        <span className={`block text-[10px] ${small ? "text-subtle" : "text-muted"}`}>
          {c.caught}/{c.scanned}
        </span>
      </button>
    </td>
  );
}

function Row({
  row,
  fb,
  selected,
  onSelect,
}: {
  row: BenchmarkRow;
  fb: boolean;
  selected: string | null; // the selected control in THIS row, if any
  onSelect: (control: string) => void;
}) {
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
        <Cell
          key={c.control}
          c={c}
          ranked={row.ranked.includes(c.control)}
          fb={fb}
          selected={selected === c.control}
          onSelect={() => onSelect(c.control)}
        />
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

// The prompts behind one cell (open item D), every control's verdict on each, the
// selected control's misses first — "what slipped through" is the question a cell
// raises. On harmless rows the order flips: its false blocks first.
const VERDICT_TEXT = (v: Verdict, fb: boolean) =>
  ({
    caught: fb ? "blocked" : "caught",
    missed: fb ? "passed" : "missed",
    alerts: "alerted",
    error: "error",
    notSeen: "not seen",
    notRun: "not run",
  })[v];

function verdictTone(v: Verdict, fb: boolean): string {
  const good = fb ? v === "missed" : v === "caught";
  const bad = fb ? v === "caught" : v === "missed";
  if (good) return "border-cf-green/60 text-cf-green";
  if (bad) return "border-cf-red/50 text-cf-red";
  if (v === "alerts") return "border-line-strong text-text";
  return "border-dashed border-line-strong text-subtle"; // error / not seen / not run: not a verdict
}

function CellPrompts({
  sel,
  rows,
  controls,
  fb,
  onClose,
}: {
  sel: { key: string; control: string };
  rows: RowAttack[];
  controls: ControlScore[];
  fb: boolean;
  onClose: () => void;
}) {
  const order: Record<Verdict, number> = fb
    ? { caught: 0, alerts: 1, missed: 2, error: 3, notRun: 4, notSeen: 5 }
    : { missed: 0, alerts: 1, caught: 2, error: 3, notRun: 4, notSeen: 5 };
  const sorted = [...rows].sort((a, b) => order[a.verdicts[sel.control]] - order[b.verdicts[sel.control]]);
  const label = controls.find((c) => c.control === sel.control)?.label ?? sel.control;
  const counts = new Map<Verdict, number>();
  for (const r of rows) counts.set(r.verdicts[sel.control], (counts.get(r.verdicts[sel.control]) ?? 0) + 1);
  return (
    <div className="mt-3 rounded-xl border border-line bg-surface-2/50 p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="text-[12px] text-text">
          <span className="font-semibold">{sel.key}</span> · {label}:{" "}
          <span className="text-muted">
            {[...counts.entries()]
              .sort((a, b) => order[a[0]] - order[b[0]])
              .map(([v, n]) => `${n} ${VERDICT_TEXT(v, fb)}`)
              .join(" · ")}
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-[11.5px] font-semibold text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Close
        </button>
      </div>
      {/* relative: this scroll box contains its sr-only text (CLAUDE.md, scroll containers). */}
      <div className="relative mt-2 max-h-80 overflow-auto">
        <table className="w-full min-w-[520px] border-collapse text-[11.5px]">
          <thead>
            <tr className="text-[10px] tracking-wide text-subtle uppercase">
              <th className="px-2 pb-1 text-left font-semibold">Prompt</th>
              {controls.map((c) => (
                <th
                  key={c.control}
                  className={`px-2 pb-1 text-right font-semibold whitespace-nowrap ${c.control === sel.control ? "text-accent" : ""}`}
                >
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <tr key={r.id} className="border-t border-line align-top">
                <td className="max-w-0 px-2 py-1 text-text">
                  <div className="truncate" title={r.prompt}>
                    {r.prompt || <span className="text-subtle">(no preview)</span>}
                  </div>
                </td>
                {controls.map((c) => (
                  <td key={c.control} className="px-2 py-1 text-right whitespace-nowrap">
                    <span
                      className={`inline-block rounded-full border px-1.5 py-px text-[10px] font-semibold ${verdictTone(r.verdicts[c.control], fb)}`}
                    >
                      {VERDICT_TEXT(r.verdicts[c.control], fb)}
                    </span>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
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
  // The cell whose prompts are open below the grid (open item D); cleared whenever
  // the grid's rows change meaning (grouping or metric).
  const [sel, setSel] = useState<{ key: string; control: string } | null>(null);
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
            setSel(null);
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
              setSel(null);
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
            No control led by more than the margin of error in{" "}
            {bench.rankedRows === 1 ? `the one ${noun}` : `any of the ${bench.rankedRows} ${nouns}`} that could be compared
            — run more prompts to separate them.
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
                <Row
                  key={row.key}
                  row={row}
                  fb={fb}
                  selected={sel?.key === row.key ? sel.control : null}
                  onSelect={(control) =>
                    setSel((s) => (s?.key === row.key && s.control === control ? null : { key: row.key, control }))
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {sel && (
        <CellPrompts
          sel={sel}
          rows={rowAttacks(fb ? benignCorpus : corpus, results, groupBy, sel.key, ids)}
          controls={controls}
          fb={fb}
          onClose={() => setSel(null)}
        />
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
        are too few to rank. A marker also needs a clear lead: its 95% interval (in each cell's tooltip) must not overlap
        any other ranked control's, so a gap that could be chance marks nothing. Click a cell to see its prompts.{" "}
        {groupBy === "topic"
          ? "Topic is the scan category, or the goal column of an uploaded CSV."
          : "Language is read from the prompt's writing system, not declared: Thai script is Thai, but Latin letters could be English or any Latin-script language. Prompts under 80% one script count as mixed."}
      </p>
    </div>
  );
}
