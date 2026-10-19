// Catch rate and false-block rate per scheduled run, per vendor (2026-10-19). The re-run sends the same labelled prompts
// every 6 hours, so a line moving is the VENDOR changing — Lakera's step-up on 2026-10-16 is the case it was built for.
//
// Form: small multiples (one per vendor and direction), two series each on one 0–100% axis — never two axes. Colour by
// series identity from the validated chart palette (--blue catch rate, --purple false-block rate, ΔE 15.2 apart), with a
// legend and the latest values written beside each title, so identity is never colour alone. Every point has a hover
// title with its counts ("5 of 6"); a run without verdicts for a label is a GAP in that line, never a 0% point. A table
// view gives the same numbers as text.
import { useState } from "react";
import type { ExternalGuardrailProvider, RunPoint } from "../../lib/types";
import { providerLabel } from "../../lib/guardrailView";

type Series = { provider: ExternalGuardrailProvider; dir: "prompt" | "reply"; runs: RunPoint[] };

const W = 280;
const H = 100;
const PAD = { l: 30, r: 8, t: 8, b: 18 };
const RUN_MS = 6 * 3_600_000;
const SERIES = [
  { key: "attack", label: "catch rate", sub: "attacks blocked", color: "var(--blue)" },
  { key: "benign", label: "false-block rate", sub: "harmless blocked", color: "var(--purple)" },
] as const;

const pct = (b: number, v: number) => (v > 0 ? Math.round((b / v) * 100) : null);
const when = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function Multiple({ s, from, to, n }: { s: Series; from: number; to: number; n: (v: number) => string }) {
  const span = Math.max(1, to - from);
  const x = (iso: string) => PAD.l + ((Date.parse(iso) - from) / span) * (W - PAD.l - PAD.r);
  const y = (r: number) => PAD.t + (1 - r) * (H - PAD.t - PAD.b);
  // The newest run WITH verdicts — dated, because a vendor that has been down since (Cato's 401s from 2026-10-13) would
  // otherwise show a week-old rate as "latest". More than one run behind the window's end is said outright.
  const last = s.runs[s.runs.length - 1];
  const stale = last ? to - Date.parse(last.t) > RUN_MS * 2 : false;
  const rates = SERIES.map((k) => {
    const c = last?.[k.key];
    return c && c.verdicts > 0 ? `${k.label} ${pct(c.block, c.verdicts)}% (${n(c.block)} of ${n(c.verdicts)})` : `${k.label} —`;
  }).join(" · ");
  const summary = last ? `${stale ? "no verdict since " : "run of "}${when(last.t)}: ${rates}` : rates;
  return (
    <figure className="m-0 min-w-0 rounded-xl border border-line bg-surface-2/40 p-2.5">
      <figcaption className="mb-1 flex flex-wrap items-baseline gap-x-2 text-[12px]">
        <span className="font-semibold text-text">{providerLabel(s.provider)}</span>
        {s.dir === "reply" && <span className="rounded-full border border-line px-1.5 text-[10px] text-subtle">reply</span>}
        <span className={`text-[10.5px] ${stale ? "font-semibold text-cf-amber-ink" : "text-muted"}`}>{summary}</span>
      </figcaption>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="block h-auto w-full"
        role="img"
        aria-label={`${providerLabel(s.provider)}${s.dir === "reply" ? " replies" : ""}, ${s.runs.length} runs; latest: ${summary}`}
      >
        {[0, 0.5, 1].map((g) => (
          <g key={g}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(g)} y2={y(g)} stroke="var(--line)" strokeWidth={1} />
            <text x={PAD.l - 4} y={y(g) + 3} textAnchor="end" fontSize={9} fill="var(--subtle)">
              {g * 100}%
            </text>
          </g>
        ))}
        <text x={PAD.l} y={H - 4} fontSize={9} fill="var(--subtle)">
          {when(new Date(from).toISOString())}
        </text>
        <text x={W - PAD.r} y={H - 4} textAnchor="end" fontSize={9} fill="var(--subtle)">
          {when(new Date(to).toISOString())}
        </text>
        {SERIES.map((k) => {
          // Break the line where a run is missing or has no verdict for this label: a gap, never a 0% point.
          const pts = s.runs.map((r) => ({ t: r.t, c: r[k.key] }));
          const segs: string[] = [];
          let cur: string[] = [];
          let prevT = -Infinity;
          for (const p of pts) {
            const ok = p.c.verdicts > 0;
            const t = Date.parse(p.t);
            if (!ok || t - prevT > RUN_MS * 1.5) {
              if (cur.length > 1) segs.push(cur.join(" "));
              cur = [];
            }
            if (ok) cur.push(`${x(p.t).toFixed(1)},${y(p.c.block / p.c.verdicts).toFixed(1)}`);
            prevT = ok ? t : -Infinity;
          }
          if (cur.length > 1) segs.push(cur.join(" "));
          return (
            <g key={k.key}>
              {segs.map((d, i) => (
                <polyline key={i} points={d} fill="none" stroke={k.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              ))}
              {pts
                .filter((p) => p.c.verdicts > 0)
                .map((p) => (
                  <circle key={p.t} cx={x(p.t)} cy={y(p.c.block / p.c.verdicts)} r={3.5} fill={k.color} stroke="var(--surface)" strokeWidth={1.5}>
                    <title>
                      {`${when(p.t)} run · ${k.label}: ${pct(p.c.block, p.c.verdicts)}% — ${n(p.c.block)} of ${n(p.c.verdicts)} ${
                        k.key === "attack" ? "attacks" : "harmless"
                      } blocked`}
                    </title>
                  </circle>
                ))}
            </g>
          );
        })}
      </svg>
    </figure>
  );
}

export function RunTrend({ series, since, until, n }: { series: Series[]; since: string; until: string; n: (v: number) => string }) {
  const [table, setTable] = useState(false);
  const from = Date.parse(since);
  const to = Date.parse(until);
  return (
    <>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted">
        {SERIES.map((k) => (
          <span key={k.key} className="inline-flex items-center gap-1.5">
            <svg width="18" height="8" aria-hidden>
              <line x1="1" x2="17" y1="4" y2="4" stroke={k.color} strokeWidth="2" strokeLinecap="round" />
              <circle cx="9" cy="4" r="3" fill={k.color} />
            </svg>
            <b className="text-text">{k.label}</b> ({k.sub})
          </span>
        ))}
        <span className="text-subtle">one point per scheduled run · a gap is a run with no verdict, not 0%</span>
        <button
          type="button"
          onClick={() => setTable((v) => !v)}
          className="ml-auto rounded-md border border-line bg-surface px-2 py-0.5 text-[11px] text-muted transition hover:text-text"
        >
          {table ? "Show charts" : "Show data"}
        </button>
      </div>
      {table ? (
        <div className="relative max-h-[420px] overflow-auto">
          <table className="w-full min-w-[520px] border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-line text-left text-[11px] text-subtle">
                <th className="py-1.5 pr-3 font-semibold">Vendor</th>
                <th className="py-1.5 pr-3 font-semibold">Run</th>
                <th className="py-1.5 pr-3 font-semibold">catch rate</th>
                <th className="py-1.5 font-semibold">false-block rate</th>
              </tr>
            </thead>
            <tbody>
              {series.flatMap((s) =>
                [...s.runs].reverse().map((r) => (
                  <tr key={`${s.provider}|${s.dir}|${r.t}`} className="border-b border-line/60 last:border-0">
                    <td className="py-1 pr-3">
                      {providerLabel(s.provider)}
                      {s.dir === "reply" ? " · reply" : ""}
                    </td>
                    <td className="py-1 pr-3 font-mono text-[11px] text-muted">{when(r.t)}</td>
                    {(["attack", "benign"] as const).map((k) => (
                      <td key={k} className="py-1 pr-3 font-mono tabular-nums">
                        {r[k].verdicts > 0 ? `${pct(r[k].block, r[k].verdicts)}% (${n(r[k].block)} of ${n(r[k].verdicts)})` : "—"}
                      </td>
                    ))}
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
          {series.map((s) => (
            <Multiple key={`${s.provider}|${s.dir}`} s={s} from={from} to={to} n={n} />
          ))}
        </div>
      )}
    </>
  );
}
