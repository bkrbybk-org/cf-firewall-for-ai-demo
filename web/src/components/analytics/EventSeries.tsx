// Time-series chart shared by all three Analytics tabs, plus the series
// definitions that configure it.
import { useState } from "react";

// `cls` fills the area wash, `stroke` draws the 2px line, `dot` keys the legend
// and tooltip. Colors are the app's existing status palette (block/error = red,
// log = amber, guardrails = purple, allowed/hit = green) — status semantics, not
// a categorical ramp, so they are reserved and never reassigned per chart.
export type SeriesDef = { key: string; label: string; cls: string; stroke: string; dot: string };

// Edge tab: WAF action mix. Gateway tab: cache outcome mix.
export const SERIES: SeriesDef[] = [
  { key: "block", label: "block", cls: "fill-cf-red", stroke: "stroke-cf-red", dot: "bg-cf-red" },
  { key: "log", label: "log", cls: "fill-cf-amber", stroke: "stroke-cf-amber", dot: "bg-cf-amber" },
  { key: "other", label: "other", cls: "fill-subtle", stroke: "stroke-subtle", dot: "bg-subtle" },
];
export const GW_SERIES: SeriesDef[] = [
  { key: "hit", label: "cache hit", cls: "fill-cf-green", stroke: "stroke-cf-green", dot: "bg-cf-green" },
  { key: "miss", label: "miss", cls: "fill-subtle", stroke: "stroke-subtle", dot: "bg-subtle" },
  { key: "error", label: "error / blocked", cls: "fill-cf-red", stroke: "stroke-cf-red", dot: "bg-cf-red" },
];
// Prompt log: what happened to each logged prompt.
export const PLOG_SERIES: SeriesDef[] = [
  { key: "reply", label: "replied", cls: "fill-cf-green", stroke: "stroke-cf-green", dot: "bg-cf-green" },
  {
    key: "guardrails",
    label: "guardrails-blocked",
    cls: "fill-cf-purple",
    stroke: "stroke-cf-purple",
    dot: "bg-cf-purple",
  },
  { key: "error", label: "error", cls: "fill-cf-red", stroke: "stroke-cf-red", dot: "bg-cf-red" },
];

// Round an axis maximum up to a clean tick value (1/2/5 × 10ⁿ) so the y labels
// read 0/50/100 rather than 0/37/74.
function niceMax(v: number): number {
  if (v <= 5) return Math.max(1, Math.ceil(v));
  const mag = 10 ** Math.floor(Math.log10(v));
  const norm = v / mag;
  const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
  return step * mag;
}

// Line + area chart of events over time. Series-agnostic so all three tabs
// share it (edge: block/log/other · gateway: hit/miss/error · prompt log:
// reply/guardrails/error). Area carries magnitude as a 10% wash, the 2px line
// carries shape; a crosshair snaps to the nearest bucket and one tooltip reads
// out every series at that x, so the pointer never has to land on a line.
//
// Series are drawn UNSTACKED, each from its own zero baseline. Stacking these
// would be actively misleading here: the data is sparse and zero-heavy, so a
// series sitting at 0 inherits the cumulative height of the ones below it and
// paints a flat line across the top that reads as a constant nonzero value.
// The tooltip still reports the total, so nothing is lost by not stacking.
export function EventSeries({
  rows,
  bucket,
  defs,
  ariaLabel,
}: {
  rows: Record<string, number | string>[];
  bucket?: "hour" | "day";
  defs: SeriesDef[];
  ariaLabel: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const num = (r: Record<string, number | string>, k: string) => Number(r[k] ?? 0);
  const total = (r: Record<string, number | string>) => defs.reduce((n, s) => n + num(r, s.key), 0);

  const n = rows.length;
  // Unstacked, so the axis tops out at the largest single series value.
  const peak = Math.max(1, ...rows.flatMap((r) => defs.map((s) => num(r, s.key))));
  const max = niceMax(peak);
  const W = 720;
  // Wider aspect ratio than a typical chart on purpose: the page now runs up
  // to 1600px wide, and at the old 720:168 ratio this chart rendered taller
  // than every other card on the page since it's the only one that scales
  // its height with container width instead of sizing to its content.
  const H = 90;
  const padL = 34;
  const padR = 8;
  const padT = 10;
  const padB = 24;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;
  const baseY = padT + plotH;

  // A single bucket has no line to draw, so it sits centered as a marker.
  const xAt = (i: number) => (n <= 1 ? padL + plotW / 2 : padL + (i / (n - 1)) * plotW);
  const yAt = (v: number) => padT + plotH * (1 - v / max);

  // Gridline values, deduped after rounding so a small max (e.g. 1) doesn't
  // print "1 / 1 / 0" from a fractional midpoint.
  const ticks = [...new Set([0, max / 2, max].map((v) => Math.round(v)))];

  const fmtBucket = (iso: string) =>
    bucket === "day"
      ? new Date(iso).toLocaleDateString("en-GB", { month: "short", day: "numeric" })
      : new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });

  // Label ~6 ticks max, always including the last bucket.
  const labelEvery = Math.max(1, Math.ceil(n / 6));
  // Markers would be noise on a dense series; show them only when sparse.
  const showMarkers = n > 1 && n <= 24;

  function onMove(e: React.PointerEvent<SVGSVGElement>) {
    if (n === 0) return;
    const box = e.currentTarget.getBoundingClientRect();
    const vx = ((e.clientX - box.left) / box.width) * W; // client px → viewBox units
    const frac = (vx - padL) / (plotW || 1);
    setHover(Math.max(0, Math.min(n - 1, Math.round(frac * (n - 1)))));
  }

  const hoveredRow = hover != null ? rows[hover] : null;

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full touch-none"
        role="img"
        aria-label={ariaLabel}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
      >
        {/* Gridlines — hairline, solid, recessive. */}
        {ticks.map((v) => (
          <g key={v}>
            <line
              x1={padL}
              x2={W - padR}
              y1={yAt(v)}
              y2={yAt(v)}
              className={v === 0 ? "stroke-line-strong" : "stroke-line"}
              strokeWidth="1"
            />
            <text x={padL - 6} y={yAt(v) + 3} textAnchor="end" className="fill-subtle text-[9px] tabular-nums">
              {v.toLocaleString()}
            </text>
          </g>
        ))}

        {/* Area wash, drawn first so lines and markers sit on top. */}
        {n > 1 &&
          defs.map((s) => (
            <polygon
              key={s.key}
              points={[
                ...rows.map((r, i) => `${xAt(i)},${yAt(num(r, s.key))}`),
                `${xAt(n - 1)},${baseY}`,
                `${xAt(0)},${baseY}`,
              ].join(" ")}
              className={s.cls}
              fillOpacity={0.1}
            />
          ))}

        {/* 2px line per series. */}
        {n > 1 &&
          defs.map((s) => (
            <polyline
              key={s.key}
              points={rows.map((r, i) => `${xAt(i)},${yAt(num(r, s.key))}`).join(" ")}
              fill="none"
              className={s.stroke}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          ))}

        {/* Markers carry a surface-colored ring so they stay legible where
            series overlap. Hidden on dense series to avoid clutter. */}
        {(showMarkers || n === 1) &&
          defs.map((s) =>
            rows.map((r, i) => (
              <circle
                key={`${s.key}-${i}`}
                cx={xAt(i)}
                cy={yAt(num(r, s.key))}
                r={hover === i ? 4.5 : 3}
                className={`${s.cls} stroke-surface`}
                fillOpacity={1}
                strokeWidth="2"
              />
            )),
          )}

        {/* Crosshair: readers aim at a bucket, not at a 2px line. */}
        {hover != null && (
          <line
            x1={xAt(hover)}
            x2={xAt(hover)}
            y1={padT}
            y2={baseY}
            className="stroke-line-strong"
            strokeWidth="1"
          />
        )}

        {/* X labels. */}
        {rows.map((r, i) =>
          i % labelEvery === 0 || i === n - 1 ? (
            <text
              key={String(r.t)}
              x={xAt(i)}
              y={H - 6}
              textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
              className="fill-subtle text-[9px]"
            >
              {fmtBucket(String(r.t))}
            </text>
          ) : null,
        )}
      </svg>

      {/* One tooltip, every series. Value leads, label follows. */}
      {hoveredRow && (
        <div
          className="pointer-events-none absolute top-1 z-10 min-w-36 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[11px] shadow-lg"
          style={{
            left: `${(xAt(hover!) / W) * 100}%`,
            transform: `translateX(${xAt(hover!) > W / 2 ? "calc(-100% - 10px)" : "10px"})`,
          }}
        >
          <div className="mb-1 font-semibold text-text">{fmtBucket(String(hoveredRow.t))}</div>
          {defs.map((s) => (
            <div key={s.key} className="flex items-center gap-2">
              <span className={`h-0.5 w-3 shrink-0 rounded-full ${s.dot}`} />
              <span className="font-mono font-semibold text-text tabular-nums">{num(hoveredRow, s.key)}</span>
              <span className="text-muted">{s.label}</span>
            </div>
          ))}
          <div className="mt-1 border-t border-line pt-1 text-muted">
            <span className="font-mono font-semibold text-text tabular-nums">{total(hoveredRow)}</span> total
          </div>
        </div>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted">
        {defs.map((s) => (
          <span key={s.key} className="flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-full ${s.dot}`} /> {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

