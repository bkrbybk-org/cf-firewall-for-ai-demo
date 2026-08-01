// Layout primitives shared by every Analytics tab. Kept dependency-free so the
// tab modules can import them without pulling in chart or data-fetching code.

// Bucket width as it reads in a chart subtitle ("per 5 min"). The server picks
// the width (src/config.ts bucketFor), so every tab must be able to say what it
// got rather than assuming hourly.
export type SeriesBucket = "5m" | "hour" | "day";

export function bucketLabel(bucket: SeriesBucket | undefined): string {
  return bucket === "day" ? "day" : bucket === "5m" ? "5 min" : "hour";
}

export function Tile({
  label,
  value,
  icon,
  tone,
  // Optional secondary line: a rate ("42% of events") and/or a trend delta vs
  // the preceding window. Both are omitted rather than faked when the data
  // can't support them — see AnalyticsSummary.truncated.
  rate,
  delta,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  tone: string;
  rate?: string;
  delta?: number | null;
}) {
  const showDelta = delta != null && Number.isFinite(delta);
  return (
    <div className="flex min-w-40 flex-1 items-center gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
      <span className={`rounded-xl border p-2 ${tone}`}>{icon}</span>
      <div className="min-w-0">
        <div className="flex items-baseline gap-1.5">
          <span className="text-xl leading-tight font-bold text-text tabular-nums">{value}</span>
          {showDelta && (
            // Neutral wording: a delta is movement, not good or bad — more
            // blocks could mean more attacks or a stricter rule.
            <span
              className={`text-[11px] font-semibold tabular-nums ${
                delta! > 0 ? "text-cf-amber" : delta! < 0 ? "text-cf-blue" : "text-subtle"
              }`}
              title="vs the preceding window of the same length"
            >
              {delta! > 0 ? "▲" : delta! < 0 ? "▼" : "="}
              {delta === 0 ? "" : Math.abs(delta!)}
            </span>
          )}
        </div>
        <div className="truncate text-[11.5px] text-muted">{label}</div>
        {rate && <div className="text-[10.5px] text-subtle">{rate}</div>}
      </div>
    </div>
  );
}

export function Card({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">{title}</h2>
      {subtitle && <div className="mt-0.5 text-[11.5px] text-muted">{subtitle}</div>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

// Horizontal labeled bar list — used for top rules, the score histogram, and
// the per-model / per-topic breakdowns.
export function BarList({
  rows,
  // When set, each row becomes a button that drills into the prompt log.
  onPick,
  // Scale bars against this instead of the largest row. Lets a caller keep two
  // separate lists on a comparable scale, or exclude an outlier that would
  // otherwise flatten everything else to invisible slivers.
  scaleMax,
}: {
  rows: { name: string; sub?: string; count: number; barCls: string; hint?: string }[];
  onPick?: (row: { name: string; count: number }) => void;
  scaleMax?: number;
}) {
  const max = Math.max(1, scaleMax ?? 0, ...rows.map((r) => r.count));
  return (
    <div className="flex flex-col gap-2.5">
      {rows.map((r, i) => {
        const body = (
          <>
            <div className="mb-1 flex items-baseline gap-2 text-[12px]">
              <span className="truncate text-text">{r.name}</span>
              {r.sub && <span className="shrink-0 text-[10.5px] text-subtle">{r.sub}</span>}
              <span className="ml-auto font-mono text-[11.5px] text-muted tabular-nums">{r.count}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-surface-2">
              <div
                className={`h-full rounded-full ${r.barCls}`}
                // A non-zero count always paints at least a hairline, so "some"
                // never renders identically to "none".
                style={{ width: r.count === 0 ? 0 : `${Math.max(1.5, (r.count / max) * 100)}%` }}
              />
            </div>
          </>
        );
        const title = r.hint ?? `${r.name}: ${r.count}`;
        return onPick ? (
          <button
            key={i}
            type="button"
            title={title}
            onClick={() => onPick({ name: r.name, count: r.count })}
            className="-mx-1.5 rounded-lg px-1.5 py-1 text-left transition hover:bg-surface-hover"
          >
            {body}
          </button>
        ) : (
          <div key={i} title={title}>
            {body}
          </div>
        );
      })}
    </div>
  );
}
