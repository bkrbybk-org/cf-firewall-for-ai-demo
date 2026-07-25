// Layout primitives shared by every Analytics tab. Kept dependency-free so the
// tab modules can import them without pulling in chart or data-fetching code.

export function Tile({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  tone: string;
}) {
  return (
    <div className="flex min-w-40 flex-1 items-center gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
      <span className={`rounded-xl border p-2 ${tone}`}>{icon}</span>
      <div>
        <div className="text-xl leading-tight font-bold text-text tabular-nums">{value}</div>
        <div className="text-[11.5px] text-muted">{label}</div>
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
}: {
  rows: { name: string; sub?: string; count: number; barCls: string }[];
}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <div className="flex flex-col gap-2.5">
      {rows.map((r, i) => (
        <div key={i} title={`${r.name}: ${r.count}`}>
          <div className="mb-1 flex items-baseline gap-2 text-[12px]">
            <span className="truncate text-text">{r.name}</span>
            {r.sub && <span className="shrink-0 text-[10.5px] text-subtle">{r.sub}</span>}
            <span className="ml-auto font-mono text-[11.5px] text-muted tabular-nums">{r.count}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-surface-2">
            <div className={`h-full rounded-full ${r.barCls}`} style={{ width: `${(r.count / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}
