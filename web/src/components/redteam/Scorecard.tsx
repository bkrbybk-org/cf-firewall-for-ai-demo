// Scorecard for a red-team run: headline tiles + severity/category breakdown
// bars. Reuses the analytics primitives so it reads as one system with the rest
// of the app. The headline is "reached the model" (edge miss rate), never ASR —
// see redteam.ts for why the two are different axes.
import { ShieldX, ShieldCheck, TriangleAlert, CircleSlash } from "lucide-react";
import { Tile } from "../analytics/primitives";
import { SEVERITY_BAR, type RtBreakdownRow, type RtScore, type RtSeverity } from "../../lib/redteam";

function Bars({ title, rows, colorOf }: { title: string; rows: RtBreakdownRow[]; colorOf: (key: string) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.total));
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">{title}</h2>
      <div className="mt-0.5 text-[11.5px] text-muted">reached the model / scored attempts per group</div>
      <div className="mt-3 flex flex-col gap-2.5">
        {rows.map((r) => {
          const pct = r.scored === 0 ? 0 : Math.round((r.reached / r.scored) * 100);
          return (
            <div key={r.key} title={`${r.key}: ${r.reached}/${r.scored} reached the model`}>
              <div className="mb-1 flex items-baseline gap-2 text-[12px]">
                <span className="truncate text-text">{r.key}</span>
                <span className="ml-auto font-mono text-[11.5px] text-muted tabular-nums">
                  {r.reached}/{r.scored}
                  <span className="ml-1 text-subtle">({pct}%)</span>
                </span>
              </div>
              {/* Track width encodes how many attacks are in the group; the fill
                  encodes how many reached the model. */}
              <div className="h-2 overflow-hidden rounded-full bg-surface-2" style={{ width: `${(r.total / max) * 100}%` }}>
                <div
                  className={`h-full rounded-full ${colorOf(r.key)}`}
                  style={{ width: `${r.total === 0 ? 0 : (r.reached / r.total) * 100}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function Scorecard({
  score,
  bySeverityRows,
  byCategoryRows,
}: {
  score: RtScore;
  bySeverityRows: RtBreakdownRow[];
  byCategoryRows: RtBreakdownRow[];
}) {
  return (
    <>
      <div className="flex flex-wrap gap-3">
        <Tile
          label={`reached the model (of ${score.scored} scored)`}
          value={`${score.reachedPct}%`}
          icon={<ShieldX size={16} className="text-cf-red" />}
          tone="border-cf-red/40 bg-cf-red/10"
        />
        <Tile
          label="stopped at the edge"
          value={score.stopped}
          icon={<ShieldCheck size={16} className="text-cf-green" />}
          tone="border-cf-green/40 bg-cf-green/10"
        />
        <Tile
          label="reached the model"
          value={score.reached}
          icon={<TriangleAlert size={16} className="text-cf-amber" />}
          tone="border-cf-amber/40 bg-cf-amber/10"
        />
        <Tile
          label="excluded (denied / pending / error)"
          value={score.denied + score.pending + score.error + score.guardrails}
          icon={<CircleSlash size={16} className="text-subtle" />}
          tone="border-line bg-surface-2"
        />
      </div>

      {(score.denied > 0 || score.guardrails > 0 || score.pending > 0 || score.error > 0) && (
        <div className="rounded-xl border border-line bg-surface-2 px-3.5 py-2.5 text-[11.5px] text-muted">
          Excluded from the headline: {score.denied} denied (stopped by a non-WAF layer such as Access or rate limiting),{" "}
          {score.guardrails} AI Gateway Guardrails block{score.guardrails === 1 ? "" : "s"}, {score.pending} with no edge
          verdict yet, {score.error} failed request{score.error === 1 ? "" : "s"}. These are shown but never folded into
          the percentage.
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Bars title="By severity" rows={bySeverityRows} colorOf={(k) => SEVERITY_BAR[k as RtSeverity]} />
        <Bars title="By category" rows={byCategoryRows} colorOf={() => "bg-cf-red/70"} />
      </div>
    </>
  );
}
