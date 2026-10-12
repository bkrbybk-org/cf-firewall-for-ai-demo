// External guardrails tab: what each third-party vendor decided, read live from the Analytics Engine dataset the
// Worker writes one data point to per vendor per check (src/guardrailLog.ts → src/guardrailAnalytics.ts).
//
// The honesty rules travel with the numbers: "≈" when Analytics Engine sampled rows (counts are estimates), "≥"
// when the read hit its row cap (counts are a floor), "—" for a latency nobody measured — never 0 ms — and every
// card states its window and which traffic it covers.
import { AlertTriangle, Download, ShieldAlert, ShieldCheck, ShieldX, Split } from "lucide-react";
import { bucketLabel, Card, Tile } from "./primitives";
import { EventSeries, type SeriesDef } from "./EventSeries";
import { detectionLabel, providerFullLabel, providerLabel } from "../../lib/guardrailView";
import { downloadFile } from "../../lib/export";
import { buildGuardrailReport, guardrailReportFilename, guardrailReportToMarkdown } from "../../lib/guardrailReport";
import type { GuardrailAnalytics, GuardrailVendorStats } from "../../lib/types";
import { labelledRows, type RateCell } from "../../lib/falseBlocks";

// The verdict palette the chat card uses: block red, allow with alerts amber, clean allow green; "no verdict"
// grey, because an error is not a decision either way.
export const GUARDRAIL_SERIES: SeriesDef[] = [
  { key: "block", label: "block", cls: "fill-cf-red", stroke: "stroke-cf-red", dot: "bg-cf-red" },
  { key: "alerts", label: "allow with alerts", cls: "fill-cf-amber", stroke: "stroke-cf-amber", dot: "bg-cf-amber" },
  { key: "allow", label: "allow", cls: "fill-cf-green", stroke: "stroke-cf-green", dot: "bg-cf-green" },
  { key: "error", label: "no verdict", cls: "fill-subtle", stroke: "stroke-subtle", dot: "bg-subtle" },
];

export type GuardrailSource = "chat" | "redteam" | "scheduled" | "all";

export const SOURCE_LABEL: Record<GuardrailSource, string> = {
  chat: "chat traffic",
  redteam: "Red Team runs",
  scheduled: "scheduled re-runs",
  all: "all traffic",
};

// The tab as a file: exactly the numbers on screen, with the same window, traffic and honesty marks.
function download(d: GuardrailAnalytics, ext: "md" | "json") {
  const r = buildGuardrailReport(d, providerFullLabel);
  if (ext === "md") downloadFile(guardrailReportFilename(r, "md"), guardrailReportToMarkdown(r, detectionLabel), "text/markdown");
  else downloadFile(guardrailReportFilename(r, "json"), JSON.stringify(r, null, 2), "application/json");
}

function rangeLabel(h: number): string {
  return h === 1 ? "last hour" : h === 24 ? "last 24h" : h === 168 ? "last 7 days" : `last ${h}h`;
}

export function GuardrailsTab({ d, hours }: { d: GuardrailAnalytics | null; hours: number }) {
  if (d?.configured === false)
    return (
      <Card title="Not configured">
        <p className="text-sm text-muted">
          Set <code className="font-mono">CF_ANALYTICS_TOKEN</code> (needs <b>Account Analytics: Read</b>) and{" "}
          <code className="font-mono">CF_ACCOUNT_ID</code> to read the guardrail verdict dataset.
        </p>
      </Card>
    );
  if (d?.error)
    return (
      <Card title="Analytics Engine error">
        <p className="text-sm text-cf-red">{d.error}</p>
      </Card>
    );
  if (!d || !d.totals)
    return (
      <Card title="Loading…">
        <p className="text-sm text-muted">Reading guardrail verdicts…</p>
      </Card>
    );

  // "≈" estimated, "≥" a floor. Sampling wins the prefix: an estimate is not a floor.
  const mark = d.sampled ? "≈" : d.capped ? "≥" : "";
  const n = (v: number) => `${mark}${Math.round(v).toLocaleString()}`;
  // One vendor's page (Analytics → <vendor>): every number below is that vendor's alone, and the label says whose.
  const who = d.provider ? providerFullLabel(d.provider) : null;
  const window = `${who ? `${who} · ` : ""}${rangeLabel(d.rangeHours ?? hours)} · ${SOURCE_LABEL[d.source ?? "chat"]}`;
  const t = d.totals;

  return (
    <>
      {(d.sampled || d.capped || (d.rowsDropped ?? 0) > 0) && (
        <div className="flex items-start gap-2.5 rounded-xl border border-cf-amber/60 bg-cf-amber/10 px-3.5 py-2.5 text-[12px] text-text">
          <AlertTriangle size={15} className="mt-0.5 shrink-0 text-cf-amber" />
          <div>
            {d.sampled && (
              <p>
                <b>Estimated.</b> Analytics Engine sampled some verdicts in this window, so counts are estimates (≈);
                latency and disagreements cover the stored rows only.
              </p>
            )}
            {d.capped && (
              <p>
                <b>A floor, not a total.</b> The read stopped at {d.rowsRead.toLocaleString()} rows, so counts are at
                least what is shown (≥). Narrow the window for exact numbers.
              </p>
            )}
            {(d.rowsDropped ?? 0) > 0 && (
              <p>
                {d.rowsDropped} row{d.rowsDropped === 1 ? "" : "s"} of an unknown shape {d.rowsDropped === 1 ? "was" : "were"}{" "}
                skipped, not counted.
              </p>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-end gap-2 text-[11.5px]">
        <span className="mr-auto text-subtle">{window}</span>
        <button
          type="button"
          onClick={() => download(d, "md")}
          title="Download this window as a Markdown report: vendor names, outcomes and detector names only — no prompt or reply text"
          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface px-2 py-1 text-muted transition hover:text-text"
        >
          <Download size={12} /> Report (.md)
        </button>
        <button
          type="button"
          onClick={() => download(d, "json")}
          title="Download the same numbers as JSON, to re-check or chart elsewhere"
          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface px-2 py-1 text-muted transition hover:text-text"
        >
          <Download size={12} /> Data (.json)
        </button>
      </div>

      <div className="flex flex-wrap gap-3">
        <Tile
          label={`vendor verdicts · ${t.turns} turn${t.turns === 1 ? "" : "s"}`}
          value={n(t.verdicts)}
          icon={<ShieldCheck size={16} className="text-cf-blue" />}
          tone="border-cf-blue/40 bg-cf-blue/10"
        />
        <Tile
          label="blocks"
          value={n(t.block)}
          icon={<ShieldX size={16} className="text-cf-red" />}
          tone="border-cf-red/40 bg-cf-red/10"
        />
        <Tile
          label="allowed with alerts"
          value={n(t.alerts)}
          icon={<ShieldAlert size={16} className="text-cf-amber" />}
          tone="border-cf-amber/40 bg-cf-amber/10"
        />
        <Tile
          label={`no verdict · ${n(t.error)} closed / ${n(t.failedOpen)} open`}
          value={n(t.error + t.failedOpen)}
          icon={<AlertTriangle size={16} className="text-subtle" />}
          tone="border-line bg-surface-2"
        />
      </div>

      {t.verdicts === 0 && d.vendors.length === 0 ? (
        <Card title="No guardrail verdicts in this window" subtitle={window}>
          <p className="text-sm text-muted">
            {who ?? "No external guardrail"} checked {who ? "no" : "a"}{" "}
            {d.source === "redteam" ? "Red Team prompt" : d.source === "scheduled" ? "scheduled re-run prompt" : "prompt"} in the{" "}
            {rangeLabel(d.rangeHours)}.
            {d.source === "scheduled" && " The re-run sends its 12 fixed prompts every 6 hours (00, 06, 12, 18 UTC) from 2026-10-12 on, while a guardrail is enabled."}{" "}
            Verdicts are recorded from 2026-10-09 on, while at least one guardrail is enabled in Settings.
          </p>
        </Card>
      ) : (
        <>
          <Card title={who ? "Verdicts" : "Verdicts per vendor"} subtitle={`${window} · prompt and reply checks counted apart`}>
            <VendorTable vendors={d.vendors} n={n} buckets={d.series.map((p) => p.t)} bucket={d.bucket} />
          </Card>

          {d.source !== "chat" && <FalseBlocks vendors={d.vendors} n={n} window={window} />}
          {d.source === "scheduled" && (
            // #15: the point of this source. Every re-run is the same 12 prompts to every enabled vendor at once, so a
            // change from one bucket to the next is the vendor changing, not the traffic.
            <p className="text-[11.5px] leading-relaxed text-muted">
              <b className="text-text">Reading drift:</b> each re-run sends the same 12 prompts (6 attacks, 6 harmless Thai)
              to every enabled guardrail at once, with no model and no edge. A bucket's block count moving between runs is a
              vendor changing its answer to the same prompt.
            </p>
          )}

          <Card
            title="Verdicts over time"
            subtitle={`per ${bucketLabel(d.bucket)} · ${who ? "its" : "every vendor's"} verdicts, by outcome · ${window}`}
          >
            <EventSeries rows={d.series} bucket={d.bucket} defs={GUARDRAIL_SERIES} ariaLabel="External guardrail verdicts over time" />
          </Card>

          <Card
            title={who ? `Where ${who} and another vendor disagreed` : "Where the vendors disagreed"}
            subtitle={`turns one vendor blocked and another allowed · ${d.disagreements.count} in the ${rangeLabel(d.rangeHours)}${
              d.sampled ? " (stored rows only)" : ""
            }`}
          >
            {d.disagreements.count === 0 ? (
              <p className="text-sm text-muted">
                None: every turn checked by two or more vendors got the same verdict from each (errors are not counted as
                verdicts).
              </p>
            ) : (
              <ul className="flex flex-col gap-2">
                {d.disagreements.latest.map((x) => (
                  <li key={`${x.ray}|${x.dir}`} className="flex flex-wrap items-center gap-2 text-[12px]">
                    <Split size={13} className="shrink-0 text-subtle" aria-hidden />
                    <span className="font-mono text-[11.5px] text-muted" title="Cloudflare ray — the same id as the edge event and the prompt log">
                      {x.ray}
                    </span>
                    <span className="rounded-full border border-line px-1.5 text-[10.5px] text-subtle">{x.dir}</span>
                    <span className="text-subtle">{new Date(x.ts).toLocaleString()}</span>
                    {x.verdicts.map((v) => (
                      <span
                        key={v.provider}
                        className={`rounded-full border px-2 py-0.5 text-[10.5px] font-bold ${
                          v.outcome === "block"
                            ? "border-cf-red/50 bg-cf-red/10 text-cf-red"
                            : v.alerts
                              ? "border-cf-amber/60 bg-cf-amber/10 text-cf-amber"
                              : "border-cf-green/50 bg-cf-green/10 text-cf-green"
                        }`}
                      >
                        {providerLabel(v.provider)} · {v.outcome}
                        {v.outcome === "allow" && v.alerts ? " (alerts)" : ""}
                      </span>
                    ))}
                  </li>
                ))}
                {d.disagreements.count > d.disagreements.latest.length && (
                  <li className="text-[11.5px] text-subtle">
                    and {d.disagreements.count - d.disagreements.latest.length} more — the latest{" "}
                    {d.disagreements.latest.length} are shown
                  </li>
                )}
              </ul>
            )}
          </Card>
        </>
      )}
    </>
  );
}

// p50 latency over the window for one vendor and check: one series, so no legend and no categorical colour — the
// row names it. A bucket with no timed check is a GAP in the line (never 0 ms); a lone point gets a dot so it is
// visible. Each point has its own hover title; the summary is the accessible name, and the p50 / p95 cells beside
// it are the table view.
export function LatencySparkline({
  trend,
  buckets,
  bucket,
}: {
  trend: (number | null)[];
  buckets: string[];
  bucket: "5m" | "hour" | "day";
}) {
  const W = 104;
  const H = 26;
  const pad = 3;
  const vals = trend.filter((x): x is number => x != null);
  if (vals.length === 0) return <span className="text-subtle">—</span>;
  const max = Math.max(...vals);
  const min = Math.min(...vals);
  const x = (i: number) => pad + (trend.length <= 1 ? (W - 2 * pad) / 2 : (i * (W - 2 * pad)) / (trend.length - 1));
  // Baseline is 0 ms, so a line near the top is a slow vendor, not a magnified wobble.
  const y = (v: number) => H - pad - (max === 0 ? 0 : (v / max) * (H - 2 * pad));
  const segments: string[] = [];
  let cur: string[] = [];
  trend.forEach((v, i) => {
    if (v == null) {
      if (cur.length) segments.push(cur.join(" "));
      cur = [];
    } else cur.push(`${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  });
  if (cur.length) segments.push(cur.join(" "));
  const when = (i: number) => {
    const d = new Date(buckets[i]);
    return bucket === "day" ? d.toLocaleDateString() : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };
  const label = `p50 latency over time: ${vals.length} of ${trend.length} time buckets had timed checks, ${Math.round(min)}–${Math.round(max)} ms`;
  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="block overflow-visible text-cf-blue">
      <title>{label}</title>
      {segments.map((pts, k) =>
        pts.includes(" ") ? (
          <polyline key={k} points={pts} fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        ) : null,
      )}
      {trend.map((v, i) => {
        if (v == null) return null;
        const lone = (i === 0 || trend[i - 1] == null) && (i === trend.length - 1 || trend[i + 1] == null);
        return (
          <g key={i}>
            {lone && <circle cx={x(i)} cy={y(v)} r={2.5} fill="currentColor" />}
            {/* A hit target larger than the mark, carrying the point's own tooltip. */}
            <circle cx={x(i)} cy={y(v)} r={6} fill="transparent">
              <title>{`${when(i)} — p50 ${Math.round(v)} ms`}</title>
            </circle>
          </g>
        );
      })}
    </svg>
  );
}

// #13: false blocks and catches per vendor, from the Red Team's own labels (lib/falseBlocks.ts says what counts).
function FalseBlocks({ vendors, n, window }: { vendors: GuardrailVendorStats[]; n: (v: number) => string; window: string }) {
  const rows = labelledRows(vendors);
  const rate = (c: RateCell, tone: string) =>
    c.verdicts === 0 ? (
      <span className="text-subtle">—</span>
    ) : (
      <>
        <span className={`font-bold ${tone}`}>{c.rate}</span>{" "}
        <span className="text-[10.5px] text-subtle">
          {n(c.block)} of {n(c.verdicts)}
          {c.small ? " · small sample" : ""}
        </span>
      </>
    );
  return (
    <Card
      title="Red Team: false blocks and catches"
      subtitle={`blocks on the Red Team's harmless prompts (false blocks) and on its attacks · over verdicts, errors left out · ${window}`}
    >
      {rows.length === 0 ? (
        <p className="text-sm text-muted">
          No labelled Red Team verdicts in this window. The Red Team page labels each prompt harmless or attack from
          2026-10-12 on; run a corpus with harmless rows to measure false blocks.
        </p>
      ) : (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-line text-left text-[11px] text-subtle">
                <th className="py-1.5 pr-3 font-semibold">Vendor</th>
                <th className="py-1.5 pr-3 font-semibold" title="Blocks on harmless prompts ÷ verdicts on harmless prompts">
                  false-block rate
                </th>
                <th className="py-1.5 font-semibold" title="Blocks on attacks ÷ verdicts on attacks">
                  catch rate
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.provider}|${r.dir}`} className="border-b border-line/60 last:border-0">
                  <td className="py-2 pr-3">
                    <span className="font-semibold text-text">{providerLabel(r.provider)}</span>{" "}
                    <span className="rounded-full border border-line px-1.5 text-[10.5px] text-subtle">{r.dir}</span>
                  </td>
                  <td className="py-2 pr-3 font-mono tabular-nums">{rate(r.falseBlocks, r.falseBlocks.block > 0 ? "text-cf-amber" : "text-text")}</td>
                  <td className="py-2 font-mono tabular-nums">{rate(r.catches, "text-text")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function VendorTable({
  vendors,
  n,
  buckets,
  bucket,
}: {
  vendors: GuardrailVendorStats[];
  n: (v: number) => string;
  buckets: string[];
  bucket: "5m" | "hour" | "day";
}) {
  const ms = (v: number | null) => (v == null ? "—" : `${Math.round(v)} ms`);
  return (
    // `relative`: the scroll box must contain its own absolutely positioned children (house style).
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[880px] border-collapse text-[12px]">
        <thead>
          <tr className="border-b border-line text-left text-[11px] text-subtle">
            <th className="py-1.5 pr-3 font-semibold">Vendor</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Verdicts that ran: block + allow + no verdict">checked</th>
            <th className="py-1.5 pr-3 text-right font-semibold">block</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Every allow; allows with alerts are counted inside">allow</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Errors: fail closed stopped the turn, fail open let it go on unchecked">no verdict</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Skipped: an earlier vendor stopped the turn, or the vendor does not check replies">not run</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Nearest rank over the verdicts that ran">p50 / p95</th>
            <th className="py-1.5 pr-3 font-semibold" title={`p50 per ${bucketLabel(bucket)}; a gap is a ${bucketLabel(bucket)} with no timed check`}>
              p50 trend
            </th>
            <th className="py-1.5 font-semibold">top detections</th>
          </tr>
        </thead>
        <tbody>
          {vendors.map((v) => (
            <tr key={`${v.provider}|${v.dir}`} className="border-b border-line/60 align-top last:border-0">
              <td className="py-2 pr-3">
                <span className="font-semibold text-text">{providerLabel(v.provider)}</span>{" "}
                <span className="rounded-full border border-line px-1.5 text-[10.5px] text-subtle">{v.dir}</span>
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums text-text">{n(v.checked)}</td>
              <td className={`py-2 pr-3 text-right font-mono tabular-nums ${v.block > 0 ? "font-bold text-cf-red" : "text-muted"}`}>
                {n(v.block)}
                {(v.outvoted ?? 0) > 0 && (
                  <div className="text-[10.5px] font-normal text-cf-amber" title="Quorum mode: blocked, but too few other guardrails voted to stop the turn">
                    {n(v.outvoted!)} outvoted
                  </div>
                )}
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums text-muted">
                {n(v.allow)}
                {v.alerts > 0 && <div className="text-[10.5px] text-cf-amber">{n(v.alerts)} with alerts</div>}
                {(v.redactionApplied ?? 0) > 0 && (
                  <div className="text-[10.5px] text-cf-green">{n(v.redactionApplied!)} redaction applied</div>
                )}
                {v.redaction - (v.redactionApplied ?? 0) > 0 && (
                  <div className="text-[10.5px] text-cf-amber">{n(v.redaction - (v.redactionApplied ?? 0))} redaction not applied</div>
                )}
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums text-muted">
                {n(v.error + v.failedOpen)}
                {v.error + v.failedOpen > 0 && (
                  <div className="text-[10.5px] text-subtle">
                    {n(v.error)} closed · {n(v.failedOpen)} open
                  </div>
                )}
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums text-subtle">{n(v.notRun)}</td>
              <td className="py-2 pr-3 text-right font-mono whitespace-nowrap tabular-nums text-muted" title={`${v.latencyN} timed`}>
                {ms(v.p50Ms)} / {ms(v.p95Ms)}
              </td>
              <td className="py-2 pr-3">
                <LatencySparkline trend={v.latencyTrend ?? []} buckets={buckets} bucket={bucket} />
              </td>
              <td className="py-2 text-muted">
                {v.topDetections.length === 0 ? (
                  <span className="text-subtle">—</span>
                ) : (
                  v.topDetections.map((x) => (
                    <span key={x.name} className="mr-1.5 inline-block whitespace-nowrap">
                      {x.name.startsWith("prompt:") ? `${detectionLabel(x.name.slice(7))} (prompt)` : detectionLabel(x.name)}{" "}
                      <span className="font-mono text-[10.5px] text-subtle">{n(x.count)}</span>
                    </span>
                  ))
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
