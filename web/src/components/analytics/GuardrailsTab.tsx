// External guardrails tab: what each third-party vendor decided, read live from the Analytics Engine dataset the
// Worker writes one data point to per vendor per check (src/guardrailLog.ts → src/guardrailAnalytics.ts).
//
// The honesty rules travel with the numbers: "≈" when Analytics Engine sampled rows (counts are estimates), "≥"
// when the read hit its row cap (counts are a floor), "—" for a latency nobody measured — never 0 ms — and every
// card states its window and which traffic it covers.
import { AlertTriangle, ShieldAlert, ShieldCheck, ShieldX, Split } from "lucide-react";
import { bucketLabel, Card, Tile } from "./primitives";
import { EventSeries, type SeriesDef } from "./EventSeries";
import { detectionLabel, providerLabel } from "../../lib/guardrailView";
import type { GuardrailAnalytics, GuardrailVendorStats } from "../../lib/types";

// The verdict palette the chat card uses: block red, allow with alerts amber, clean allow green; "no verdict"
// grey, because an error is not a decision either way.
export const GUARDRAIL_SERIES: SeriesDef[] = [
  { key: "block", label: "block", cls: "fill-cf-red", stroke: "stroke-cf-red", dot: "bg-cf-red" },
  { key: "alerts", label: "allow with alerts", cls: "fill-cf-amber", stroke: "stroke-cf-amber", dot: "bg-cf-amber" },
  { key: "allow", label: "allow", cls: "fill-cf-green", stroke: "stroke-cf-green", dot: "bg-cf-green" },
  { key: "error", label: "no verdict", cls: "fill-subtle", stroke: "stroke-subtle", dot: "bg-subtle" },
];

export type GuardrailSource = "chat" | "redteam" | "all";

export const SOURCE_LABEL: Record<GuardrailSource, string> = {
  chat: "chat traffic",
  redteam: "Red Team runs",
  all: "all traffic",
};

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
  const window = `${rangeLabel(d.rangeHours ?? hours)} · ${SOURCE_LABEL[d.source ?? "chat"]}`;
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
            No external guardrail checked a {d.source === "redteam" ? "Red Team prompt" : "prompt"} in the {rangeLabel(d.rangeHours)}.
            Verdicts are recorded from 2026-10-09 on, while at least one guardrail is enabled in Settings.
          </p>
        </Card>
      ) : (
        <>
          <Card title="Verdicts per vendor" subtitle={`${window} · prompt and reply checks counted apart`}>
            <VendorTable vendors={d.vendors} n={n} />
          </Card>

          <Card title="Verdicts over time" subtitle={`per ${bucketLabel(d.bucket)} · every vendor's verdicts, by outcome · ${window}`}>
            <EventSeries rows={d.series} bucket={d.bucket} defs={GUARDRAIL_SERIES} ariaLabel="External guardrail verdicts over time" />
          </Card>

          <Card
            title="Where the vendors disagreed"
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

function VendorTable({ vendors, n }: { vendors: GuardrailVendorStats[]; n: (v: number) => string }) {
  const ms = (v: number | null) => (v == null ? "—" : `${Math.round(v)} ms`);
  return (
    // `relative`: the scroll box must contain its own absolutely positioned children (house style).
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-[12px]">
        <thead>
          <tr className="border-b border-line text-left text-[11px] text-subtle">
            <th className="py-1.5 pr-3 font-semibold">Vendor</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Verdicts that ran: block + allow + no verdict">checked</th>
            <th className="py-1.5 pr-3 text-right font-semibold">block</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Every allow; allows with alerts are counted inside">allow</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Errors: fail closed stopped the turn, fail open let it go on unchecked">no verdict</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Skipped: an earlier vendor stopped the turn, or the vendor does not check replies">not run</th>
            <th className="py-1.5 pr-3 text-right font-semibold" title="Nearest rank over the verdicts that ran">p50 / p95</th>
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
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums text-muted">
                {n(v.allow)}
                {v.alerts > 0 && <div className="text-[10.5px] text-cf-amber">{n(v.alerts)} with alerts</div>}
                {v.redaction > 0 && <div className="text-[10.5px] text-cf-amber">{n(v.redaction)} redaction not applied</div>}
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
