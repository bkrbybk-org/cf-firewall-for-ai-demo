// AI Security (edge) tab — zone-scoped WAF events plus the Firewall for AI
// detection breakdowns behind them.
import { Link } from "react-router-dom";
import { BarChart3, ShieldAlert, ShieldCheck, ShieldX, UserSearch } from "lucide-react";
import { BarList, Card, Tile } from "./primitives";
import { EventSeries, SERIES } from "./EventSeries";
import { topicLabel } from "../../lib/format";
import { isLlmRule } from "../../lib/data";
import type { Analytics } from "../../lib/types";

const SCORE_BUCKET_CLS = ["bg-cf-red", "bg-cf-amber", "bg-subtle", "bg-cf-green"];

// What a click on a rule / score bucket asks the page to show.
export interface EdgeDrill {
  label: string; // human description of the slice, shown as a banner
  note?: string; // caveat, e.g. blocked prompts never reached the Worker
}

export function classifyAction(action: string): "block" | "log" | "other" {
  const a = action.toLowerCase();
  if (/block|drop/.test(a)) return "block";
  if (/log|link_maze/.test(a)) return "log";
  return "other";
}

// Does the traffic actually reach AI Security? A /api/chat request is only
// scanned when its endpoint carries the cf-llm managed label — this makes the
// most common misconfiguration visible in aggregate, not just per-request.
function ScanCoverage({ scanned, labeled, aiScored }: { scanned: number; labeled: number; aiScored: number }) {
  const pct = scanned ? Math.round((labeled / scanned) * 100) : 0;
  const gap = scanned > 0 && labeled < scanned;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[12.5px]">
        <span className="font-mono text-xl font-bold text-text tabular-nums">{pct}%</span>
        <span className="text-muted">
          of <b className="text-text tabular-nums">{scanned}</b> chat request{scanned === 1 ? "" : "s"} carried the{" "}
          <code className="font-mono">cf-llm</code> label · <b className="text-text tabular-nums">{aiScored}</b> were
          scored
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-surface-2">
        <div
          className={`h-full rounded-full ${gap ? "bg-cf-amber" : "bg-cf-green"}`}
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>
      {gap && (
        <p className="text-[11.5px] text-muted">
          Unlabeled requests are never scanned. Apply the <code className="font-mono">cf-llm</code> label to{" "}
          <code className="font-mono">POST /api/chat</code> in Security → Web Assets.
        </p>
      )}
      {scanned === 0 && (
        <p className="text-[11.5px] text-muted">
          No <code className="font-mono">/api/chat</code> requests in this window.
        </p>
      )}
    </div>
  );
}

export function EdgeTab({
  data,
  hours,
  onDrill,
}: {
  data: Analytics | null;
  hours: number;
  onDrill?: (d: EdgeDrill) => void;
}) {
  const actions = data?.actions ?? {};
  const blocked = Object.entries(actions)
    .filter(([a]) => classifyAction(a) === "block")
    .reduce((n, [, c]) => n + c, 0);
  const logged = Object.entries(actions)
    .filter(([a]) => classifyAction(a) === "log")
    .reduce((n, [, c]) => n + c, 0);
  const hasEvents = (data?.totalEvents ?? 0) > 0;
  const hasScores = (data?.aiScored ?? 0) > 0;

  // Rates and trends are suppressed, not approximated, when the row cap was hit
  // — see AnalyticsSummary.truncated. A percentage of a truncated total, or a
  // delta between two capped windows, would read as precise while being wrong.
  const total = data?.totalEvents ?? 0;
  const capped = data?.truncated === true;
  const prev = data?.prev;
  const pctOf = (n: number) => (capped || total === 0 ? undefined : `${Math.round((n / total) * 100)}% of events`);
  const deltaOf = (now: number, before?: number) => (prev && before != null ? now - before : null);

  // AI Security's own rules vs unrelated zone rules that fire on the same
  // traffic. Kept apart so the demo never credits AI Security for a Geography
  // or scanner-signature rule — on this zone those actually outrank the LLM
  // rules by count.
  const allRules = data?.topRules ?? [];
  const llmRules = allRules.filter((r) => isLlmRule(r.name));
  const otherRules = allRules.filter((r) => !isLlmRule(r.name));
  const ruleBarCls = (action: string) =>
    classifyAction(action) === "block" ? "bg-cf-red" : classifyAction(action) === "log" ? "bg-cf-amber" : "bg-subtle";
  // One scale across both lists so the relative sizes stay honest when split.
  const ruleScale = Math.max(1, ...allRules.map((r) => r.count));

  // The clean bucket (typically >95% of traffic) is excluded from the bar scale
  // so the attack buckets stay visible instead of collapsing to slivers.
  const scoreBuckets = data?.scoreBuckets ?? [];
  const attackBuckets = scoreBuckets.slice(0, -1);
  const cleanBucket = scoreBuckets.length > 0 ? scoreBuckets[scoreBuckets.length - 1] : null;
  const attackTotal = attackBuckets.reduce((n, b) => n + b.count, 0);

  return (
    <>
      {data?.configured === false ? (
        <Card title="Not configured">
          <p className="text-sm text-muted">
            Set the <code className="font-mono">CF_ANALYTICS_TOKEN</code> secret (Zone Analytics: Read) to enable
            this dashboard.
          </p>
        </Card>
      ) : data?.error ? (
        <Card title="Analytics error">
          <p className="text-sm text-cf-red">{data.error}</p>
        </Card>
      ) : !data ? (
        <Card title="Loading…">
          <p className="text-sm text-muted">Querying GraphQL Analytics…</p>
        </Card>
      ) : (
        <>
          <div className="flex flex-wrap gap-3">
            <Tile
              label={`security events · ${hours}h`}
              // Exactly at the row cap means "at least this many" — say so
              // rather than presenting a floor as an exact total.
              value={capped ? `${total}+` : total}
              rate={capped ? "row cap reached — see note below" : undefined}
              delta={deltaOf(total, prev?.totalEvents)}
              icon={<BarChart3 size={16} className="text-cf-blue" />}
              tone="border-cf-blue/40 bg-cf-blue/10"
            />
            <Tile
              label="blocked"
              value={blocked}
              rate={pctOf(blocked)}
              delta={deltaOf(blocked, prev?.blocked)}
              icon={<ShieldX size={16} className="text-cf-red" />}
              tone="border-cf-red/40 bg-cf-red/10"
            />
            <Tile
              label="logged"
              value={logged}
              rate={pctOf(logged)}
              delta={deltaOf(logged, prev?.logged)}
              icon={<ShieldAlert size={16} className="text-cf-amber" />}
              tone="border-cf-amber/40 bg-cf-amber/10"
            />
            <Tile
              label="prompts with PII"
              value={data.piiRequests ?? 0}
              rate={
                (data.aiScored ?? 0) > 0
                  ? `${Math.round(((data.piiRequests ?? 0) / (data.aiScored ?? 1)) * 100)}% of scored prompts`
                  : undefined
              }
              delta={deltaOf(data.piiRequests ?? 0, prev?.piiRequests)}
              icon={<UserSearch size={16} className="text-cf-purple" />}
              tone="border-cf-purple/40 bg-cf-purple/10"
            />
          </div>

          {!hasEvents && !hasScores ? (
            <Card title="No events in this window">
              <div className="flex items-start gap-3 text-sm text-muted">
                <ShieldCheck size={18} className="mt-0.5 shrink-0 text-cf-green" />
                <p>
                  Nothing recorded in the last {hours}h. Send a few attacks from the{" "}
                  <Link to="/" className="text-accent hover:underline">
                    Firewall page
                  </Link>{" "}
                  and come back — GraphQL ingestion lags ~1–2 minutes. Note: edge analytics only exist for the
                  production hostname, not local dev.
                </p>
              </div>
            </Card>
          ) : (
            <>
              <Card
                title="Events over time"
                subtitle={`per ${data.bucket === "day" ? "day" : "hour"} · block vs log vs other`}
              >
                <EventSeries
                  rows={data.series ?? []}
                  bucket={data.bucket}
                  defs={SERIES}
                  ariaLabel="Security events over time"
                />
              </Card>

              {capped && (
                <div className="rounded-xl border border-cf-amber/30 bg-cf-amber/[0.06] px-3.5 py-2 text-[11.5px] text-muted">
                  This window returned the full {total}-row query cap, so counts are a{" "}
                  <b className="text-text">floor, not a total</b>, and the trend vs the previous window is hidden —
                  comparing two capped windows would be meaningless. Narrow the range to get exact numbers.
                </div>
              )}

              <div className="grid gap-4 lg:grid-cols-2">
                <Card
                  title="AI Security rules fired"
                  subtitle={`cf.llm.* rules only · by event count${onDrill ? " · click to inspect prompts" : ""}`}
                >
                  {llmRules.length > 0 ? (
                    <BarList
                      scaleMax={ruleScale}
                      rows={llmRules.map((r) => ({
                        name: r.name,
                        sub: r.action,
                        count: r.count,
                        barCls: ruleBarCls(r.action),
                      }))}
                      onPick={
                        onDrill &&
                        ((row) =>
                          onDrill({
                            label: `Rule “${row.name}” · ${row.count} event${row.count === 1 ? "" : "s"} in the last ${hours}h`,
                            note:
                              classifyAction(allRules.find((r) => r.name === row.name)?.action ?? "") === "block"
                                ? "This rule BLOCKS at the edge, so those prompts never reached the Worker and are not in this log. The log shows what did get through in the same window."
                                : undefined,
                          }))
                      }
                    />
                  ) : (
                    <p className="text-sm text-muted">
                      No AI Security rule matched in this window
                      {otherRules.length > 0 ? " — only unrelated zone rules fired (see below)." : "."}
                    </p>
                  )}

                  {otherRules.length > 0 && (
                    <div className="mt-4 border-t border-line pt-3">
                      <div className="mb-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">
                        Other zone rules — not AI Security
                      </div>
                      <BarList
                        scaleMax={ruleScale}
                        rows={otherRules.map((r) => ({
                          name: r.name,
                          sub: r.action,
                          count: r.count,
                          barCls: "bg-subtle",
                          hint: `${r.name}: ${r.count} — not an AI Security rule`,
                        }))}
                      />
                      <p className="mt-2.5 text-[11px] text-subtle">
                        These fire on the same traffic but have nothing to do with AI Security — kept separate so
                        their counts are never read as detections.
                      </p>
                    </div>
                  )}
                </Card>

                <Card
                  title="Injection-score distribution"
                  subtitle={`${data.aiScored ?? 0} AI-scored prompt${(data.aiScored ?? 0) === 1 ? "" : "s"} · lower score = more likely an attack`}
                >
                  {hasScores ? (
                    <>
                      {/* Scaled across the attack buckets only. Including the
                          clean bucket (usually >95%) flattened these to
                          invisible slivers — the security signal was the one
                          thing you could not read. */}
                      <BarList
                        rows={attackBuckets.map((b, i) => ({
                          name: b.label,
                          count: b.count,
                          barCls: SCORE_BUCKET_CLS[i] ?? "bg-subtle",
                        }))}
                        onPick={
                          onDrill &&
                          ((row) =>
                            onDrill({
                              label: `Injection score ${row.name} · ${row.count} prompt${row.count === 1 ? "" : "s"} in the last ${hours}h`,
                              note: "Prompts scoring low enough to hit a blocking rule never reached the Worker, so they are not in this log.",
                            }))
                        }
                      />
                      {cleanBucket && (
                        <div className="mt-3 flex items-baseline gap-2 border-t border-line pt-3 text-[12px]">
                          <span className="h-2 w-2 shrink-0 rounded-full bg-cf-green" />
                          <span className="text-muted">{cleanBucket.label}</span>
                          <span className="ml-auto font-mono text-[11.5px] text-text tabular-nums">
                            {cleanBucket.count}
                          </span>
                        </div>
                      )}
                      <p className="mt-2 text-[11px] text-subtle">
                        Bars are scaled across the attack range only ({attackTotal} prompt
                        {attackTotal === 1 ? "" : "s"}); the clean bucket is listed separately so it does not flatten
                        them.
                      </p>
                    </>
                  ) : (
                    <p className="text-sm text-muted">
                      No AI-scored prompts in this window — send traffic from the Firewall page.
                    </p>
                  )}
                </Card>
              </div>

              {/* Firewall for AI detection breakdowns — the per-category
                  detail behind the injection histogram above. */}
              <div className="grid gap-4 lg:grid-cols-2">
                <Card title="Unsafe topics detected" subtitle="Llama Guard categories, by prompt count">
                  {(data.unsafeTopics ?? []).length > 0 ? (
                    <BarList
                      rows={(data.unsafeTopics ?? []).map((t) => ({
                        name: topicLabel(t.code),
                        count: t.count,
                        barCls: "bg-cf-red",
                      }))}
                    />
                  ) : (
                    <p className="text-sm text-muted">No unsafe topics detected in this window.</p>
                  )}
                </Card>

                <Card title="PII categories detected" subtitle="by prompt count · a prompt can hit several">
                  {(data.piiCategories ?? []).length > 0 ? (
                    <BarList
                      rows={(data.piiCategories ?? []).map((p) => ({
                        name: p.name,
                        count: p.count,
                        barCls: "bg-cf-purple",
                      }))}
                    />
                  ) : (
                    <p className="text-sm text-muted">No PII detected in this window.</p>
                  )}
                </Card>
              </div>

              <Card
                title="Custom topic matches"
                subtitle="by prompt count · avg match strength (higher = stronger match)"
              >
                {(data.customTopics ?? []).length > 0 ? (
                  <BarList
                    rows={(data.customTopics ?? []).map((c) => ({
                      name: c.label,
                      sub: `avg strength ${c.avgStrength}`,
                      count: c.count,
                      barCls: "bg-cf-amber",
                    }))}
                  />
                ) : (
                  <p className="text-sm text-muted">
                    No custom topics matched in this window. Custom topics are configured per-zone in the
                    dashboard and tuned with the graded presets in the Attack Library.
                  </p>
                )}
              </Card>

              <Card title="Scan coverage" subtitle="are prompts actually reaching AI Security?">
                <ScanCoverage
                  scanned={data.scannedRequests ?? 0}
                  labeled={data.labeledRequests ?? 0}
                  aiScored={data.aiScored ?? 0}
                />
              </Card>
            </>
          )}
        </>
      )}
    </>
  );
}
