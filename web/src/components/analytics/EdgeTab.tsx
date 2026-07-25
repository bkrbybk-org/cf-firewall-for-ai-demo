// AI Security (edge) tab — zone-scoped WAF events plus the Firewall for AI
// detection breakdowns behind them.
import { Link } from "react-router-dom";
import { BarChart3, ShieldAlert, ShieldCheck, ShieldX, UserSearch } from "lucide-react";
import { BarList, Card, Tile } from "./primitives";
import { EventSeries, SERIES } from "./EventSeries";
import { topicLabel } from "../../lib/format";
import type { Analytics } from "../../lib/types";

const SCORE_BUCKET_CLS = ["bg-cf-red", "bg-cf-amber", "bg-subtle", "bg-cf-green"];

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

export function EdgeTab({ data, hours }: { data: Analytics | null; hours: number }) {
  const actions = data?.actions ?? {};
  const blocked = Object.entries(actions)
    .filter(([a]) => classifyAction(a) === "block")
    .reduce((n, [, c]) => n + c, 0);
  const logged = Object.entries(actions)
    .filter(([a]) => classifyAction(a) === "log")
    .reduce((n, [, c]) => n + c, 0);
  const hasEvents = (data?.totalEvents ?? 0) > 0;
  const hasScores = (data?.aiScored ?? 0) > 0;

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
              value={data.totalEvents ?? 0}
              icon={<BarChart3 size={16} className="text-cf-blue" />}
              tone="border-cf-blue/40 bg-cf-blue/10"
            />
            <Tile
              label="blocked"
              value={blocked}
              icon={<ShieldX size={16} className="text-cf-red" />}
              tone="border-cf-red/40 bg-cf-red/10"
            />
            <Tile
              label="logged"
              value={logged}
              icon={<ShieldAlert size={16} className="text-cf-amber" />}
              tone="border-cf-amber/40 bg-cf-amber/10"
            />
            <Tile
              label="prompts with PII"
              value={data.piiRequests ?? 0}
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

              <div className="grid gap-4 lg:grid-cols-2">
                <Card title="Top fired rules" subtitle="by event count, colored by action">
                  {data.topRules && data.topRules.length > 0 ? (
                    <BarList
                      rows={data.topRules.map((r) => ({
                        name: r.name,
                        sub: r.action,
                        count: r.count,
                        barCls:
                          classifyAction(r.action) === "block"
                            ? "bg-cf-red"
                            : classifyAction(r.action) === "log"
                              ? "bg-cf-amber"
                              : "bg-subtle",
                      }))}
                    />
                  ) : (
                    <p className="text-sm text-muted">No rule matches in this window.</p>
                  )}
                </Card>

                <Card
                  title="Injection-score distribution"
                  subtitle={`${data.aiScored ?? 0} AI-scored prompt${(data.aiScored ?? 0) === 1 ? "" : "s"} · low score = likely attack`}
                >
                  {hasScores ? (
                    <BarList
                      rows={(data.scoreBuckets ?? []).map((b, i) => ({
                        name: b.label,
                        count: b.count,
                        barCls: SCORE_BUCKET_CLS[i] ?? "bg-subtle",
                      }))}
                    />
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
