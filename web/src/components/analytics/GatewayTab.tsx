// AI Gateway tab. Unlike the zone-scoped edge tab this data is ACCOUNT-scoped —
// the logs cover every app using the selected gateway, which the Scope card
// below states explicitly.
import { Link } from "react-router-dom";
import { CircleDollarSign, Route, ShieldCheck, Timer, Zap } from "lucide-react";
import { BarList, Card, Tile } from "./primitives";
import { EventSeries, GW_SERIES } from "./EventSeries";
import { fmtCost } from "../../lib/format";
import type { GatewayAnalytics as GatewayAnalyticsData } from "../../lib/types";

export function GatewayTab({ d, hours, gatewayId }: { d: GatewayAnalyticsData | null; hours: number; gatewayId: string }) {
  if (d?.configured === false)
    return (
      <Card title="Not configured">
        <p className="text-sm text-muted">
          Set <code className="font-mono">CF_ANALYTICS_TOKEN</code> (needs <b>AI Gateway Read</b>) and{" "}
          <code className="font-mono">CF_ACCOUNT_ID</code> to enable gateway analytics.
        </p>
      </Card>
    );
  if (d?.error)
    return (
      <Card title="AI Gateway error">
        <p className="text-sm text-cf-red">{d.error}</p>
        <p className="mt-2 text-[11.5px] text-muted">
          A permission error here usually means the token is missing the <b>AI Gateway Read</b> scope.
        </p>
      </Card>
    );
  if (!d)
    return (
      <Card title="Loading…">
        <p className="text-sm text-muted">Reading AI Gateway logs…</p>
      </Card>
    );

  const requests = d.requests ?? 0;
  const cached = d.cachedRequests ?? 0;
  const hitRate = requests ? Math.round((cached / requests) * 100) : 0;

  return (
    <>
      <div className="flex flex-wrap gap-3">
        <Tile
          label={`gateway requests · ${hours}h`}
          value={requests}
          icon={<Route size={16} className="text-cf-blue" />}
          tone="border-cf-blue/40 bg-cf-blue/10"
        />
        <Tile
          label={`cache hits (${hitRate}%)`}
          value={cached}
          icon={<Zap size={16} className="text-cf-green" />}
          tone="border-cf-green/40 bg-cf-green/10"
        />
        <Tile
          label="total cost"
          value={fmtCost(d.totalCost) ?? "$0"}
          icon={<CircleDollarSign size={16} className="text-cf-amber" />}
          tone="border-cf-amber/40 bg-cf-amber/10"
        />
        <Tile
          label={`avg latency · p95 ${d.p95Ms ?? 0} ms`}
          value={`${d.avgMs ?? 0} ms`}
          icon={<Timer size={16} className="text-cf-purple" />}
          tone="border-cf-purple/40 bg-cf-purple/10"
        />
      </div>

      <Card title="Scope" subtitle={`gateway: ${d.gatewayId || gatewayId}${d.guarded ? " · Guardrails enabled" : ""}`}>
        <p className="text-[12px] leading-relaxed text-muted">
          AI Gateway logs are <b className="text-text">account-scoped</b> — unlike the zone-scoped edge data on the
          other tab, these numbers include <i>any</i> application routing through this gateway, not just this demo.
          Guardrails blocks (2016 prompt / 2017 response) appear here as errors and non-200 status codes.
          {d.truncated && " Only the most recent 500 log entries are read, so totals in this window are a floor."}
        </p>
      </Card>

      {requests === 0 ? (
        <Card title="No gateway traffic in this window">
          <div className="flex items-start gap-3 text-sm text-muted">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-cf-green" />
            <p>
              Nothing logged for this gateway in the last {hours}h. Switch the route toggle to{" "}
              <b>AI Gateway</b> on the{" "}
              <Link to="/" className="text-accent hover:underline">
                Firewall page
              </Link>{" "}
              and send a few prompts, or pick a different gateway above.
            </p>
          </div>
        </Card>
      ) : (
        <>
          <Card
            title="Gateway requests over time"
            subtitle={`per ${d.bucket === "day" ? "day" : "hour"} · cache hit vs miss vs error`}
          >
            <EventSeries
              rows={d.series ?? []}
              bucket={d.bucket}
              defs={GW_SERIES}
              ariaLabel="AI Gateway requests over time"
            />
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Requests by model" subtitle="with tokens and cost per model">
              {(d.byModel ?? []).length > 0 ? (
                <BarList
                  rows={(d.byModel ?? []).map((m) => ({
                    name: m.model,
                    sub: `${m.tokensIn + m.tokensOut} tok · ${fmtCost(m.cost) ?? "$0"}`,
                    count: m.count,
                    barCls: "bg-cf-blue",
                  }))}
                />
              ) : (
                <p className="text-sm text-muted">No model data in this window.</p>
              )}
            </Card>

            <Card
              title="Status codes"
              subtitle={`${d.errors ?? 0} failed request${(d.errors ?? 0) === 1 ? "" : "s"} · Guardrails blocks land here`}
            >
              {(d.statusCodes ?? []).length > 0 ? (
                <BarList
                  rows={(d.statusCodes ?? []).map((s) => ({
                    name: String(s.code),
                    count: s.count,
                    barCls: s.code >= 400 ? "bg-cf-red" : "bg-cf-green",
                  }))}
                />
              ) : (
                <p className="text-sm text-muted">No status codes recorded in this window.</p>
              )}
            </Card>
          </div>

          <Card title="Token usage" subtitle="summed across the window">
            <div className="flex flex-wrap gap-x-8 gap-y-2 text-[12.5px]">
              <span className="text-muted">
                input <b className="font-mono text-text tabular-nums">{(d.tokensIn ?? 0).toLocaleString()}</b>
              </span>
              <span className="text-muted">
                output <b className="font-mono text-text tabular-nums">{(d.tokensOut ?? 0).toLocaleString()}</b>
              </span>
              <span className="text-muted">
                p50 latency <b className="font-mono text-text tabular-nums">{d.p50Ms ?? 0} ms</b>
              </span>
              <span className="text-muted">
                p95 latency <b className="font-mono text-text tabular-nums">{d.p95Ms ?? 0} ms</b>
              </span>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
