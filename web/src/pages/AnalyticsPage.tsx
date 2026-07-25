// Security analytics dashboard: aggregated WAF events + AI Security scores
// for the zone, rendered with hand-rolled SVG/flex bars (no chart dependency).
// Status colors mirror the rest of the app: block=red, log=amber, allow=green.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  BarChart3,
  ChevronDown,
  ChevronRight,
  CircleDollarSign,
  MessagesSquare,
  RefreshCw,
  Route,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Timer,
  Trash2,
  UserSearch,
  Zap,
} from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { Verdict } from "../components/Verdict";
import {
  clearPromptLog,
  getAnalytics,
  getGatewayAnalytics,
  getModels,
  getPromptAnalytics,
  getPromptLog,
} from "../lib/api";
import { fmtCost, fmtTime, topicLabel } from "../lib/format";
import type {
  Analytics,
  GatewayAnalytics as GatewayAnalyticsData,
  GatewayOption,
  PromptAnalytics,
  PromptLog,
  PromptLogRow as PromptLogRowData,
} from "../lib/types";

const RANGES = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];
const REFRESH_MS = 60_000;

type SeriesDef = { key: string; label: string; cls: string; dot: string };

// Edge tab: WAF action mix. Gateway tab: cache outcome mix.
const SERIES: SeriesDef[] = [
  { key: "block", label: "block", cls: "fill-cf-red", dot: "bg-cf-red" },
  { key: "log", label: "log", cls: "fill-cf-amber", dot: "bg-cf-amber" },
  { key: "other", label: "other", cls: "fill-subtle", dot: "bg-subtle" },
];
const GW_SERIES: SeriesDef[] = [
  { key: "hit", label: "cache hit", cls: "fill-cf-green", dot: "bg-cf-green" },
  { key: "miss", label: "miss", cls: "fill-subtle", dot: "bg-subtle" },
  { key: "error", label: "error / blocked", cls: "fill-cf-red", dot: "bg-cf-red" },
];
// Prompt log: what happened to each logged prompt.
const PLOG_SERIES: SeriesDef[] = [
  { key: "reply", label: "replied", cls: "fill-cf-green", dot: "bg-cf-green" },
  { key: "guardrails", label: "guardrails-blocked", cls: "fill-cf-purple", dot: "bg-cf-purple" },
  { key: "error", label: "error", cls: "fill-cf-red", dot: "bg-cf-red" },
];

function classifyAction(action: string): "block" | "log" | "other" {
  const a = action.toLowerCase();
  if (/block|drop/.test(a)) return "block";
  if (/log|link_maze/.test(a)) return "log";
  return "other";
}

function Tile({
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

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">{title}</h2>
      {subtitle && <div className="mt-0.5 text-[11.5px] text-muted">{subtitle}</div>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

// Stacked column chart of events over time. One column per bucket; segments
// get a 2px gap and the topmost a rounded data-end. Series-agnostic so both
// tabs share it (edge: block/log/other · gateway: hit/miss/error).
function EventSeries({
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
  const series = rows;
  const num = (r: Record<string, number | string>, k: string) => Number(r[k] ?? 0);
  const total = (r: Record<string, number | string>) => defs.reduce((n, s) => n + num(r, s.key), 0);
  const max = Math.max(1, ...series.map(total));
  const W = 720;
  const H = 150;
  const padL = 30;
  const padB = 18;
  const plotW = W - padL - 4;
  const plotH = H - padB - 6;
  const n = series.length || 1;
  const colW = Math.max(2, Math.min(26, (plotW / n) * 0.7));
  const step = plotW / n;
  const labelEvery = Math.max(1, Math.ceil(n / 6));
  const fmtBucket = (iso: string) =>
    bucket === "day"
      ? new Date(iso).toLocaleDateString("en-GB", { month: "short", day: "numeric" })
      : new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label={ariaLabel}>
        {[0.5, 1].map((f) => (
          <g key={f}>
            <line
              x1={padL}
              x2={W - 4}
              y1={6 + plotH * (1 - f)}
              y2={6 + plotH * (1 - f)}
              className="stroke-line"
              strokeWidth="1"
            />
            <text x={padL - 5} y={6 + plotH * (1 - f) + 3} textAnchor="end" className="fill-subtle text-[9px]">
              {Math.round(max * f)}
            </text>
          </g>
        ))}
        <line x1={padL} x2={W - 4} y1={6 + plotH} y2={6 + plotH} className="stroke-line-strong" strokeWidth="1" />
        {series.map((r, i) => {
          const x = padL + i * step + (step - colW) / 2;
          const rowTotal = total(r);
          let y = 6 + plotH;
          const segs: { key: string; h: number; cls: string }[] = [];
          for (const s of defs) {
            const v = num(r, s.key);
            if (v <= 0) continue;
            const h = (v / max) * plotH;
            segs.push({ key: s.key, h, cls: s.cls });
          }
          const t = String(r.t);
          return (
            <g key={t}>
              <title>
                {`${fmtBucket(t)} — ${rowTotal} event${rowTotal === 1 ? "" : "s"}: ` +
                  defs.map((s) => `${num(r, s.key)} ${s.label}`).join(", ")}
              </title>
              {segs.map((s, j) => {
                y -= s.h;
                const gap = j < segs.length - 1 ? 2 : 0;
                const isTop = j === segs.length - 1;
                return (
                  <rect
                    key={s.key}
                    x={x}
                    y={y}
                    width={colW}
                    height={Math.max(1, s.h - gap)}
                    rx={isTop ? 2 : 0}
                    className={s.cls}
                  />
                );
              })}
              {i % labelEvery === 0 && (
                <text x={x + colW / 2} y={H - 4} textAnchor="middle" className="fill-subtle text-[9px]">
                  {fmtBucket(t)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex items-center gap-4 text-[11px] text-muted">
        {defs.map((s) => (
          <span key={s.key} className="flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-full ${s.dot}`} /> {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// Horizontal labeled bar list — used for top rules and the score histogram.
function BarList({
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

const SCORE_BUCKET_CLS = ["bg-cf-red", "bg-cf-amber", "bg-subtle", "bg-cf-green"];

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

// AI Gateway tab. Unlike the edge data above this is ACCOUNT-scoped — the logs
// cover every app using the selected gateway, which the caveat below states.
function GatewayTab({ d, hours, gatewayId }: { d: GatewayAnalyticsData | null; hours: number; gatewayId: string }) {
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

// Prompt log tab. Rows are PII-redacted at write time; expanding one shows the
// redacted reply plus the live edge verdict (joined by ray via <Verdict>), so
// you can see a prompt alongside exactly what the edge detected on it.
const OUTCOME_TONE: Record<string, string> = {
  reply: "border-cf-green/50 text-cf-green",
  guardrails: "border-cf-purple/50 text-cf-purple",
  error: "border-cf-red/50 text-cf-red",
};

function PromptLogRowView({ r }: { r: PromptLogRowData }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-line bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-[12px]"
      >
        {open ? <ChevronDown size={13} className="shrink-0 text-subtle" /> : <ChevronRight size={13} className="shrink-0 text-subtle" />}
        <span className="shrink-0 font-mono text-[11px] text-subtle tabular-nums">
          {new Date(r.ts).toLocaleString("en-GB", { hour12: false })}
        </span>
        <span className={`shrink-0 rounded-full border px-1.5 py-px text-[10px] font-semibold ${OUTCOME_TONE[r.outcome] ?? "border-line text-muted"}`}>
          {r.outcome}
        </span>
        <span className="shrink-0 rounded-full border border-line px-1.5 py-px text-[10px] text-muted">
          {r.route === "gateway" ? "AI Gateway" : "Workers AI"}
        </span>
        <span className="min-w-0 flex-1 truncate text-text">{r.prompt}</span>
        {r.redactions > 0 && (
          <span className="shrink-0 rounded-full border border-cf-amber/50 px-1.5 py-px text-[10px] font-semibold text-cf-amber">
            {r.redactions} redacted
          </span>
        )}
      </button>
      {open && (
        <div className="flex flex-col gap-2.5 border-t border-line px-3 py-2.5 text-[12px]">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">Prompt (redacted)</div>
            <div className="rounded-lg border border-line bg-bg px-2.5 py-1.5 whitespace-pre-wrap break-words text-text">
              {r.prompt}
            </div>
          </div>
          {r.reply != null ? (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">Reply (redacted)</div>
              <div className="rounded-lg border border-line bg-bg px-2.5 py-1.5 whitespace-pre-wrap break-words text-muted">
                {r.reply || "(empty)"}
              </div>
            </div>
          ) : (
            <div className="text-[11px] text-subtle">
              Reply not captured{r.outcome === "reply" ? " (streamed)" : ""}.
            </div>
          )}
          <div className="text-[11px] text-subtle">
            <span className="font-mono">{r.model}</span>
            {r.gatewayId && <> · gateway <span className="font-mono">{r.gatewayId}</span></>}
            {r.promptTokens != null && <> · {(r.promptTokens ?? 0) + (r.completionTokens ?? 0)} tok</>}
          </div>
          {/* The cf-ray join to the live edge verdict — the whole point. */}
          <Verdict ray={r.ray} prompt={r.prompt} />
        </div>
      )}
    </div>
  );
}

// Rollups over the whole prompt log (SQL GROUP BY in D1). Sits above the raw
// rows so the tab answers "what has been sent overall" before "what exactly".
function PromptStats({ a }: { a: PromptAnalytics }) {
  const total = a.total ?? 0;
  if (total === 0) return null;
  const withPii = a.withPii ?? 0;
  const piiPct = Math.round((withPii / total) * 100);
  const blocked = (a.byOutcome ?? []).find((o) => o.outcome === "guardrails")?.count ?? 0;
  const gateway = (a.byRoute ?? []).find((r) => r.route === "gateway")?.count ?? 0;
  const span =
    a.firstTs && a.lastTs
      ? `${new Date(a.firstTs).toLocaleString("en-GB", { hour12: false })} → ${new Date(a.lastTs).toLocaleString("en-GB", { hour12: false })}`
      : "";

  return (
    <>
      <div className="flex flex-wrap gap-3">
        <Tile
          label="prompts logged"
          value={total}
          icon={<MessagesSquare size={16} className="text-cf-blue" />}
          tone="border-cf-blue/40 bg-cf-blue/10"
        />
        <Tile
          label={`carried PII (${piiPct}%)`}
          value={withPii}
          icon={<UserSearch size={16} className="text-cf-purple" />}
          tone="border-cf-purple/40 bg-cf-purple/10"
        />
        <Tile
          label="guardrails-blocked"
          value={blocked}
          icon={<ShieldX size={16} className="text-cf-red" />}
          tone="border-cf-red/40 bg-cf-red/10"
        />
        <Tile
          label={`via AI Gateway (of ${total})`}
          value={gateway}
          icon={<Route size={16} className="text-cf-green" />}
          tone="border-cf-green/40 bg-cf-green/10"
        />
      </div>

      {(a.series ?? []).length > 0 && (
        <Card title="Prompts over time" subtitle={`per ${a.bucket === "day" ? "day" : "hour"} · by outcome${span ? ` · ${span}` : ""}`}>
          <EventSeries rows={a.series ?? []} bucket={a.bucket} defs={PLOG_SERIES} ariaLabel="Prompts over time" />
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Prompts by model" subtitle="with tokens consumed">
          <BarList
            rows={(a.byModel ?? []).map((m) => ({
              name: m.model,
              sub: `${m.promptTokens + m.completionTokens} tok`,
              count: m.count,
              barCls: "bg-cf-blue",
            }))}
          />
        </Card>
        <Card title="Route split" subtitle="Workers AI direct vs routed via AI Gateway">
          <BarList
            rows={(a.byRoute ?? []).map((r) => ({
              name: r.route === "gateway" ? "AI Gateway" : "Workers AI (direct)",
              count: r.count,
              barCls: r.route === "gateway" ? "bg-cf-green" : "bg-subtle",
            }))}
          />
        </Card>
      </div>

      {(a.repeated ?? []).length > 0 && (
        <Card
          title="Repeated prompts"
          subtitle="same text sent more than once — autopilot reruns and replayed attacks"
        >
          <BarList
            rows={(a.repeated ?? []).map((r) => ({
              name: r.prompt.length > 90 ? r.prompt.slice(0, 90) + "…" : r.prompt,
              sub: r.redactions > 0 ? `${r.redactions} redacted` : undefined,
              count: r.count,
              barCls: "bg-cf-amber",
            }))}
          />
        </Card>
      )}
    </>
  );
}

function PromptLogTab({ d, a, onClear }: { d: PromptLog | null; a: PromptAnalytics | null; onClear: () => void }) {
  const [confirming, setConfirming] = useState(false);

  if (d?.configured === false)
    return (
      <Card title="Prompt log not configured">
        <p className="text-sm text-muted">
          Bind a D1 database as <code className="font-mono">DB</code> and apply the migration:
        </p>
        <pre className="mt-2 overflow-x-auto rounded-lg border border-line bg-bg p-2.5 font-mono text-[11px] text-muted">
          npx wrangler d1 migrations apply cf-ai-waf-demo-log --remote
        </pre>
      </Card>
    );
  if (d?.error)
    return (
      <Card title="Prompt log error">
        <p className="text-sm text-cf-red">{d.error}</p>
      </Card>
    );
  if (!d)
    return (
      <Card title="Loading…">
        <p className="text-sm text-muted">Reading prompt log…</p>
      </Card>
    );

  const rows = d.rows ?? [];
  return (
    <>
      {a && !a.error && <PromptStats a={a} />}

      <Card title="About this log" subtitle={`${d.total ?? 0} prompt${(d.total ?? 0) === 1 ? "" : "s"} stored`}>
        <p className="text-[12px] leading-relaxed text-muted">
          Every prompt that <b className="text-text">reached the Worker</b> is stored here with PII{" "}
          <b className="text-text">redacted</b> (card, IBAN, email, phone, IP, wallet, Thai national ID). Each row joins
          to the live edge verdict by <code className="font-mono">cf-ray</code> — expand one to see the detections that
          fired on that exact prompt. Edge-blocked (403) requests never reach the Worker, so they are not here; see the{" "}
          <b className="text-text">AI Security (edge)</b> tab for those.
          <br />
          <span className="text-subtle">
            Note: redaction protects this store only. AI Gateway still logs the raw prompt + response payload (visible in
            the dashboard) — that is a separate control.
          </span>
        </p>
        <div className="mt-3">
          {confirming ? (
            <span className="inline-flex items-center gap-2 text-[12px]">
              <span className="text-muted">Clear all {d.total ?? 0} rows?</span>
              <button
                type="button"
                onClick={() => {
                  setConfirming(false);
                  onClear();
                }}
                className="rounded-full bg-cf-red px-3 py-1 text-[11.5px] font-semibold text-white"
              >
                Yes, clear
              </button>
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="rounded-full border border-line px-3 py-1 text-[11.5px] text-muted hover:text-text"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={() => setConfirming(true)}
              disabled={rows.length === 0}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-cf-red hover:text-cf-red disabled:opacity-50"
            >
              <Trash2 size={13} /> Clear log
            </button>
          )}
        </div>
      </Card>

      {rows.length === 0 ? (
        <Card title="No prompts logged yet">
          <div className="flex items-start gap-3 text-sm text-muted">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-cf-green" />
            <p>
              Send a prompt from the{" "}
              <Link to="/" className="text-accent hover:underline">
                Firewall page
              </Link>{" "}
              (either route) and it appears here. Local dev has no <code className="font-mono">cf-ray</code>, so the
              per-row verdict shows "pending".
            </p>
          </div>
        </Card>
      ) : (
        <div className="flex flex-col gap-2">
          {rows.map((r) => (
            <PromptLogRowView key={r.ray} r={r} />
          ))}
        </div>
      )}
    </>
  );
}

type Tab = "edge" | "gateway" | "promptlog";

export function AnalyticsPage() {
  const [tab, setTab] = useState<Tab>("edge");
  const [hours, setHours] = useState(24);
  const [data, setData] = useState<Analytics | null>(null);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Gateway tab: the account's gateways (same list the chat page uses) + the
  // aggregated logs for whichever one is selected.
  const [gateways, setGateways] = useState<GatewayOption[]>([]);
  const [gatewayId, setGatewayId] = useState("");
  const [gw, setGw] = useState<GatewayAnalyticsData | null>(null);
  // Prompt-log tab: PII-redacted prompts from D1.
  const [plog, setPlog] = useState<PromptLog | null>(null);
  const [pstats, setPstats] = useState<PromptAnalytics | null>(null);
  const [plogRoute, setPlogRoute] = useState("");
  const [plogOutcome, setPlogOutcome] = useState("");

  const load = useCallback(async (h: number) => {
    setLoading(true);
    try {
      setData(await getAnalytics(h));
      setFetchedAt(fmtTime());
    } catch {
      setData({ configured: true, error: "network error" });
    } finally {
      setLoading(false);
    }
  }, []);

  const loadGw = useCallback(async (id: string, h: number) => {
    setLoading(true);
    try {
      setGw(await getGatewayAnalytics(id, h));
      setFetchedAt(fmtTime());
    } catch {
      setGw({ configured: true, error: "network error" });
    } finally {
      setLoading(false);
    }
  }, []);

  // Gateway list is served by /api/models alongside the model menu.
  useEffect(() => {
    getModels()
      .then((d) => {
        setGateways(d.gateways ?? []);
        setGatewayId((cur) => cur || d.defaultGateway || d.gateways?.[0]?.id || "");
      })
      .catch(() => {});
  }, []);

  // Rollups cover the whole log, so they ignore the row filters on purpose.
  const loadPlog = useCallback(async (route: string, outcome: string) => {
    setLoading(true);
    try {
      const [log, stats] = await Promise.all([
        getPromptLog({ route, outcome, limit: 200 }),
        getPromptAnalytics(0),
      ]);
      setPlog(log);
      setPstats(stats);
      setFetchedAt(fmtTime());
    } catch {
      setPlog({ configured: true, error: "network error" });
    } finally {
      setLoading(false);
    }
  }, []);

  const refresh = useCallback(() => {
    if (tab === "edge") load(hours);
    else if (tab === "gateway") loadGw(gatewayId, hours);
    else loadPlog(plogRoute, plogOutcome);
  }, [tab, hours, gatewayId, plogRoute, plogOutcome, load, loadGw, loadPlog]);

  useEffect(() => {
    refresh();
    const t = window.setInterval(refresh, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [refresh]);

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
    <div className="flex h-full flex-col">
      <Header
        title="Security Analytics"
        subtitle={
          <>
            Zone WAF events + <code className="font-mono">cf.llm.*</code> scores via GraphQL Analytics · aggregated at
            the Worker
          </>
        }
        actions={<ThemeToggle />}
      />

      <main className="min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-5xl flex-col gap-4">
          {/* Tab strip: edge (zone-scoped) vs AI Gateway (account-scoped). */}
          <div className="flex overflow-hidden rounded-full border border-line text-[12.5px] self-start">
            {(
              [
                { id: "edge" as const, label: "AI Security (edge)" },
                { id: "gateway" as const, label: "AI Gateway" },
                { id: "promptlog" as const, label: "Prompt log" },
              ]
            ).map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={`px-4 py-1.5 transition ${
                  tab === t.id ? "bg-accent/15 font-bold text-accent" : "bg-surface text-muted hover:bg-surface-hover"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-[12.5px] text-muted">
            {tab !== "promptlog" && (
              <div className="flex overflow-hidden rounded-full border border-line">
                {RANGES.map((r) => (
                  <button
                    key={r.hours}
                    type="button"
                    onClick={() => setHours(r.hours)}
                    className={`px-3.5 py-1.5 transition ${
                      hours === r.hours ? "bg-accent/15 font-bold text-accent" : "bg-surface hover:bg-surface-hover"
                    }`}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
            )}
            {tab === "gateway" && gateways.length > 0 && (
              <label className="flex items-center gap-1.5">
                Gateway
                <select
                  value={gatewayId}
                  onChange={(e) => setGatewayId(e.target.value)}
                  className="rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
                >
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {tab === "promptlog" && (
              <>
                <label className="flex items-center gap-1.5">
                  Route
                  <select
                    value={plogRoute}
                    onChange={(e) => setPlogRoute(e.target.value)}
                    className="rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
                  >
                    <option value="">all</option>
                    <option value="direct">Workers AI</option>
                    <option value="gateway">AI Gateway</option>
                  </select>
                </label>
                <label className="flex items-center gap-1.5">
                  Outcome
                  <select
                    value={plogOutcome}
                    onChange={(e) => setPlogOutcome(e.target.value)}
                    className="rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
                  >
                    <option value="">all</option>
                    <option value="reply">replied</option>
                    <option value="guardrails">guardrails-blocked</option>
                    <option value="error">error</option>
                  </select>
                </label>
              </>
            )}
            <button
              type="button"
              onClick={refresh}
              disabled={loading}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 transition hover:border-accent hover:text-text disabled:opacity-50"
            >
              <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> refresh
            </button>
            {fetchedAt && <span className="text-subtle">fetched {fetchedAt} · auto-refresh 60s</span>}
          </div>

          {tab === "promptlog" ? (
            <PromptLogTab
              d={plog}
              a={pstats}
              onClear={() => clearPromptLog().then(() => loadPlog(plogRoute, plogOutcome))}
            />
          ) : tab === "gateway" ? (
            <GatewayTab d={gw} hours={hours} gatewayId={gatewayId} />
          ) : data?.configured === false ? (
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
        </div>
      </main>

      <footer className="shrink-0 border-t border-line bg-surface px-5 py-2 text-[11.5px] text-muted">
        Sources: <code className="font-mono">firewallEventsAdaptive</code> +{" "}
        <code className="font-mono">httpRequestsAdaptive</code> (zone GraphQL, ingestion lags ~1–2 min) ·{" "}
        <code className="font-mono">ai-gateway/gateways/&#123;id&#125;/logs</code> (account REST API) · latest 500 rows
        per query · edge data is zone-scoped, gateway data is account-scoped.
      </footer>
    </div>
  );
}
