// GET /api/guardrail-analytics — the Analytics page's "External guardrails" tab. Reads the verdict data points
// src/guardrailLog.ts writes to Analytics Engine, through the AE SQL API, and aggregates them here.
//
// Why raw rows aggregated in the Worker, not SQL aggregates: percentiles must use the nearest-rank rule
// (src/percentile.ts, bug #24), the "where vendors disagreed" view needs rows grouped by ray, and the edge
// tab already works this way — so the honesty rules are the same ones:
//   - **Sampling is reported, never hidden.** Every count is weighted by `_sample_interval` (Cloudflare's
//     rule for AE). If any row was sampled, `sampled: true` and the page says "estimated"; latency
//     percentiles and disagreements are then over the stored rows only, and say so.
//   - **A capped read is a floor.** At ROW_CAP rows, `capped: true` and totals read "at least".
//   - **No data is never zero.** A vendor with no verdicts has null latency, not 0 ms.
//   - **Every number has its window** (`rangeHours`, `since`, `until`) and its source filter.
// Facts checked live 2026-10-09: the SQL API answers a plain SELECT on a not-yet-created dataset with HTTP 200 and
// no rows (so "nothing written yet" is an empty window, not an error) — but a FUNCTION of a column there is a 422
// ("unable to find type of column"), so the query selects `timestamp` bare and parses it here: a UTC
// "YYYY-MM-DD HH:MM:SS" string.

import { bucketFor, type SeriesBucket } from "./config";
import { PROVIDER_IDS } from "./externalGuardrails";
import { AE_SCHEMA, type VerdictOutcome, type VerdictSource } from "./guardrailLog";
import { nearestRank } from "./percentile";
import { clientError } from "./publicError";
import type { Env, ExternalGuardrailProvider } from "./types";

export const AE_DATASET = "cf_ai_waf_demo_guardrail_verdicts";
export const ROW_CAP = 10_000;
export const RANGE_HOURS = [1, 24, 168] as const;
export type SourceFilter = VerdictSource | "all";

const OUTCOMES: readonly VerdictOutcome[] = ["block", "allow", "error", "failed_open", "not_run"];

// Both inputs are checked against fixed lists before they reach the SQL, so nothing typed by a caller is
// ever interpolated — the SQL API takes a plain statement, with no bound parameters.
export function buildSql(hours: (typeof RANGE_HOURS)[number], source: SourceFilter): string {
  if (!(RANGE_HOURS as readonly number[]).includes(hours)) throw new Error(`bad hours ${hours}`);
  if (source !== "chat" && source !== "redteam" && source !== "all") throw new Error(`bad source ${source}`);
  return [
    "SELECT timestamp AS ts, _sample_interval AS si,",
    "blob2 AS src, blob3 AS dir, blob4 AS provider, blob5 AS outcome, blob6 AS detected, blob7 AS ray,",
    "blob8 AS scan_id, blob10 AS action,",
    "double1 AS ms, double2 AS status, double3 AS alerts, double4 AS redaction, double5 AS incomplete, double6 AS decided",
    `FROM ${AE_DATASET}`,
    `WHERE blob1 = '${AE_SCHEMA}' AND timestamp > NOW() - INTERVAL '${hours}' HOUR`,
    source === "all" ? "" : `AND blob2 = '${source}'`,
    // By the ALIAS: `timestamp AS ts … ORDER BY timestamp` is a 422 ("unable to find type of column"), checked live.
    `ORDER BY ts DESC LIMIT ${ROW_CAP}`,
    "FORMAT JSON",
  ]
    .filter(Boolean)
    .join(" ");
}

// ── rows ─────────────────────────────────────────────────────────────────────
export interface VerdictRow {
  ts: number; // epoch ms
  si: number; // how many verdicts this stored row stands for (1 = not sampled)
  src: VerdictSource;
  dir: "prompt" | "reply";
  provider: ExternalGuardrailProvider;
  outcome: VerdictOutcome;
  detected: string[];
  ray: string | null;
  action: string | null;
  ms: number | null;
  alerts: boolean;
  redaction: boolean;
  incomplete: boolean;
  decided: boolean;
}

const NAME = /^[A-Za-z0-9_.:\-/ ]{1,80}$/;
const num = (v: unknown): number => (typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN);

// AE's DateTime as the SQL API returns it: "2026-10-09 08:34:31", in UTC (checked against NOW() and the clock).
// Anything else is not a time this reader knows.
export function parseAeTime(v: unknown): number {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(v)) return NaN;
  return Date.parse(v.replace(" ", "T") + "Z");
}

// A row this reader does not recognise is dropped and counted, never guessed at — a renamed outcome must not
// be counted as anything. Names are re-checked: the dataset is ours, but the reader does not trust that.
export function parseRow(r: unknown): VerdictRow | null {
  if (!r || typeof r !== "object") return null;
  const o = r as Record<string, unknown>;
  const ts = parseAeTime(o.ts);
  const provider = o.provider as ExternalGuardrailProvider;
  const outcome = o.outcome as VerdictOutcome;
  if (!Number.isFinite(ts) || !PROVIDER_IDS.includes(provider) || !OUTCOMES.includes(outcome)) return null;
  if (o.dir !== "prompt" && o.dir !== "reply") return null;
  if (o.src !== "chat" && o.src !== "redteam") return null;
  const si = num(o.si);
  const ms = num(o.ms);
  return {
    ts,
    si: Number.isFinite(si) && si >= 1 ? si : 1,
    src: o.src,
    dir: o.dir,
    provider,
    outcome,
    detected: typeof o.detected === "string" && o.detected ? o.detected.split(",").filter((d) => NAME.test(d)) : [],
    ray: typeof o.ray === "string" && /^[A-Za-z0-9]{1,64}$/.test(o.ray) ? o.ray : null,
    action: o.action === "deny" || o.action === "abort" ? o.action : null,
    ms: outcome !== "not_run" && Number.isFinite(ms) && ms >= 0 ? ms : null,
    alerts: num(o.alerts) === 1,
    redaction: num(o.redaction) === 1,
    incomplete: num(o.incomplete) === 1,
    decided: num(o.decided) === 1,
  };
}

// ── aggregation (pure) ───────────────────────────────────────────────────────
export interface VendorStats {
  provider: ExternalGuardrailProvider;
  dir: "prompt" | "reply";
  // Weighted counts (sum of _sample_interval). `checked` = verdicts that ran: block + allow + error + failedOpen.
  checked: number;
  block: number;
  allow: number; // every allow, alerts included
  alerts: number; // allows with alerts (detectOnly) — a subset of allow
  redaction: number; // allows with a redaction requested, not applied — a subset of allow
  incomplete: number;
  error: number; // fail closed: the turn stopped without a verdict
  failedOpen: number; // fail open: the turn went on without a verdict
  notRun: number;
  decided: number; // times this vendor's verdict stopped the turn
  // Over the stored rows that ran and timed (unweighted); null when there are none — never 0 ms.
  latencyN: number;
  p50Ms: number | null;
  p95Ms: number | null;
  topDetections: { name: string; count: number }[];
  lastTs: number | null; // the newest check that ran (not not_run), epoch ms — Settings' "last checked"
}

export interface SeriesPoint {
  t: string; // bucket start, ISO
  block: number;
  alerts: number;
  allow: number; // clean allows only (alerts counted apart)
  error: number; // error + failed open: no verdict
}

export interface Disagreement {
  ts: number;
  ray: string;
  dir: "prompt" | "reply";
  verdicts: { provider: ExternalGuardrailProvider; outcome: "block" | "allow"; alerts: boolean }[];
}

export interface GuardrailAnalyticsBody {
  rangeHours: number;
  since: string;
  until: string;
  source: SourceFilter;
  rowsRead: number;
  rowsDropped: number; // rows of a shape this reader does not know
  capped: boolean;
  sampled: boolean;
  totals: { turns: number; verdicts: number; block: number; alerts: number; error: number; failedOpen: number };
  vendors: VendorStats[];
  bucket: SeriesBucket;
  series: SeriesPoint[];
  // Turns where at least one vendor blocked and another allowed the same text (errors and not-run excluded:
  // they are not verdicts). Over stored rows only: with sampling, rows of a turn can be missing.
  disagreements: { count: number; latest: Disagreement[] };
}

const pct = (sorted: number[], p: number) => sorted[nearestRank(sorted.length, p) - 1];

export function aggregate(
  rows: VerdictRow[],
  opts: { hours: number; now: number; source: SourceFilter; rowsRead: number; rowsDropped: number },
): GuardrailAnalyticsBody {
  const sinceMs = opts.now - opts.hours * 3_600_000;
  const byKey = new Map<string, { s: VendorStats; ms: number[]; det: Map<string, number> }>();
  const totals = { turns: 0, verdicts: 0, block: 0, alerts: 0, error: 0, failedOpen: 0 };
  const turnKeys = new Set<string>();

  for (const r of rows) {
    const key = `${r.provider}|${r.dir}`;
    let e = byKey.get(key);
    if (!e) {
      e = {
        s: {
          provider: r.provider, dir: r.dir, checked: 0, block: 0, allow: 0, alerts: 0, redaction: 0, incomplete: 0,
          error: 0, failedOpen: 0, notRun: 0, decided: 0, latencyN: 0, p50Ms: null, p95Ms: null, topDetections: [],
          lastTs: null,
        },
        ms: [],
        det: new Map(),
      };
      byKey.set(key, e);
    }
    const s = e.s;
    const w = r.si;
    if (r.outcome === "not_run") {
      s.notRun += w;
      continue;
    }
    s.checked += w;
    s.lastTs = Math.max(s.lastTs ?? 0, r.ts);
    totals.verdicts += w;
    if (r.decided) s.decided += w;
    if (r.incomplete) s.incomplete += w;
    if (r.outcome === "block") {
      s.block += w;
      totals.block += w;
    } else if (r.outcome === "allow") {
      s.allow += w;
      if (r.alerts) {
        s.alerts += w;
        totals.alerts += w;
      }
      if (r.redaction) s.redaction += w;
    } else if (r.outcome === "error") {
      s.error += w;
      totals.error += w;
    } else {
      s.failedOpen += w;
      totals.failedOpen += w;
    }
    if (r.ms != null) e.ms.push(r.ms);
    if (r.outcome !== "error" && r.outcome !== "failed_open") {
      for (const d of r.detected) e.det.set(d, (e.det.get(d) ?? 0) + w);
    }
    if (r.ray && r.dir === "prompt") turnKeys.add(r.ray);
  }
  totals.turns = turnKeys.size;

  const order = (p: ExternalGuardrailProvider) => PROVIDER_IDS.indexOf(p);
  const vendors = [...byKey.values()]
    .map(({ s, ms, det }) => {
      const sorted = [...ms].sort((a, b) => a - b);
      return {
        ...s,
        latencyN: sorted.length,
        p50Ms: sorted.length ? pct(sorted, 50) : null,
        p95Ms: sorted.length ? pct(sorted, 95) : null,
        topDetections: [...det.entries()]
          .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .slice(0, 5)
          .map(([name, count]) => ({ name, count })),
      };
    })
    .sort((a, b) => order(a.provider) - order(b.provider) || (a.dir === b.dir ? 0 : a.dir === "prompt" ? -1 : 1));

  // Series: every bucket across the window, prefilled, so a quiet stretch reads as zero verdicts — which it is
  // (the window was read; the dataset simply holds none there), unlike an unread stretch on the edge tab.
  const { bucket, stepMs } = bucketFor(opts.hours);
  const series = new Map<string, SeriesPoint>();
  const first = Math.floor(sinceMs / stepMs) * stepMs;
  for (let t = first; t <= opts.now; t += stepMs) {
    const k = new Date(t).toISOString();
    series.set(k, { t: k, block: 0, alerts: 0, allow: 0, error: 0 });
  }
  for (const r of rows) {
    if (r.outcome === "not_run") continue;
    const k = new Date(Math.floor(r.ts / stepMs) * stepMs).toISOString();
    const p = series.get(k);
    if (!p) continue; // outside the prefilled window (clock skew at the edges)
    if (r.outcome === "block") p.block += r.si;
    else if (r.outcome === "allow") (r.alerts ? (p.alerts += r.si) : (p.allow += r.si));
    else p.error += r.si;
  }

  // Disagreements, over stored rows grouped by ray + direction.
  const turns = new Map<string, Disagreement>();
  for (const r of rows) {
    if (!r.ray || (r.outcome !== "block" && r.outcome !== "allow")) continue;
    const k = `${r.ray}|${r.dir}`;
    const d = turns.get(k) ?? { ts: r.ts, ray: r.ray, dir: r.dir, verdicts: [] };
    d.ts = Math.max(d.ts, r.ts);
    if (!d.verdicts.some((v) => v.provider === r.provider)) {
      d.verdicts.push({ provider: r.provider, outcome: r.outcome, alerts: r.alerts });
    }
    turns.set(k, d);
  }
  const split = [...turns.values()]
    .filter((d) => d.verdicts.some((v) => v.outcome === "block") && d.verdicts.some((v) => v.outcome === "allow"))
    .map((d) => ({ ...d, verdicts: [...d.verdicts].sort((a, b) => order(a.provider) - order(b.provider)) }))
    .sort((a, b) => b.ts - a.ts);

  return {
    rangeHours: opts.hours,
    since: new Date(sinceMs).toISOString(),
    until: new Date(opts.now).toISOString(),
    source: opts.source,
    rowsRead: opts.rowsRead,
    rowsDropped: opts.rowsDropped,
    capped: opts.rowsRead >= ROW_CAP,
    sampled: rows.some((r) => r.si > 1),
    totals,
    vendors,
    bucket,
    series: [...series.values()],
    disagreements: { count: split.length, latest: split.slice(0, 10) },
  };
}

// ── handler ──────────────────────────────────────────────────────────────────
export async function handleGuardrailAnalytics(url: URL, env: Env, fetchImpl: typeof fetch = fetch): Promise<Response> {
  // (No "is this Worker writing?" flag: `wrangler dev` provides a stand-in binding, so its presence proves nothing.)
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) return Response.json({ configured: false });
  const h = Number(url.searchParams.get("hours") ?? 24);
  const hours = ((RANGE_HOURS as readonly number[]).includes(h) ? h : 24) as (typeof RANGE_HOURS)[number];
  const s = url.searchParams.get("source");
  const source: SourceFilter = s === "redteam" || s === "all" ? s : "chat";
  try {
    const res = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: "POST",
      headers: { authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
      body: buildSql(hours, source),
    });
    const text = await res.text();
    if (!res.ok) {
      // The SQL API's error text can echo the statement; only the status goes to the client.
      console.error("guardrail-analytics: AE SQL", res.status, text.slice(0, 500));
      const hint = res.status === 401 || res.status === 403 ? " — the token needs Account Analytics: Read" : "";
      return Response.json({ configured: true, error: `Analytics Engine returned HTTP ${res.status}${hint}` }, { status: 502 });
    }
    const body = JSON.parse(text) as { data?: unknown[] };
    const raw = Array.isArray(body.data) ? body.data : [];
    const rows = raw.map(parseRow).filter((r): r is VerdictRow => r != null);
    return Response.json(
      {
        configured: true,
        ...aggregate(rows, { hours, now: Date.now(), source, rowsRead: raw.length, rowsDropped: raw.length - rows.length }),
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (err) {
    return Response.json({ configured: true, error: clientError(err, "Guardrail analytics") }, { status: 502 });
  }
}

