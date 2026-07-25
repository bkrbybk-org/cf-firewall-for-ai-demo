// Cloudflare GraphQL Analytics API client + the two queries the app uses.

import { GRAPHQL_ENDPOINT } from "./config";
import type { AnalyticsSummary, GatewayAnalytics, VerdictResult, NeuronUsage } from "./types";

// Time-bucket scaffold shared by the zone analytics and the gateway analytics:
// hourly buckets up to 48h, daily beyond. Buckets are pre-filled across the
// whole range so gaps render as zero rather than going missing.
function makeBuckets<T extends { t: string }>(
  now: number,
  hours: number,
  blank: (t: string) => T,
): { bucket: "hour" | "day"; stepMs: number; series: Map<string, T>; floor: (iso: string) => string } {
  const bucket: "hour" | "day" = hours <= 48 ? "hour" : "day";
  const stepMs = bucket === "hour" ? 3_600_000 : 86_400_000;
  const series = new Map<string, T>();
  for (let t = Math.floor((now - hours * 3_600_000) / stepMs) * stepMs; t <= now; t += stepMs) {
    const key = new Date(t).toISOString();
    series.set(key, blank(key));
  }
  const floor = (iso: string) => new Date(Math.floor(Date.parse(iso) / stepMs) * stepMs).toISOString();
  return { bucket, stepMs, series, floor };
}

// Single place that talks to the GraphQL API. Returns the parsed body so
// callers can inspect `errors` and `data` themselves.
export async function gqlFetch<T>(
  token: string,
  query: string,
  variables: Record<string, unknown>,
): Promise<{ data?: T; errors?: { message: string }[] }> {
  const res = await fetch(GRAPHQL_ENDPOINT, {
    method: "POST",
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return res.json();
}

// List every AI Gateway id in the account via the REST API. Needs an API
// token with "AI Gateway Read" (the token is account-scoped — it cannot be
// restricted to one gateway). Returns the gateway ids (the id IS the name);
// the list carries no guardrails flag, so `guarded` is derived elsewhere.
export async function listAiGateways(accountId: string, token: string): Promise<string[]> {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai-gateway/gateways?per_page=50`,
    { headers: { authorization: "Bearer " + token } },
  );
  const j = (await res.json()) as {
    success?: boolean;
    errors?: { message: string }[];
    result?: { id?: string }[];
  };
  if (!j.success || !Array.isArray(j.result)) {
    throw new Error(j.errors?.[0]?.message || `AI Gateway list failed (HTTP ${res.status})`);
  }
  return j.result.map((g) => String(g.id ?? "")).filter(Boolean);
}

// --- Live edge verdict ---------------------------------------------------
// Look up what Cloudflare's edge did to a given request (by ray id): the
// security action, matched WAF rule(s), and the Firewall for AI detection
// scores. Powers GET /api/verdict.

type VerdictData = {
  viewer?: {
    zones?: { http?: Record<string, unknown>[]; fw?: Record<string, unknown>[] }[];
  };
};

export async function queryVerdict(
  zoneId: string,
  token: string,
  ray: string,
): Promise<VerdictResult> {
  const since = new Date(Date.now() - 15 * 60000).toISOString();
  const until = new Date(Date.now() + 60000).toISOString();
  const query = `query($z:String!,$s:Time!,$e:Time!,$ray:String!){viewer{zones(filter:{zoneTag:$z}){
    http:httpRequestsAdaptive(limit:1,filter:{datetime_geq:$s,datetime_leq:$e,rayName:$ray}){
      edgeResponseStatus securityAction securitySource webAssetsLabelsManaged
      firewallForAiInjectionScore firewallForAiPiiCategories firewallForAiUnsafeTopicCategories
      firewallForAiCustomTopicCategories { topicLabel score } firewallForAiCustomTopicCategoriesScoresMin
    }
    fw:firewallEventsAdaptive(limit:20,filter:{datetime_geq:$s,datetime_leq:$e,rayName:$ray},orderBy:[datetime_DESC]){
      action ruleId rulesetId description source
    }
  }}}`;

  const j = await gqlFetch<VerdictData>(token, query, {
    z: zoneId,
    s: since,
    e: until,
    ray,
  });
  if (j.errors?.length) {
    return {
      found: false, httpStatus: null, securityAction: null, securitySource: null,
      ai: null, rules: [], cfLlmLabeled: false, scored: false, error: j.errors[0].message,
    };
  }
  const zone = j.data?.viewer?.zones?.[0];
  const http = zone?.http?.[0] ?? null;
  const fw = zone?.fw ?? [];
  const injectionScore = (http?.firewallForAiInjectionScore as number) ?? null;
  const labels = (http?.webAssetsLabelsManaged as string[]) ?? [];
  return {
    found: !!http || fw.length > 0,
    httpStatus: (http?.edgeResponseStatus as number) ?? null,
    securityAction: (http?.securityAction as string) ?? null,
    securitySource: (http?.securitySource as string) ?? null,
    ai: http
      ? {
          injectionScore,
          piiCategories: (http.firewallForAiPiiCategories as string[]) ?? [],
          unsafeTopicCategories: (http.firewallForAiUnsafeTopicCategories as string[]) ?? [],
          customTopicCategories: (
            (http.firewallForAiCustomTopicCategories as
              | { topicLabel: string; score: number }[]
              | undefined) ?? []
          ).map((c) => ({ label: c.topicLabel, score: c.score })),
          customTopicScoreMin:
            (http.firewallForAiCustomTopicCategoriesScoresMin as number) ?? null,
        }
      : null,
    // injectionScore 100 = "Cloudflare did not score the request" → not actually scanned.
    scored: injectionScore != null && injectionScore !== 100,
    cfLlmLabeled: labels.includes("cf-llm"),
    rules: fw.map((e) => ({
      ruleId: String(e.ruleId ?? ""),
      action: String(e.action ?? ""),
      description: String(e.description ?? ""),
      source: String(e.source ?? ""),
    })),
  };
}

// --- Workers AI Neuron usage --------------------------------------------
// Sums Neurons consumed by the account today (since 00:00 UTC), to warn when
// approaching the free daily allocation. Powers GET /api/neurons.

type NeuronData = {
  viewer?: {
    accounts?: {
      aiInferenceAdaptiveGroups?: { count: number; sum: { totalNeurons: number } }[];
    }[];
  };
};

export async function queryNeuronUsage(
  accountId: string,
  token: string,
): Promise<NeuronUsage> {
  const now = new Date();
  const since = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
  ).toISOString();
  const until = new Date(Date.now() + 60_000).toISOString();
  const query = `query($acc:String!,$s:Time!,$e:Time!){viewer{accounts(filter:{accountTag:$acc}){
    aiInferenceAdaptiveGroups(limit:1,filter:{datetime_geq:$s,datetime_leq:$e}){
      count
      sum { totalNeurons }
    }
  }}}`;

  const j = await gqlFetch<NeuronData>(token, query, { acc: accountId, s: since, e: until });
  if (j.errors?.length) {
    return { totalNeurons: 0, requestCount: 0, error: j.errors[0].message };
  }
  const row = j.data?.viewer?.accounts?.[0]?.aiInferenceAdaptiveGroups?.[0];
  return { totalNeurons: row?.sum?.totalNeurons ?? 0, requestCount: row?.count ?? 0 };
}

// --- Security analytics dashboard ---------------------------------------
// Pulls raw firewall events + AI-scored chat requests for the last N hours
// and aggregates them into the dashboard payload. Raw rows + Worker-side
// aggregation keeps the GraphQL side simple (no Groups/name joins) — a demo
// zone stays well under the row limits.

type AnalyticsData = {
  viewer?: {
    zones?: {
      fw?: { datetime: string; action: string; ruleId: string; description: string }[];
      http?: {
        datetime: string;
        firewallForAiInjectionScore: number | null;
        firewallForAiPiiCategories: string[] | null;
        firewallForAiUnsafeTopicCategories: string[] | null;
        firewallForAiCustomTopicCategories: { topicLabel: string; score: number }[] | null;
        webAssetsLabelsManaged: string[] | null;
      }[];
    }[];
  };
};

const EVENT_LIMIT = 500;

export async function queryAnalytics(
  zoneId: string,
  token: string,
  hours: number,
): Promise<AnalyticsSummary> {
  const now = Date.now();
  const since = new Date(now - hours * 3_600_000).toISOString();
  const until = new Date(now + 60_000).toISOString();
  const query = `query($z:String!,$s:Time!,$e:Time!,$limit:Int!){viewer{zones(filter:{zoneTag:$z}){
    fw:firewallEventsAdaptive(limit:$limit,filter:{datetime_geq:$s,datetime_leq:$e},orderBy:[datetime_DESC]){
      datetime action ruleId description
    }
    http:httpRequestsAdaptive(limit:$limit,filter:{datetime_geq:$s,datetime_leq:$e,clientRequestPath:"/api/chat"},orderBy:[datetime_DESC]){
      datetime firewallForAiInjectionScore firewallForAiPiiCategories
      firewallForAiUnsafeTopicCategories
      firewallForAiCustomTopicCategories { topicLabel score }
      webAssetsLabelsManaged
    }
  }}}`;

  const empty: AnalyticsSummary = {
    rangeHours: hours, since, until, totalEvents: 0, actions: {}, topRules: [],
    series: [], bucket: hours <= 48 ? "hour" : "day", aiScored: 0, scoreBuckets: [], piiRequests: 0,
    unsafeTopics: [], piiCategories: [], customTopics: [], scannedRequests: 0, labeledRequests: 0,
  };

  const j = await gqlFetch<AnalyticsData>(token, query, { z: zoneId, s: since, e: until, limit: EVENT_LIMIT });
  if (j.errors?.length) return { ...empty, error: j.errors[0].message };

  const zone = j.data?.viewer?.zones?.[0];
  const fw = zone?.fw ?? [];
  const http = zone?.http ?? [];

  // Action + rule tallies.
  const actions: Record<string, number> = {};
  const ruleCounts = new Map<string, { name: string; action: string; count: number }>();
  for (const e of fw) {
    actions[e.action] = (actions[e.action] ?? 0) + 1;
    const name = e.description || e.ruleId || "(unnamed rule)";
    const key = name + "|" + e.action;
    const row = ruleCounts.get(key) ?? { name, action: e.action, count: 0 };
    row.count++;
    ruleCounts.set(key, row);
  }
  const topRules = [...ruleCounts.values()].sort((a, b) => b.count - a.count).slice(0, 8);

  // Time series: hourly buckets up to 48h, daily beyond (shared helper).
  const { bucket, series, floor } = makeBuckets(now, hours, (t) => ({ t, block: 0, log: 0, other: 0 }));
  for (const e of fw) {
    const row = series.get(floor(e.datetime));
    if (!row) continue;
    const a = e.action.toLowerCase();
    if (/block|drop/.test(a)) row.block++;
    else if (/log|link_maze/.test(a)) row.log++;
    else row.other++;
  }

  // Injection-score histogram over AI-scored chat requests. Score 100 means
  // "not scored"; low scores = likely attack.
  const buckets = [
    { label: "1–10 (attack)", min: 1, max: 10, count: 0 },
    { label: "11–20", min: 11, max: 20, count: 0 },
    { label: "21–50", min: 21, max: 50, count: 0 },
    { label: "51–99 (clean)", min: 51, max: 99, count: 0 },
  ];
  let aiScored = 0;
  let piiRequests = 0;
  let labeledRequests = 0;
  // Per-category detection tallies. Custom topics also accumulate strength
  // (100 − score) so the UI can show a mean match strength, not a raw score.
  const unsafeCounts = new Map<string, number>();
  const piiCounts = new Map<string, number>();
  const customCounts = new Map<string, { count: number; strengthSum: number }>();
  for (const r of http) {
    const s = r.firewallForAiInjectionScore;
    if (s != null && s !== 100) {
      aiScored++;
      const b = buckets.find((x) => s >= x.min && s <= x.max);
      if (b) b.count++;
    }
    const pii = r.firewallForAiPiiCategories ?? [];
    if (pii.length > 0) piiRequests++;
    for (const p of pii) piiCounts.set(p, (piiCounts.get(p) ?? 0) + 1);
    for (const u of r.firewallForAiUnsafeTopicCategories ?? []) {
      unsafeCounts.set(u, (unsafeCounts.get(u) ?? 0) + 1);
    }
    for (const c of r.firewallForAiCustomTopicCategories ?? []) {
      const row = customCounts.get(c.topicLabel) ?? { count: 0, strengthSum: 0 };
      row.count++;
      row.strengthSum += Math.max(0, Math.min(100, 100 - c.score));
      customCounts.set(c.topicLabel, row);
    }
    if ((r.webAssetsLabelsManaged ?? []).includes("cf-llm")) labeledRequests++;
  }

  const byCountDesc = <T extends { count: number }>(a: T, b: T) => b.count - a.count;

  return {
    ...empty,
    totalEvents: fw.length,
    actions,
    topRules,
    series: [...series.values()],
    bucket,
    aiScored,
    scoreBuckets: buckets.map(({ label, count }) => ({ label, count })),
    piiRequests,
    unsafeTopics: [...unsafeCounts.entries()].map(([code, count]) => ({ code, count })).sort(byCountDesc),
    piiCategories: [...piiCounts.entries()].map(([name, count]) => ({ name, count })).sort(byCountDesc),
    customTopics: [...customCounts.entries()]
      .map(([label, r]) => ({ label, count: r.count, avgStrength: Math.round(r.strengthSum / r.count) }))
      .sort(byCountDesc),
    scannedRequests: http.length,
    labeledRequests,
  };
}

// --- AI Gateway analytics ------------------------------------------------
// AI Gateway has no GraphQL dataset, so this reads the logs REST API and sums
// the rows Worker-side (same shape as queryAnalytics). Needs an API token with
// "AI Gateway Read" — the same scope the gateway dropdown already requires.
//
// NOTE: gateway logs are ACCOUNT-scoped, not zone-scoped: they include any
// other app routing through the same gateway. The UI says so explicitly.

type GatewayLog = {
  created_at?: string;
  cached?: boolean;
  duration?: number;
  cost?: number;
  tokens_in?: number;
  tokens_out?: number;
  model?: string;
  success?: boolean;
  status_code?: number;
};

// The logs API caps per_page at 50, so walk pages until we have LIMIT rows.
const GATEWAY_LOG_LIMIT = 500;
const GATEWAY_PAGE_SIZE = 50;

function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return Math.round(sorted[i]);
}

export async function queryGatewayLogs(
  accountId: string,
  token: string,
  gatewayId: string,
  guarded: boolean,
  hours: number,
): Promise<GatewayAnalytics> {
  const now = Date.now();
  const since = new Date(now - hours * 3_600_000).toISOString();
  const until = new Date(now + 60_000).toISOString();

  const { bucket, series, floor } = makeBuckets(now, hours, (t) => ({ t, hit: 0, miss: 0, error: 0 }));
  const empty: GatewayAnalytics = {
    gatewayId, guarded, rangeHours: hours, since, until,
    requests: 0, cachedRequests: 0, totalCost: 0, tokensIn: 0, tokensOut: 0,
    avgMs: 0, p50Ms: 0, p95Ms: 0, errors: 0, statusCodes: [], byModel: [],
    series: [...series.values()], bucket, truncated: false,
  };

  const rows: GatewayLog[] = [];
  let truncated = false;
  for (let page = 1; rows.length < GATEWAY_LOG_LIMIT; page++) {
    const qs = new URLSearchParams({
      start_date: since,
      end_date: until,
      page: String(page),
      per_page: String(GATEWAY_PAGE_SIZE),
      order_by: "created_at",
      order_by_direction: "desc",
    });
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/logs?${qs}`,
      { headers: { authorization: "Bearer " + token } },
    );
    const j = (await res.json()) as {
      success?: boolean;
      errors?: { message: string }[];
      result?: GatewayLog[];
    };
    if (!j.success || !Array.isArray(j.result)) {
      // Page 1 failing is a real error; a later page failing just truncates.
      if (page === 1) {
        return { ...empty, error: j.errors?.[0]?.message || `AI Gateway logs failed (HTTP ${res.status})` };
      }
      truncated = true;
      break;
    }
    rows.push(...j.result);
    if (j.result.length < GATEWAY_PAGE_SIZE) break; // last page
    if (rows.length >= GATEWAY_LOG_LIMIT) truncated = true;
  }

  let cachedRequests = 0, totalCost = 0, tokensIn = 0, tokensOut = 0, errors = 0;
  const durations: number[] = [];
  const statusCounts = new Map<number, number>();
  const modelRows = new Map<string, { count: number; tokensIn: number; tokensOut: number; cost: number }>();

  for (const r of rows) {
    const failed = r.success === false;
    if (failed) errors++;
    if (r.cached) cachedRequests++;
    totalCost += r.cost ?? 0;
    tokensIn += r.tokens_in ?? 0;
    tokensOut += r.tokens_out ?? 0;
    if (typeof r.duration === "number") durations.push(r.duration);
    if (typeof r.status_code === "number") {
      statusCounts.set(r.status_code, (statusCounts.get(r.status_code) ?? 0) + 1);
    }
    const model = r.model || "(unknown)";
    const m = modelRows.get(model) ?? { count: 0, tokensIn: 0, tokensOut: 0, cost: 0 };
    m.count++;
    m.tokensIn += r.tokens_in ?? 0;
    m.tokensOut += r.tokens_out ?? 0;
    m.cost += r.cost ?? 0;
    modelRows.set(model, m);

    if (r.created_at) {
      const b = series.get(floor(r.created_at));
      if (b) {
        if (failed) b.error++;
        else if (r.cached) b.hit++;
        else b.miss++;
      }
    }
  }

  durations.sort((a, b) => a - b);
  const avgMs = durations.length
    ? Math.round(durations.reduce((n, d) => n + d, 0) / durations.length)
    : 0;

  return {
    ...empty,
    requests: rows.length,
    cachedRequests,
    totalCost,
    tokensIn,
    tokensOut,
    avgMs,
    p50Ms: percentile(durations, 50),
    p95Ms: percentile(durations, 95),
    errors,
    statusCodes: [...statusCounts.entries()]
      .map(([code, count]) => ({ code, count }))
      .sort((a, b) => b.count - a.count),
    byModel: [...modelRows.entries()]
      .map(([model, m]) => ({ model, ...m }))
      .sort((a, b) => b.count - a.count),
    series: [...series.values()],
    truncated,
  };
}
