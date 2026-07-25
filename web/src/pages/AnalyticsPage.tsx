// Security analytics dashboard shell: shared range picker, per-tab filters, and
// the fetch/refresh cycle. The tabs themselves live in components/analytics/.
import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { EdgeTab } from "../components/analytics/EdgeTab";
import { GatewayTab } from "../components/analytics/GatewayTab";
import { PromptLogTab } from "../components/analytics/PromptLogTab";
import {
  clearPromptLog,
  getAnalytics,
  getGatewayAnalytics,
  getModels,
  getPromptAnalytics,
  getPromptLog,
} from "../lib/api";
import { fmtTime } from "../lib/format";
import type {
  Analytics,
  GatewayAnalytics as GatewayAnalyticsData,
  GatewayOption,
  PromptAnalytics,
  PromptLog,
} from "../lib/types";

const RANGES = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];
const REFRESH_MS = 60_000;

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
          ) : (
            <EdgeTab data={data} hours={hours} />
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
