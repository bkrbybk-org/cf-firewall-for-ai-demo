// Security analytics dashboard shell: shared range picker, per-tab filters, and
// the fetch/refresh cycle. The tabs themselves live in components/analytics/.
import { useCallback, useEffect, useState } from "react";
import { CalendarClock, Crosshair, RefreshCw, X } from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { EdgeTab, type EdgeDrill } from "../components/analytics/EdgeTab";
import { GatewayTab } from "../components/analytics/GatewayTab";
import { PromptLogTab, type PromptLogView } from "../components/analytics/PromptLogTab";
import {
  clearPromptLog,
  getAnalytics,
  getGatewayAnalytics,
  getModels,
  getPromptAnalytics,
  getPromptLog,
  type TimeWindow,
} from "../lib/api";
import { fmtTime } from "../lib/format";
import type {
  Analytics,
  GatewayAnalytics as GatewayAnalyticsData,
  GatewayOption,
  PromptAnalytics,
  PromptLog,
} from "../lib/types";

// <input type="datetime-local"> reads/writes local time with no timezone
// suffix ("2026-07-31T14:30"), which Date() parses as local time — exactly
// what the picker should mean ("2:30pm here"), so no manual TZ math needed.
const toLocalMs = (v: string): number | undefined => {
  if (!v) return undefined;
  const ms = new Date(v).getTime();
  return Number.isFinite(ms) ? ms : undefined;
};
const fromMs = (ms: number): string => {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

const RANGES = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];
// Matches OUTCOME_TONE in PromptLogTab so the filter chips read as the same
// vocabulary as the rows they filter.
const OUTCOME_FILTERS = [
  { value: "reply", label: "replied", tone: "border-cf-green/50 text-cf-green" },
  { value: "guardrails", label: "guardrails-blocked", tone: "border-cf-purple/50 text-cf-purple" },
  { value: "error", label: "error", tone: "border-cf-red/50 text-cf-red" },
];
// The prompt log is deliberately small and often reviewed as "the whole demo
// session so far", so it gets an explicit all-time option the other tabs
// don't need (their datasets are too large to ever want unbounded).
const PLOG_RANGES = [...RANGES, { label: "all", hours: 0 }];
const REFRESH_MS = 60_000;

type Tab = "edge" | "gateway" | "promptlog";

export function AnalyticsPage() {
  const [tab, setTab] = useState<Tab>("edge");
  // Prompt log feature flag (PROMPT_LOG_ENABLED + a bound D1), served by
  // /api/models. Off means the tab does not exist — not that it renders a
  // setup hint — and the edge tab's drill-through has nowhere to land, so it
  // is withheld too. Starts false so nothing flashes into view before the
  // response arrives; the server refuses the data either way.
  const [promptLogEnabled, setPromptLogEnabled] = useState(false);
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
  // Multi-select: any combination of outcomes at once (e.g. reply + error,
  // hiding only guardrails-blocked). Empty = no filter, same as before.
  const [plogOutcomes, setPlogOutcomes] = useState<string[]>([]);
  const [plogHours, setPlogHours] = useState(1); // latest 1h by default
  // Custom date/time range: a fifth option alongside the presets, not a
  // separate control — only one of {preset, custom} is ever in effect.
  const [plogCustom, setPlogCustom] = useState(false);
  // Paging, sorting and text search for the prompt log. These live here, next
  // to the fetch, because all three are now resolved in SQL — the table shows
  // one page of the whole log rather than a slice of the newest 200 rows.
  const [plogView, setPlogView] = useState<PromptLogView>({
    page: 0,
    pageSize: 25,
    sort: "ts",
    dir: "desc", // newest first — the log is read as "what just happened"
    q: "",
  });
  // Context banner set when the user drilled in from the edge tab, so the
  // prompt log says which slice they clicked — and, when that slice was
  // blocked at the edge, that those prompts cannot appear here at all.
  const [drill, setDrill] = useState<EdgeDrill | null>(null);

  // Drill in from the edge tab: switch to the prompt log and widen its window
  // to match the edge range being viewed, so the two views describe the same
  // span. The log can only ever show prompts that REACHED the Worker — the
  // banner carries that caveat when the clicked slice was blocked.
  const onDrill = useCallback(
    (d: EdgeDrill) => {
      if (!promptLogEnabled) return;
      setDrill(d);
      setPlogCustom(false);
      setPlogHours(hours);
      setTab("promptlog");
    },
    [hours, promptLogEnabled],
  );
  const [plogSince, setPlogSince] = useState(""); // datetime-local strings;
  const [plogUntil, setPlogUntil] = useState(""); // "" = open-ended on that side
  const plogWindow: TimeWindow = plogCustom
    ? { sinceMs: toLocalMs(plogSince), untilMs: toLocalMs(plogUntil) }
    : { hours: plogHours };

  // Changing WHICH rows are selected has to restart paging — page 5 of a
  // narrower result set is either empty or a different slice than the user
  // thinks they are looking at. No-ops when already on page 1, so this cannot
  // feed back into the fetch effect.
  useEffect(() => {
    setPlogView((v) => (v.page === 0 ? v : { ...v, page: 0 }));
  }, [plogRoute, plogOutcomes, plogCustom, plogHours, plogSince, plogUntil]);

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

  // Gateway list and the prompt-log flag are both served by /api/models,
  // alongside the model menu.
  useEffect(() => {
    getModels()
      .then((d) => {
        setGateways(d.gateways ?? []);
        setGatewayId((cur) => cur || d.defaultGateway || d.gateways?.[0]?.id || "");
        const enabled = d.promptLog?.enabled ?? false;
        setPromptLogEnabled(enabled);
        // Deep links and a remembered tab can both point at a tab that no
        // longer exists; fall back rather than rendering an empty shell.
        if (!enabled) {
          setTab((cur) => (cur === "promptlog" ? "edge" : cur));
          setDrill(null);
        }
      })
      .catch(() => {});
  }, []);

  // Rollups share the same time frame as the rows so both describe the same
  // window (see TimeWindow — hours preset, or an explicit custom range). The
  // rollups always cover the whole window; only the row query is paged.
  const loadPlog = useCallback(async (route: string, outcome: string[], window: TimeWindow, view: PromptLogView) => {
    setLoading(true);
    try {
      const [log, stats] = await Promise.all([
        getPromptLog({
          route,
          outcome,
          q: view.q.trim() || undefined,
          sort: view.sort,
          dir: view.dir,
          limit: view.pageSize,
          offset: view.page * view.pageSize,
          ...window,
        }),
        getPromptAnalytics(window),
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
    else loadPlog(plogRoute, plogOutcomes, plogWindow, plogView);
    // plogWindow is a fresh object every render, so its own primitive inputs
    // — not the object itself — are the real dependencies here. plogOutcomes
    // is an array too, but it only ever changes via setPlogOutcomes (a new
    // array each time), so referential comparison here is fine. plogView is
    // likewise only replaced wholesale, so it can be depended on directly.
  }, [tab, hours, gatewayId, plogRoute, plogOutcomes, plogCustom, plogHours, plogSince, plogUntil, plogView, load, loadGw, loadPlog]);

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

      {/* `relative` is load-bearing: Tailwind's `sr-only` (the prompt log's
          "Expand" column header) is position:absolute, and without a positioned
          ancestor its containing block is the document, not this scroll box —
          so it escapes overflow-y clipping, inflates documentElement.scrollHeight
          as the table scrolls, and lets the whole shell (footer included) scroll
          off the viewport. */}
      <main className="relative min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
          {/* Tab strip: edge (zone-scoped) vs AI Gateway (account-scoped). */}
          <div className="flex overflow-hidden rounded-full border border-line text-[12.5px] self-start">
            {(
              [
                { id: "edge" as const, label: "AI Security (edge)" },
                { id: "gateway" as const, label: "AI Gateway" },
                // Only offered when there is a log to look at.
                ...(promptLogEnabled ? [{ id: "promptlog" as const, label: "Prompt log" }] : []),
              ]
            ).map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => {
                  // Switching tabs by hand ends the drill context — the banner
                  // would otherwise outlive the click that created it.
                  if (t.id !== "promptlog") setDrill(null);
                  setTab(t.id);
                }}
                className={`px-4 py-1.5 transition ${
                  tab === t.id ? "bg-accent/15 font-bold text-accent" : "bg-surface text-muted hover:bg-surface-hover"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-[12.5px] text-muted">
            {tab === "promptlog" ? (
              <>
                <div className="flex overflow-hidden rounded-full border border-line">
                  {PLOG_RANGES.map((r) => (
                    <button
                      key={r.hours}
                      type="button"
                      onClick={() => {
                        setPlogCustom(false);
                        setPlogHours(r.hours);
                      }}
                      className={`px-3.5 py-1.5 transition ${
                        !plogCustom && plogHours === r.hours
                          ? "bg-accent/15 font-bold text-accent"
                          : "bg-surface hover:bg-surface-hover"
                      }`}
                    >
                      {r.label}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => {
                      // Seed both fields with the currently active preset's
                      // range on first switch, so Custom starts as an
                      // editable version of what was just showing rather
                      // than an empty (all-time) range.
                      if (!plogCustom && !plogSince && !plogUntil) {
                        const now = Date.now();
                        setPlogUntil(fromMs(now));
                        setPlogSince(fromMs(plogHours > 0 ? now - plogHours * 3_600_000 : now - 24 * 3_600_000));
                      }
                      setPlogCustom(true);
                    }}
                    className={`border-l border-line px-3.5 py-1.5 transition ${
                      plogCustom ? "bg-accent/15 font-bold text-accent" : "bg-surface hover:bg-surface-hover"
                    }`}
                  >
                    Custom
                  </button>
                </div>
                {plogCustom && (
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1.5 rounded-xl border border-line bg-surface px-1 py-1 shadow-sm transition focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/20">
                      <CalendarClock size={14} className="ml-1.5 shrink-0 text-subtle" />
                      <label className="flex items-center gap-1.5">
                        <span className="text-subtle">from</span>
                        <input
                          type="datetime-local"
                          value={plogSince}
                          max={plogUntil || undefined}
                          onChange={(e) => setPlogSince(e.target.value)}
                          className="rounded-lg bg-transparent px-1.5 py-1 text-[12.5px] text-text outline-none"
                        />
                      </label>
                      <div className="h-4 w-px bg-line" />
                      <label className="flex items-center gap-1.5">
                        <span className="text-subtle">to</span>
                        <input
                          type="datetime-local"
                          value={plogUntil}
                          min={plogSince || undefined}
                          onChange={(e) => setPlogUntil(e.target.value)}
                          className="rounded-lg bg-transparent px-1.5 py-1 text-[12.5px] text-text outline-none"
                        />
                      </label>
                    </div>
                    {(plogSince || plogUntil) && (
                      <button
                        type="button"
                        onClick={() => {
                          setPlogSince("");
                          setPlogUntil("");
                        }}
                        title="Clear custom range"
                        className="flex items-center gap-1 rounded-full border border-line bg-surface px-2 py-1 text-subtle transition hover:border-line-strong hover:text-text"
                      >
                        <X size={12} />
                        clear
                      </button>
                    )}
                  </div>
                )}
              </>
            ) : (
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
                <div className="flex items-center gap-1.5">
                  Outcome
                  <div className="flex flex-wrap gap-1">
                    {OUTCOME_FILTERS.map((o) => {
                      const active = plogOutcomes.includes(o.value);
                      return (
                        <button
                          key={o.value}
                          type="button"
                          onClick={() =>
                            setPlogOutcomes((cur) =>
                              cur.includes(o.value) ? cur.filter((v) => v !== o.value) : [...cur, o.value],
                            )
                          }
                          aria-pressed={active}
                          className={`rounded-full border px-2.5 py-1 text-[11.5px] font-semibold transition ${
                            active ? o.tone + " bg-current/10" : "border-line text-subtle hover:text-text"
                          }`}
                        >
                          {o.label}
                        </button>
                      );
                    })}
                    {plogOutcomes.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setPlogOutcomes([])}
                        className="rounded-full border border-line px-2.5 py-1 text-[11.5px] text-subtle underline decoration-dotted hover:text-text"
                      >
                        clear
                      </button>
                    )}
                  </div>
                </div>
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

          {tab === "promptlog" && drill && (
            <div className="flex items-start gap-3 rounded-xl border border-accent/40 bg-accent/[0.07] px-3.5 py-2.5">
              <Crosshair size={15} className="mt-0.5 shrink-0 text-accent" />
              <div className="min-w-0 text-[12px]">
                <div className="font-semibold text-text">{drill.label}</div>
                {drill.note && <div className="mt-0.5 text-[11.5px] text-muted">{drill.note}</div>}
              </div>
              <button
                type="button"
                onClick={() => setDrill(null)}
                className="ml-auto shrink-0 rounded-full border border-line px-2 py-0.5 text-[11px] text-muted transition hover:text-text"
              >
                clear
              </button>
            </div>
          )}

          {tab === "promptlog" ? (
            <PromptLogTab
              d={plog}
              a={pstats}
              view={plogView}
              onView={setPlogView}
              onClear={() =>
                clearPromptLog().then(() => loadPlog(plogRoute, plogOutcomes, plogWindow, plogView))
              }
            />
          ) : tab === "gateway" ? (
            <GatewayTab d={gw} hours={hours} gatewayId={gatewayId} />
          ) : (
            /* Withholding onDrill (rather than passing a no-op) also drops
               EdgeTab's "click to inspect prompts" affordance, so the rows
               stop advertising a destination that isn't there. */
            <EdgeTab data={data} hours={hours} onDrill={promptLogEnabled ? onDrill : undefined} />
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
