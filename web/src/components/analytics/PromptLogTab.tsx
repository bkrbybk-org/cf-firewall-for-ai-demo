// Prompt log tab: SQL-GROUP-BY rollups over the whole log, then the raw
// PII-redacted rows as a sortable table. Expanding a row shows the redacted
// reply plus the live edge verdict (joined by cf-ray via <Verdict>), so a
// prompt sits next to exactly what the edge detected on it.
//
// Route/outcome filtering happens server-side (see AnalyticsPage) because it
// changes which rows are fetched. Sorting and the text search are client-side:
// they only reorder or narrow the page already in hand, so round-tripping to
// D1 for them would add latency for no benefit.
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  MessagesSquare,
  Route,
  Search,
  ShieldCheck,
  ShieldX,
  Trash2,
  UserSearch,
} from "lucide-react";
import { BarList, bucketLabel, Card, Tile } from "./primitives";
import { EventSeries, PLOG_SERIES } from "./EventSeries";
import { Verdict } from "../Verdict";
import type { PromptAnalytics, PromptLog, PromptLogRow as PromptLogRowData } from "../../lib/types";

const OUTCOME_TONE: Record<string, string> = {
  reply: "border-cf-green/50 text-cf-green",
  guardrails: "border-cf-purple/50 text-cf-purple",
  error: "border-cf-red/50 text-cf-red",
};

type SortKey = "ts" | "outcome" | "route" | "model" | "tokens" | "redactions";
type SortDir = "asc" | "desc";

const PAGE_SIZES = [10, 25, 50, 100] as const;
const DEFAULT_PAGE_SIZE = 25;

const totalTokens = (r: PromptLogRowData) => (r.promptTokens ?? 0) + (r.completionTokens ?? 0);

function sortValue(r: PromptLogRowData, key: SortKey): string | number {
  switch (key) {
    case "ts":
      return r.ts;
    case "outcome":
      return r.outcome;
    case "route":
      return r.route;
    case "model":
      return r.model;
    case "tokens":
      return totalTokens(r);
    case "redactions":
      return r.redactions;
  }
}

// Numeric columns are most useful largest-first; text columns A→Z.
const DEFAULT_DIR: Record<SortKey, SortDir> = {
  ts: "desc",
  outcome: "asc",
  route: "asc",
  model: "asc",
  tokens: "desc",
  redactions: "desc",
};

function SortHeader({
  label,
  col,
  sortKey,
  sortDir,
  onSort,
  className = "",
}: {
  label: string;
  col: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (k: SortKey) => void;
  className?: string;
}) {
  const active = sortKey === col;
  const Icon = !active ? ArrowUpDown : sortDir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th scope="col" className={`px-2.5 py-1.5 font-semibold ${className}`}>
      <button
        type="button"
        onClick={() => onSort(col)}
        aria-sort={active ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
        // uppercase repeated here: preflight resets text-transform on <button>,
        // so without it these headers would not match the plain <th> ones.
        className={`inline-flex items-center gap-1 uppercase transition hover:text-text ${active ? "text-text" : ""}`}
      >
        {label}
        <Icon size={11} className={active ? "text-accent" : "text-subtle"} />
      </button>
    </th>
  );
}

function PromptLogRowView({ r }: { r: PromptLogRowData }) {
  const [open, setOpen] = useState(false);
  const tok = totalTokens(r);
  return (
    <>
      <tr
        onClick={() => setOpen((v) => !v)}
        className="cursor-pointer border-t border-line align-top transition hover:bg-surface-hover"
      >
        <td className="px-2.5 py-1.5">
          {open ? (
            <ChevronDown size={13} className="text-subtle" />
          ) : (
            <ChevronRight size={13} className="text-subtle" />
          )}
        </td>
        <td className="px-2.5 py-1.5 font-mono text-[11px] whitespace-nowrap text-subtle tabular-nums">
          {new Date(r.ts).toLocaleString("en-GB", { hour12: false })}
        </td>
        <td className="px-2.5 py-1.5">
          <span
            className={`rounded-full border px-1.5 py-px text-[10px] font-semibold ${OUTCOME_TONE[r.outcome] ?? "border-line text-muted"}`}
          >
            {r.outcome}
          </span>
        </td>
        <td className="px-2.5 py-1.5 whitespace-nowrap text-muted">
          {r.route === "gateway" ? "AI Gateway" : "Workers AI"}
        </td>
        <td className="px-2.5 py-1.5 font-mono text-[11px] whitespace-nowrap text-muted">
          {r.model.replace(/^@cf\//, "")}
        </td>
        {/* w-full + max-w-0 makes this the column that absorbs the leftover
            width, so the prompt gets the space instead of being squeezed. */}
        <td className="w-full max-w-0 px-2.5 py-1.5">
          <div className="truncate text-text">{r.prompt}</div>
        </td>
        <td className="px-2.5 py-1.5 text-right font-mono text-[11px] whitespace-nowrap text-muted tabular-nums">
          {tok || "—"}
        </td>
        <td className="px-2.5 py-1.5 text-right whitespace-nowrap">
          {r.redactions > 0 ? (
            <span className="rounded-full border border-cf-amber/50 px-1.5 py-px text-[10px] font-semibold text-cf-amber">
              {r.redactions}
            </span>
          ) : (
            <span className="text-subtle">—</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-line bg-bg/40">
          <td colSpan={8} className="px-3 py-2.5">
            <div className="flex flex-col gap-2.5 text-[12px]">
              <div>
                <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">
                  Prompt (redacted)
                </div>
                <div className="rounded-lg border border-line bg-bg px-2.5 py-1.5 whitespace-pre-wrap break-words text-text">
                  {r.prompt}
                </div>
              </div>
              {r.reply != null ? (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">
                    Reply (redacted)
                  </div>
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
                {r.gatewayId && (
                  <>
                    {" "}
                    · gateway <span className="font-mono">{r.gatewayId}</span>
                  </>
                )}
                {r.promptTokens != null && <> · {tok} tok</>}
              </div>
              {/* The cf-ray join to the live edge verdict — the whole point.
                  `ts` anchors the lookup to when the request happened, so old
                  rows resolve instead of falling outside a window around now. */}
              <Verdict ray={r.ray} ts={r.ts} prompt={r.prompt} />
            </div>
          </td>
        </tr>
      )}
    </>
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
        <Card title="Prompts over time" subtitle={`per ${bucketLabel(a.bucket)} · by outcome${span ? ` · ${span}` : ""}`}>
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

export function PromptLogTab({ d, a, onClear }: { d: PromptLog | null; a: PromptAnalytics | null; onClear: () => void }) {
  const [confirming, setConfirming] = useState(false);
  // Newest first by default — the log is read as "what just happened".
  const [sortKey, setSortKey] = useState<SortKey>("ts");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [query, setQuery] = useState("");
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
  const [page, setPage] = useState(0);

  // Depends on the props array itself, not a `?? []` copy, so the memo is not
  // invalidated on every render. All hooks stay above the early returns.
  const visible = useMemo(() => {
    const src = d?.rows ?? [];
    const q = query.trim().toLowerCase();
    const matched = q
      ? src.filter(
          (r) =>
            r.prompt.toLowerCase().includes(q) ||
            (r.reply ?? "").toLowerCase().includes(q) ||
            r.model.toLowerCase().includes(q) ||
            r.ray.toLowerCase().includes(q),
        )
      : src;
    const dir = sortDir === "asc" ? 1 : -1;
    return [...matched].sort((a2, b2) => {
      const av = sortValue(a2, sortKey);
      const bv = sortValue(b2, sortKey);
      // Ties fall back to newest first so equal outcomes/routes stay readable.
      if (av === bv) return b2.ts - a2.ts;
      return (av > bv ? 1 : -1) * dir;
    });
  }, [d?.rows, query, sortKey, sortDir]);

  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize));
  // Filtering/sorting/page-size changes can all strand `page` past the new
  // last page (e.g. narrowing a text filter while on page 5) — clamp back
  // rather than showing an empty page.
  useEffect(() => {
    if (page > pageCount - 1) setPage(0);
  }, [pageCount, page]);
  const paged = useMemo(
    () => visible.slice(page * pageSize, page * pageSize + pageSize),
    [visible, page, pageSize],
  );

  function onSort(k: SortKey) {
    if (k === sortKey) setSortDir((cur) => (cur === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(DEFAULT_DIR[k]);
    }
    setPage(0);
  }

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
        <Card title={(d.total ?? 0) > 0 ? "No prompts in this time frame" : "No prompts logged yet"}>
          <div className="flex items-start gap-3 text-sm text-muted">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-cf-green" />
            {(d.total ?? 0) > 0 ? (
              <p>
                {d.total} prompt{d.total === 1 ? "" : "s"} are stored, just not in the selected window — widen it above
                (try <b className="text-text">all</b>) to see them.
              </p>
            ) : (
              <p>
                Send a prompt from the{" "}
                <Link to="/" className="text-accent hover:underline">
                  Firewall page
                </Link>{" "}
                (either route) and it appears here. Local dev has no <code className="font-mono">cf-ray</code>, so the
                per-row verdict shows "pending".
              </p>
            )}
          </div>
        </Card>
      ) : (
        <div className="overflow-hidden rounded-xl border border-line bg-surface">
          <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
            <label className="relative flex min-w-48 flex-1 items-center">
              <Search size={13} className="pointer-events-none absolute left-2.5 text-subtle" />
              <input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
                placeholder="Filter prompt, reply, model or ray…"
                aria-label="Filter rows"
                className="w-full rounded-lg border border-line bg-surface-2 py-1.5 pr-2.5 pl-7 text-[12px] text-text outline-none transition focus:border-accent"
              />
            </label>
            <span className="text-[11.5px] text-subtle">
              {visible.length === rows.length
                ? `${rows.length} row${rows.length === 1 ? "" : "s"}`
                : `${visible.length} of ${rows.length} rows`}
            </span>
            <label className="flex items-center gap-1.5 text-[11.5px] text-subtle">
              rows
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(0);
                }}
                aria-label="Rows per page"
                className="rounded-lg border border-line bg-surface-2 px-1.5 py-1 text-[11.5px] text-text outline-none focus:border-accent"
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {/* Wide content scrolls inside its own box rather than the page. */}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[12px]">
              <thead className="text-[10px] uppercase tracking-wider text-subtle">
                <tr>
                  <th scope="col" className="w-6 px-2.5 py-1.5">
                    <span className="sr-only">Expand</span>
                  </th>
                  <SortHeader label="Time" col="ts" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Outcome" col="outcome" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Route" col="route" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Model" col="model" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <th scope="col" className="w-full px-2.5 py-1.5 font-semibold">
                    Prompt
                  </th>
                  <SortHeader
                    label="Tok"
                    col="tokens"
                    sortKey={sortKey}
                    sortDir={sortDir}
                    onSort={onSort}
                    className="text-right"
                  />
                  <SortHeader
                    label="PII"
                    col="redactions"
                    sortKey={sortKey}
                    sortDir={sortDir}
                    onSort={onSort}
                    className="text-right"
                  />
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr className="border-t border-line">
                    <td colSpan={8} className="px-3 py-4 text-center text-[12px] text-subtle">
                      No rows match “{query}”.
                    </td>
                  </tr>
                ) : (
                  paged.map((r) => <PromptLogRowView key={r.ray} r={r} />)
                )}
              </tbody>
            </table>
          </div>

          {visible.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 text-[11.5px] text-subtle">
              <span>
                {page * pageSize + 1}–{Math.min(visible.length, page * pageSize + pageSize)} of {visible.length}
              </span>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  aria-label="Previous page"
                  className="rounded-lg border border-line p-1 transition hover:border-line-strong hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ChevronLeft size={14} />
                </button>
                <span className="px-1 tabular-nums">
                  {page + 1} / {pageCount}
                </span>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  disabled={page >= pageCount - 1}
                  aria-label="Next page"
                  className="rounded-lg border border-line p-1 transition hover:border-line-strong hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
}
