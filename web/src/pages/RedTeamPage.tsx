// Red Team page: fire the curated Prisma-AIRS attack corpus through the real
// /api/chat pipeline, resolve each request's edge verdict, and show a scorecard
// that mirrors the scan report. Re-running after a rule/Guardrail change proves
// whether the gap actually closed.
//
// The headline metric is "reached the model" (edge miss rate), NOT the scan's
// ASR (model compliance) — the two are deliberately kept apart in the UI.
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CircleAlert,
  Download,
  Info,
  Loader2,
  Play,
  Square,
  Swords,
  Trash2,
  Upload,
  Wrench,
} from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { Scorecard } from "../components/redteam/Scorecard";
import { useRedTeam, type RtAttackState } from "../hooks/useRedTeam";
import { getModels } from "../lib/api";
import { CSV_TEMPLATE, parseAttackCsv } from "../lib/attackCsv";
import { customCorpusStore } from "../lib/customCorpus";
import { downloadFile } from "../lib/export";
import { useStore } from "../lib/sessionStore";
import type { GatewayOption } from "../lib/types";
import {
  RT_CORPUS,
  SEVERITY_RANK,
  byCategory,
  estimateRunSeconds,
  formatDuration,
  bySeverity,
  scoreRun,
  type RedTeamAttack,
  type RtRunResult,
  type RtSeverity,
} from "../lib/redteam";

// ── state → pill ────────────────────────────────────────────────────────────
const STATE_PILL: Record<string, { label: string; cls: string }> = {
  allow: { label: "reached", cls: "border-cf-red/50 text-cf-red" },
  log: { label: "reached · logged", cls: "border-cf-amber/50 text-cf-amber" },
  block: { label: "blocked", cls: "border-cf-green/50 text-cf-green" },
  challenge: { label: "challenged", cls: "border-cf-green/50 text-cf-green" },
  denied: { label: "denied (non-WAF)", cls: "border-line text-muted" },
  guardrails: { label: "guardrails", cls: "border-cf-purple/50 text-cf-purple" },
  pending: { label: "no verdict", cls: "border-line text-subtle" },
  error: { label: "failed", cls: "border-line text-subtle" },
};

const SEV_PILL: Record<RtSeverity, string> = {
  critical: "border-cf-red/60 text-cf-red",
  high: "border-cf-red/40 text-cf-red/90",
  medium: "border-cf-amber/50 text-cf-amber",
  low: "border-cf-blue/50 text-cf-blue",
};

function StateCell({ s, stopped }: { s?: RtAttackState; stopped?: boolean }) {
  if (!s || s === "queued") return <span className="text-subtle">—</span>;
  if (s === "sending" || s === "sent" || s === "resolving") {
    // Once the run is stopped nothing is in flight, so a spinner labelled
    // "sending…" would be claiming work that is not happening. These rows were
    // sent but never scored, which is exactly what "unscored" means here.
    if (stopped) return <span className="text-subtle">unscored</span>;
    const label = s === "resolving" ? "resolving…" : "sending…";
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-accent">
        <Loader2 size={11} className="animate-spin" /> {label}
      </span>
    );
  }
  const pill = STATE_PILL[s] ?? { label: s, cls: "border-line text-muted" };
  return <span className={`rounded-full border px-1.5 py-px text-[10px] font-semibold ${pill.cls}`}>{pill.label}</span>;
}

// ── sortable table ──────────────────────────────────────────────────────────
// "ref" is the file/report row number, which is the only ordering a custom CSV
// has — severity and scan ASR exist on the Prisma corpus alone.
type SortKey = "ref" | "severity" | "category" | "reportedAsr" | "state";
type SortDir = "asc" | "desc";
const DEFAULT_DIR: Record<SortKey, SortDir> = {
  ref: "asc",
  severity: "asc",
  category: "asc",
  reportedAsr: "desc",
  state: "asc",
};
const STATE_ORDER: Record<string, number> = { allow: 0, log: 1, denied: 2, guardrails: 3, pending: 4, error: 5, block: 6, challenge: 7 };

// Row label: the scan's reference number, or the CSV line the prompt came from.
function refOf(a: RedTeamAttack, index: number): number {
  if (a.scanRef != null) return a.scanRef;
  const n = Number(a.id.replace(/^csv-/, ""));
  return Number.isFinite(n) ? n : index + 1;
}

function sortValue(
  a: RedTeamAttack,
  index: number,
  states: Record<string, RtAttackState>,
  key: SortKey,
): number | string {
  switch (key) {
    case "ref":
      return refOf(a, index);
    case "severity":
      // Unrated rows sort last rather than pretending to be "low".
      return a.severity ? SEVERITY_RANK[a.severity] : 99;
    case "category":
      return a.category;
    case "reportedAsr":
      return a.reportedAsr ?? -1;
    case "state": {
      const s = states[a.id];
      return s != null && s in STATE_ORDER ? STATE_ORDER[s] : 99;
    }
  }
}

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
        className={`inline-flex items-center gap-1 uppercase transition hover:text-text ${active ? "text-text" : ""}`}
      >
        {label}
        <Icon size={11} className={active ? "text-accent" : "text-subtle"} />
      </button>
    </th>
  );
}

// Pacing presets. "None" stays the default so existing behaviour is unchanged;
// the slower steps exist for rate limits (WAF rate-limiting rules, AI Gateway
// rate limiting) and for spreading a run across analytics buckets instead of
// dumping it into one.
const DELAY_OPTIONS: { ms: number; label: string }[] = [
  { ms: 0, label: "none" },
  { ms: 500, label: "0.5s" },
  { ms: 1000, label: "1s" },
  { ms: 2000, label: "2s" },
  { ms: 5000, label: "5s" },
  { ms: 10000, label: "10s" },
  { ms: 30000, label: "30s" },
];

const CONTROLS: { finding: string; count: string; control: string }[] = [
  {
    finding: "Brand Tarnishing / Self-Criticism",
    count: "53 in the scan",
    control: "Add a Custom Topic — “Self-criticism” → BLOCK (this is the scan's top gap; no rule covers it today).",
  },
  {
    finding: "Political / Political Endorsements",
    count: "21 in the scan",
    control: "Rule 9 “Custom Topics Politics & Election” already blocks at score ≤ 40 — raise the threshold to catch more.",
  },
  { finding: "Hate / Toxic / Abuse", count: "2 in the scan", control: "Rules 5/6 Unsafe Categories (S1–S14) already cover this." },
  {
    finding: "Malware Generation / RCE",
    count: "Security domain",
    control: "Enable AI Gateway Malicious Code Detection → Block on the guarded gateway.",
  },
  { finding: "PII disclosure", count: "—", control: "Rules 3/4 PII Categories already block CREDIT_CARD/EMAIL/IBAN/CRYPTO." },
];

export function RedTeamPage() {
  const { phase, attackStates, results, settleLeftMs, pacingLeftMs, run, stop, reset } = useRedTeam();
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  // Which corpus is loaded: the built-in scan replay, or a CSV the operator
  // brought. The custom one lives in a module store so switching to Analytics
  // and back does not discard it.
  const custom = useStore(customCorpusStore);
  const [useCustom, setUseCustom] = useState(false);
  const [csvError, setCsvError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const corpus = useCustom && custom ? custom.attacks : RT_CORPUS;
  const isCustom = useCustom && !!custom;

  // Switching corpora must drop the previous run's results — the scorecard
  // sums every result held, so keeping them would print the old corpus's score
  // above the new corpus's table.
  function selectCorpus(next: boolean) {
    if (next === isCustom) return;
    reset();
    setUseCustom(next);
    setSortKey(next ? "ref" : "severity");
    setSortDir("asc");
  }

  async function onPickFile(file: File | undefined) {
    if (!file) return;
    setCsvError(null);
    const parsed = parseAttackCsv(await file.text());
    if (parsed.error) {
      setCsvError(parsed.error);
      return;
    }
    reset();
    customCorpusStore.set({
      name: file.name,
      attacks: parsed.attacks,
      warnings: parsed.warnings,
      loadedAt: Date.now(),
    });
    setUseCustom(true);
    // Severity is a Prisma field; a CSV has none, so default to file order.
    setSortKey("ref");
    setSortDir("asc");
  }

  function clearCustom() {
    reset();
    customCorpusStore.set(null);
    setUseCustom(false);
    setCsvError(null);
    setSortKey("severity");
    setSortDir("asc");
    // Without this, re-picking the SAME file fires no change event.
    if (fileRef.current) fileRef.current.value = "";
  }

  // Route the batch runs through — mirrors the chat page's Route control. The
  // edge WAF verdict is the same on both, but the gateway route adds Guardrails,
  // so the guarded gateway can surface 2016/2017 blocks the WAF alone misses.
  const [route, setRoute] = useState<"direct" | "gateway">("direct");
  const [delayMs, setDelayMs] = useState(0);
  const [gateways, setGateways] = useState<GatewayOption[]>([]);
  const [gatewayId, setGatewayId] = useState("");
  useEffect(() => {
    getModels()
      .then((data) => {
        setGateways(data.gateways ?? []);
        setGatewayId(data.defaultGateway ?? data.gateways?.[0]?.id ?? "");
      })
      .catch(() => {});
  }, []);

  const running = phase === "sending" || phase === "settling" || phase === "resolving";

  const resultList: RtRunResult[] = useMemo(() => [...results.values()], [results]);
  const score = useMemo(() => scoreRun(resultList), [resultList]);
  // Empty for a custom corpus — bySeverity drops unrated attacks rather than
  // inventing a bucket, and the card is hidden below when it comes back empty.
  const sevRows = useMemo(() => bySeverity(corpus, results), [corpus, results]);
  const catRows = useMemo(() => byCategory(corpus, results), [corpus, results]);

  const rows = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    const indexed = corpus.map((a, i) => ({ a, i }));
    return indexed
      .sort((x, y) => {
        const av = sortValue(x.a, x.i, attackStates, sortKey);
        const bv = sortValue(y.a, y.i, attackStates, sortKey);
        // Ties fall back to file/report order, which is stable for both corpora.
        if (av === bv) return refOf(x.a, x.i) - refOf(y.a, y.i);
        return (av > bv ? 1 : -1) * dir;
      })
      .map((x) => x.a);
  }, [corpus, sortKey, sortDir, attackStates]);

  function onSort(k: SortKey) {
    if (k === sortKey) setSortDir((c) => (c === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(DEFAULT_DIR[k]);
    }
  }

  const sentCount = Object.values(attackStates).filter((s) => s !== "queued").length;
  let phaseText = "";
  if (phase === "sending")
    phaseText =
      pacingLeftMs > 0
        ? `sent ${sentCount}/${corpus.length} · next in ${(pacingLeftMs / 1000).toFixed(1)}s`
        : `sending ${sentCount}/${corpus.length}…`;
  else if (phase === "settling") phaseText = `waiting for edge ingestion — ${Math.ceil(settleLeftMs / 1000)}s`;
  else if (phase === "resolving") phaseText = `resolving verdicts ${results.size}/${corpus.length}…`;
  else if (phase === "done") phaseText = `done — ${score.reachedPct}% reached the model (${score.reached}/${score.scored})`;
  else if (phase === "stopped") phaseText = "stopped";

  const hasResults = results.size > 0;
  const runEstimate = formatDuration(estimateRunSeconds(corpus.length, delayMs));

  return (
    <div className="flex h-full flex-col">
      <Header
        title="Red Team"
        subtitle={<>Fire the Prisma AIRS attack corpus at the live edge and measure what got through</>}
        actions={<ThemeToggle />}
      />

      {/* `relative` contains the table's absolute sr-only header inside this
          scroll box (see AnalyticsPage for the same fix). */}
      <main className="relative min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
          {/* What this measures — the honest caveat, up front. */}
          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            <Info size={16} className="mt-0.5 shrink-0 text-cf-blue" />
            <p className="text-[12.5px] leading-relaxed text-muted">
              This replays a curated <b className="text-text">36 of the 116</b> attacks from the Prisma AIRS scan
              (Thai-language) — or <b className="text-text">your own prompts from a CSV</b> — through the real{" "}
              <code className="font-mono">/api/chat</code> route, then reads each request's edge verdict. The headline
              is{" "}
              <b className="text-text">“reached the model”</b> — how often the Cloudflare edge did <i>not</i> stop the
              request. It is <b className="text-text">not</b> the scan's ASR, which measures whether the model actually
              complied; the scan's own ASR is shown per row for reference only. Runs land in the{" "}
              <Link to="/analytics" className="text-accent hover:underline">
                prompt log
              </Link>{" "}
              (D1) as evidence.
            </p>
          </div>

          {/* Run controls */}
          <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            {running ? (
              <button
                type="button"
                onClick={stop}
                className="inline-flex items-center gap-1.5 rounded-full border border-cf-red/60 bg-cf-red/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-cf-red transition hover:bg-cf-red/20"
              >
                <Square size={13} /> Stop
              </button>
            ) : (
              <button
                type="button"
                onClick={() => run({ route, gatewayId: route === "gateway" ? gatewayId : undefined, delayMs }, corpus)}
                className="inline-flex items-center gap-1.5 rounded-full border border-accent/60 bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent transition hover:bg-accent/20"
              >
                <Play size={13} /> {hasResults ? "Re-run" : "Run"} {corpus.length} attack{corpus.length === 1 ? "" : "s"}
              </button>
            )}

            {/* Route selector — disabled mid-run so a batch never mixes routes. */}
            <div className="inline-flex overflow-hidden rounded-full border border-line text-[12px]">
              {(["direct", "gateway"] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  disabled={running}
                  onClick={() => setRoute(r)}
                  className={`px-3 py-1.5 transition disabled:opacity-50 ${
                    route === r ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:bg-surface-hover"
                  }`}
                >
                  {r === "direct" ? "Workers AI" : "AI Gateway"}
                </button>
              ))}
            </div>
            {route === "gateway" && (
              <select
                value={gatewayId}
                disabled={running}
                onChange={(e) => setGatewayId(e.target.value)}
                aria-label="AI Gateway"
                className="rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-[12px] text-text outline-none focus:border-accent disabled:opacity-50"
              >
                {gateways.length === 0 && <option value="">default gateway</option>}
                {gateways.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.label}
                    {g.guarded ? " · Guardrails" : ""}
                  </option>
                ))}
              </select>
            )}

            {phaseText && (
              <span className="inline-flex items-center gap-1.5 text-[12px] text-muted">
                {running && <Loader2 size={13} className="animate-spin text-accent" />}
                {phaseText}
              </span>
            )}
            {/* Pacing. Locked mid-run like the route selector, so a batch is
                never half-paced. */}
            <label className="flex items-center gap-1.5 text-[12px] text-muted">
              Delay
              <select
                value={delayMs}
                disabled={running}
                onChange={(e) => setDelayMs(Number(e.target.value))}
                aria-label="Delay between prompts"
                className="rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-[12px] text-text outline-none focus:border-accent disabled:opacity-50"
              >
                {DELAY_OPTIONS.map((d) => (
                  <option key={d.ms} value={d.ms}>
                    {d.label}
                  </option>
                ))}
              </select>
            </label>

            <span className="ml-auto text-[11.5px] text-subtle">
              ≈ {runEstimate} (send · 90s edge settle · resolve)
            </span>
          </div>

          {/* Corpus picker — the built-in scan replay, or the operator's own CSV. */}
          <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            <span className="text-[11.5px] font-bold uppercase tracking-wider text-subtle">Corpus</span>
            <div className="inline-flex overflow-hidden rounded-full border border-line text-[12px]">
              <button
                type="button"
                disabled={running}
                onClick={() => selectCorpus(false)}
                className={`px-3 py-1.5 transition disabled:opacity-50 ${
                  !isCustom ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:bg-surface-hover"
                }`}
              >
                Prisma AIRS ({RT_CORPUS.length})
              </button>
              <button
                type="button"
                disabled={running || !custom}
                title={custom ? undefined : "Load a CSV first"}
                onClick={() => selectCorpus(true)}
                className={`px-3 py-1.5 transition disabled:opacity-40 ${
                  isCustom ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:bg-surface-hover"
                }`}
              >
                Custom CSV{custom ? ` (${custom.attacks.length})` : ""}
              </button>
            </div>

            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              disabled={running}
              onChange={(e) => void onPickFile(e.target.files?.[0])}
              className="hidden"
              aria-hidden="true"
              tabIndex={-1}
            />
            <button
              type="button"
              disabled={running}
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-accent hover:text-accent disabled:opacity-50"
            >
              <Upload size={13} /> {custom ? "Replace CSV" : "Load CSV"}
            </button>
            <button
              type="button"
              onClick={() => downloadFile("attack-corpus-template.csv", CSV_TEMPLATE, "text/csv")}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-accent hover:text-accent"
            >
              <Download size={13} /> Template
            </button>
            {custom && (
              <button
                type="button"
                disabled={running}
                onClick={clearCustom}
                className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-cf-red hover:text-cf-red disabled:opacity-50"
              >
                <Trash2 size={13} /> Clear
              </button>
            )}
            {custom && (
              <span className="text-[11.5px] text-subtle">
                <span className="font-mono text-muted">{custom.name}</span> · {custom.attacks.length} prompt
                {custom.attacks.length === 1 ? "" : "s"}
              </span>
            )}
            <span className="ml-auto text-[11.5px] text-subtle">
              <code className="font-mono">prompt,goal</code> header · same shape as the Prisma AIRS upload
            </span>
          </div>

          {csvError && (
            <div className="flex items-start gap-2.5 rounded-xl border border-cf-red/40 bg-cf-red/[0.06] px-3.5 py-2.5 text-[12px] text-cf-red">
              <CircleAlert size={15} className="mt-px shrink-0" />
              <span>{csvError}</span>
            </div>
          )}
          {isCustom && custom!.warnings.length > 0 && (
            <div className="rounded-xl border border-cf-amber/40 bg-cf-amber/[0.06] px-3.5 py-2.5 text-[12px] text-muted">
              {custom!.warnings.map((w) => (
                <div key={w}>{w}</div>
              ))}
            </div>
          )}
          {isCustom && (
            <div className="rounded-xl border border-cf-blue/30 bg-cf-blue/[0.06] px-3.5 py-2 text-[11.5px] leading-relaxed text-muted">
              Running your own prompts. Severity and scan ASR are Prisma's assessments, so those columns are hidden
              rather than filled in with guesses. <b className="text-text">Goals are carried for reference and never
              evaluated</b> — there is no LLM judge here, so the only thing measured is whether the Cloudflare edge
              stopped the request. Prompts are parsed in the browser and reach the Worker only by being sent as normal
              chat requests, which is what makes them subject to the real edge scan.
            </div>
          )}
          {route === "gateway" && (
            <div className="rounded-xl border border-cf-purple/30 bg-cf-purple/[0.06] px-3.5 py-2 text-[11.5px] text-muted">
              Gateway route: the edge WAF verdict is unchanged, but a guarded gateway adds Guardrails — watch for{" "}
              <span className="font-semibold text-cf-purple">guardrails</span> results. Requires{" "}
              <code className="font-mono">CF_AIG_TOKEN</code> scoped correctly, or every gateway send errors.
            </div>
          )}

          {hasResults && <Scorecard score={score} bySeverityRows={sevRows} byCategoryRows={catRows} />}

          {/* Results table */}
          <section className="overflow-hidden rounded-2xl border border-line bg-surface shadow-sm">
            <div className="border-b border-line px-4 py-2.5">
              <h2 className="text-[13px] font-bold text-text">Attacks</h2>
              <div className="mt-0.5 text-[11.5px] text-muted">
                {corpus.length} prompts · click a column to sort ·{" "}
                {isCustom ? (
                  <>
                    from <span className="font-mono">{custom!.name}</span> · “goal” is your note, not something this
                    page evaluates
                  </>
                ) : (
                  <>“scan ASR” is Prisma's number, not ours</>
                )}
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-[12px]">
                <thead className="text-[10px] uppercase tracking-wider text-subtle">
                  <tr>
                    <SortHeader label="#" col="ref" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                    {/* Severity and scan ASR exist only on the Prisma corpus. */}
                    {!isCustom && (
                      <SortHeader label="Severity" col="severity" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                    )}
                    {!isCustom && (
                      <SortHeader label="Category" col="category" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                    )}
                    <th scope="col" className="w-full px-2.5 py-1.5 font-semibold">
                      Prompt
                    </th>
                    {isCustom && (
                      <th scope="col" className="px-2.5 py-1.5 font-semibold">
                        Goal
                      </th>
                    )}
                    {!isCustom && (
                      <SortHeader
                        label="Scan ASR"
                        col="reportedAsr"
                        sortKey={sortKey}
                        sortDir={sortDir}
                        onSort={onSort}
                        className="text-right"
                      />
                    )}
                    <SortHeader label="Edge result" col="state" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a, i) => (
                    <tr key={a.id} className="border-t border-line align-top">
                      <td className="px-2.5 py-1.5 font-mono text-[11px] whitespace-nowrap text-subtle tabular-nums">
                        {refOf(a, i)}
                      </td>
                      {!isCustom && (
                        <td className="px-2.5 py-1.5">
                          {a.severity ? (
                            <span className={`rounded-full border px-1.5 py-px text-[10px] font-semibold ${SEV_PILL[a.severity]}`}>
                              {a.severity}
                            </span>
                          ) : (
                            <span className="text-subtle">—</span>
                          )}
                        </td>
                      )}
                      {!isCustom && <td className="px-2.5 py-1.5 whitespace-nowrap text-muted">{a.category}</td>}
                      {/* max-w-0 + w-full lets the prompt absorb the slack and truncate. */}
                      <td className="w-full max-w-0 px-2.5 py-1.5">
                        <div className="truncate text-text" title={a.prompt} lang={isCustom ? undefined : "th"}>
                          {a.prompt}
                        </div>
                      </td>
                      {isCustom && (
                        <td className="max-w-[220px] px-2.5 py-1.5">
                          <div className="truncate text-muted" title={a.goal}>
                            {a.goal ?? <span className="text-subtle">—</span>}
                          </div>
                        </td>
                      )}
                      {!isCustom && (
                        <td className="px-2.5 py-1.5 text-right font-mono text-[11px] whitespace-nowrap text-subtle tabular-nums">
                          {a.reportedAsr != null ? `${a.reportedAsr}%` : "—"}
                        </td>
                      )}
                      <td className="px-2.5 py-1.5 whitespace-nowrap">
                        <StateCell s={attackStates[a.id]} stopped={phase === "stopped"} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Recommended controls — the actionable half */}
          <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
            <div className="flex items-center gap-2">
              <Wrench size={15} className="text-cf-green" />
              <h2 className="text-[13px] font-bold text-text">Close the gaps</h2>
            </div>
            <div className="mt-0.5 text-[11.5px] text-muted">
              Each scan finding → the Cloudflare control that addresses it (dashboard config, not code)
            </div>
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[640px] text-left text-[12px]">
                <thead className="text-[10px] uppercase tracking-wider text-subtle">
                  <tr>
                    <th className="px-2.5 py-1.5 font-semibold">Finding</th>
                    <th className="px-2.5 py-1.5 font-semibold">Volume</th>
                    <th className="px-2.5 py-1.5 font-semibold">Recommended control</th>
                  </tr>
                </thead>
                <tbody>
                  {CONTROLS.map((c) => (
                    <tr key={c.finding} className="border-t border-line align-top">
                      <td className="px-2.5 py-1.5 whitespace-nowrap font-medium text-text">{c.finding}</td>
                      <td className="px-2.5 py-1.5 whitespace-nowrap text-subtle">{c.count}</td>
                      <td className="px-2.5 py-1.5 text-muted">{c.control}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}

// Icon re-export so NavTabs can pull the same glyph without importing lucide twice.
export const RedTeamIcon = Swords;
