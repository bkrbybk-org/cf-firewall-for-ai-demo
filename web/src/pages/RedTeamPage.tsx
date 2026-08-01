// Red Team page: fire the curated Prisma-AIRS attack corpus through the real
// /api/chat pipeline, resolve each request's edge verdict, and show a scorecard
// that mirrors the scan report. Re-running after a rule/Guardrail change proves
// whether the gap actually closed.
//
// The headline metric is "reached the model" (edge miss rate), NOT the scan's
// ASR (model compliance) — the two are deliberately kept apart in the UI.
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Info,
  Loader2,
  Play,
  Square,
  Swords,
  Wrench,
} from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { Scorecard } from "../components/redteam/Scorecard";
import { useRedTeam, type RtAttackState } from "../hooks/useRedTeam";
import { getModels } from "../lib/api";
import type { GatewayOption } from "../lib/types";
import {
  RT_CORPUS,
  SEVERITY_RANK,
  byCategory,
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

function StateCell({ s }: { s?: RtAttackState }) {
  if (!s || s === "queued") return <span className="text-subtle">—</span>;
  if (s === "sending" || s === "sent" || s === "resolving") {
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
type SortKey = "severity" | "category" | "reportedAsr" | "state";
type SortDir = "asc" | "desc";
const DEFAULT_DIR: Record<SortKey, SortDir> = { severity: "asc", category: "asc", reportedAsr: "desc", state: "asc" };
const STATE_ORDER: Record<string, number> = { allow: 0, log: 1, denied: 2, guardrails: 3, pending: 4, error: 5, block: 6, challenge: 7 };

function sortValue(a: RedTeamAttack, states: Record<string, RtAttackState>, key: SortKey): number | string {
  switch (key) {
    case "severity":
      return SEVERITY_RANK[a.severity];
    case "category":
      return a.category;
    case "reportedAsr":
      return a.reportedAsr;
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
  const { phase, attackStates, results, settleLeftMs, run, stop } = useRedTeam();
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  // Route the batch runs through — mirrors the chat page's Route control. The
  // edge WAF verdict is the same on both, but the gateway route adds Guardrails,
  // so the guarded gateway can surface 2016/2017 blocks the WAF alone misses.
  const [route, setRoute] = useState<"direct" | "gateway">("direct");
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
  const sevRows = useMemo(() => bySeverity(RT_CORPUS, results), [results]);
  const catRows = useMemo(() => byCategory(RT_CORPUS, results), [results]);

  const rows = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...RT_CORPUS].sort((a, b) => {
      const av = sortValue(a, attackStates, sortKey);
      const bv = sortValue(b, attackStates, sortKey);
      if (av === bv) return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      return (av > bv ? 1 : -1) * dir;
    });
  }, [sortKey, sortDir, attackStates]);

  function onSort(k: SortKey) {
    if (k === sortKey) setSortDir((c) => (c === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(DEFAULT_DIR[k]);
    }
  }

  const sentCount = Object.values(attackStates).filter((s) => s !== "queued").length;
  let phaseText = "";
  if (phase === "sending") phaseText = `sending ${sentCount}/${RT_CORPUS.length}…`;
  else if (phase === "settling") phaseText = `waiting for edge ingestion — ${Math.ceil(settleLeftMs / 1000)}s`;
  else if (phase === "resolving") phaseText = `resolving verdicts ${results.size}/${RT_CORPUS.length}…`;
  else if (phase === "done") phaseText = `done — ${score.reachedPct}% reached the model (${score.reached}/${score.scored})`;
  else if (phase === "stopped") phaseText = "stopped";

  const hasResults = results.size > 0;

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
              (Thai-language) through the real <code className="font-mono">/api/chat</code> route, then reads each
              request's edge verdict. The headline is{" "}
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
                onClick={() => run({ route, gatewayId: route === "gateway" ? gatewayId : undefined })}
                className="inline-flex items-center gap-1.5 rounded-full border border-accent/60 bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent transition hover:bg-accent/20"
              >
                <Play size={13} /> {hasResults ? "Re-run" : "Run"} {RT_CORPUS.length} attacks
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
            <span className="ml-auto text-[11.5px] text-subtle">
              full run ≈ 4 min (send · 90s edge settle · resolve)
            </span>
          </div>
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
                {RT_CORPUS.length} prompts · click a column to sort · “scan ASR” is Prisma's number, not ours
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-[12px]">
                <thead className="text-[10px] uppercase tracking-wider text-subtle">
                  <tr>
                    <th scope="col" className="px-2.5 py-1.5 font-semibold">
                      <span className="sr-only">Ref</span>#
                    </th>
                    <SortHeader label="Severity" col="severity" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                    <SortHeader label="Category" col="category" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                    <th scope="col" className="w-full px-2.5 py-1.5 font-semibold">
                      Prompt
                    </th>
                    <SortHeader
                      label="Scan ASR"
                      col="reportedAsr"
                      sortKey={sortKey}
                      sortDir={sortDir}
                      onSort={onSort}
                      className="text-right"
                    />
                    <SortHeader label="Edge result" col="state" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a) => (
                    <tr key={a.id} className="border-t border-line align-top">
                      <td className="px-2.5 py-1.5 font-mono text-[11px] whitespace-nowrap text-subtle tabular-nums">
                        {a.scanRef}
                      </td>
                      <td className="px-2.5 py-1.5">
                        <span className={`rounded-full border px-1.5 py-px text-[10px] font-semibold ${SEV_PILL[a.severity]}`}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="px-2.5 py-1.5 whitespace-nowrap text-muted">{a.category}</td>
                      {/* max-w-0 + w-full lets the prompt absorb the slack and truncate. */}
                      <td className="w-full max-w-0 px-2.5 py-1.5">
                        <div className="truncate text-text" title={a.prompt} lang="th">
                          {a.prompt}
                        </div>
                      </td>
                      <td className="px-2.5 py-1.5 text-right font-mono text-[11px] whitespace-nowrap text-subtle tabular-nums">
                        {a.reportedAsr}%
                      </td>
                      <td className="px-2.5 py-1.5 whitespace-nowrap">
                        <StateCell s={attackStates[a.id]} />
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
