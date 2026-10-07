// Saved runs: keep a finished Red Team run in D1, list the saved ones, and compare
// two of them with diffRuns() — the "did the gap actually close?" view the saved-run
// API was built for (Open bug #21).
//
// The comparison is the honesty-critical part. diffRuns already scores only the
// attacks present in BOTH runs and flags different corpora; this component must not
// undo that by leading with either run's own stored totals, so the headline is the
// shared-attack score, the warning comes first when there is one, and differences a
// run does not record (route, guardrail settings) are said out loud.
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowRight, BarChart3, Download, GitCompare, Loader2, Save, Trash2 } from "lucide-react";
import { buildBenchmarkReport, reportFilename, reportToMarkdown } from "../../lib/benchmarkReport";
import { downloadFile } from "../../lib/export";
import { deleteRedTeamRun, getRedTeamRun, listRedTeamRuns, saveRedTeamRun, type RedTeamRunSaveRequest } from "../../lib/api";
import { diffRuns, isAttack, type RtRunDiff, type RtSavedRun } from "../../lib/redteam";
import { PROVIDER_LABELS } from "../../lib/guardrailView";
import {
  countBlockedByAny,
  falseBlockScores,
  providersIn,
  vendorScorecard,
  type FalseBlockScore,
} from "../../lib/vendorScorecard";
import { VendorScorecard } from "./VendorScorecard";
import { controlDeltas, savedRunBenchmarkInput, summarizeDiff, toSavedRun } from "../../lib/savedRuns";
import type { RedTeamRunRow } from "../../lib/types";
import { StatePill } from "./StatePill";

const BTN =
  "inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-50";

function when(ts: number): string {
  return new Date(ts).toLocaleString();
}

function routeLabel(r: {
  route: "direct" | "gateway";
  gatewayId?: string | null;
  guarded: number;
  dynamicRoute?: string | null;
}): string {
  if (r.route === "direct") return "Workers AI";
  return `AI Gateway${r.gatewayId ? ` · ${r.gatewayId}` : ""}${r.guarded ? " · Guardrails" : ""}${
    r.dynamicRoute ? ` · route ${r.dynamicRoute}` : ""
  }`;
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function SavedRuns({
  runKey,
  canSave,
  buildSave,
}: {
  // Changes with every new run, so "already saved" is tracked per run, not per page.
  runKey: number;
  canSave: boolean;
  buildSave: (label: string) => RedTeamRunSaveRequest | null;
}) {
  const [runs, setRuns] = useState<RedTeamRunRow[] | null>(null);
  const [configured, setConfigured] = useState(true);
  const [listErr, setListErr] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<{ runKey: number; id: number; pruned: number } | null>(null);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [picked, setPicked] = useState<number[]>([]);

  const load = useCallback(async () => {
    setListErr(null);
    try {
      const r = await listRedTeamRuns();
      setConfigured(r.configured);
      if (r.error) setListErr(r.error);
      setRuns(r.runs ?? []);
    } catch (e) {
      setListErr(errText(e));
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const savedThisRun = saved?.runKey === runKey;

  async function save() {
    const body = buildSave(label);
    if (!body) return;
    setSaving(true);
    setSaveErr(null);
    try {
      const r = await saveRedTeamRun(body);
      if (!r.configured) setSaveErr("Saving needs the D1 database (migration 0003) — this Worker has none.");
      else if (r.error || r.id == null) setSaveErr(r.error ?? "The server did not return an id.");
      else {
        setSaved({ runKey, id: r.id, pruned: r.pruned ?? 0 });
        setLabel("");
        await load();
      }
    } catch (e) {
      setSaveErr(errText(e));
    } finally {
      setSaving(false);
    }
  }

  async function remove(id: number) {
    if (!window.confirm(`Delete saved run #${id}? This cannot be undone.`)) return;
    try {
      const r = await deleteRedTeamRun(id);
      if (r.error) setListErr(r.error);
    } catch (e) {
      setListErr(errText(e));
    }
    setPicked((p) => p.filter((x) => x !== id));
    await load();
  }

  function togglePick(id: number) {
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id].slice(-2)));
  }

  return (
    <section className="rounded-2xl border border-line bg-surface shadow-sm">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2.5">
        <div>
          <h2 className="text-[13px] font-bold text-text">Saved runs</h2>
          <div className="mt-0.5 text-[11.5px] text-muted">
            Save a run, change a rule or guardrail, re-run, then compare the two. Stored in D1; the newest 50 are kept.
          </div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            disabled={!canSave || savedThisRun}
            placeholder="label (optional), e.g. before self-criticism topic"
            aria-label="Label for the saved run"
            maxLength={200}
            className="w-72 max-w-full rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-[12px] text-text outline-none focus:border-accent disabled:opacity-50"
          />
          <button
            type="button"
            onClick={() => void save()}
            disabled={!canSave || saving || savedThisRun}
            title={canSave ? undefined : "Finish (or stop) a run first"}
            className={BTN}
          >
            {saving ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
            {savedThisRun ? `Saved as #${saved!.id}` : "Save this run"}
          </button>
        </div>
      </div>

      <div aria-live="polite" className="empty:hidden">
        {saveErr && <div className="px-4 pt-2 text-[12px] text-cf-red">Could not save — {saveErr}</div>}
        {savedThisRun && saved!.pruned > 0 && (
          <div className="px-4 pt-2 text-[11.5px] text-muted">
            {saved!.pruned} older run{saved!.pruned === 1 ? " was" : "s were"} removed to stay within the 50-run limit.
          </div>
        )}
      </div>

      <div className="px-4 py-3">
        {!configured ? (
          <p className="text-[12px] text-muted">Saved runs need the D1 database (migration 0003); this Worker has none.</p>
        ) : listErr ? (
          <div className="flex items-center gap-2 text-[12px] text-cf-red">
            Could not load saved runs — {listErr}
            <button type="button" onClick={() => void load()} className={BTN}>
              Retry
            </button>
          </div>
        ) : runs == null ? (
          <div className="flex items-center gap-1.5 text-[12px] text-muted">
            <Loader2 size={13} className="animate-spin" /> Loading…
          </div>
        ) : runs.length === 0 ? (
          <p className="text-[12px] text-subtle">No saved runs yet.</p>
        ) : (
          <>
            <div className="mb-1.5 text-[11.5px] text-muted">
              Tick one run to see its guardrail benchmark, or two to compare them
              {picked.length === 1 ? " — tick one more to compare" : ""}.
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] text-left text-[12px]">
                <thead className="text-[10px] uppercase tracking-wider text-subtle">
                  <tr>
                    <th scope="col" className="w-8 px-2 py-1.5">
                      <span className="sr-only">Compare</span>
                    </th>
                    <th scope="col" className="px-2 py-1.5 font-semibold">#</th>
                    <th scope="col" className="px-2 py-1.5 font-semibold">Run at</th>
                    <th scope="col" className="px-2 py-1.5 font-semibold">Label</th>
                    <th scope="col" className="px-2 py-1.5 font-semibold">Corpus</th>
                    <th scope="col" className="px-2 py-1.5 font-semibold">Route</th>
                    <th scope="col" className="px-2 py-1.5 text-right font-semibold" title="reached / scored — scored = reached + stopped at the edge">
                      Reached
                    </th>
                    <th scope="col" className="px-2 py-1.5 text-right font-semibold" title="Blocked by an external guardrail — outside the edge score">
                      External
                    </th>
                    <th scope="col" className="px-2 py-1.5 text-right font-semibold" title="Blocked by AI Gateway Guardrails — outside the edge score">
                      Guardrails
                    </th>
                    <th scope="col" className="px-2 py-1.5 text-right font-semibold" title="No verdict, failed, or refused by a non-WAF layer — excluded from the score">
                      Excluded
                    </th>
                    <th scope="col" className="w-8 px-2 py-1.5">
                      <span className="sr-only">Delete</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r) => (
                    <tr key={r.id} className={`border-t border-line align-top ${picked.includes(r.id) ? "bg-accent/5" : ""}`}>
                      <td className="px-2 py-1.5">
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 cursor-pointer accent-cf-red align-middle"
                          checked={picked.includes(r.id)}
                          onChange={() => togglePick(r.id)}
                          aria-label={`Compare run ${r.id}`}
                        />
                      </td>
                      <td className="px-2 py-1.5 font-mono text-[11px] text-subtle tabular-nums">{r.id}</td>
                      <td className="px-2 py-1.5 whitespace-nowrap text-muted">{when(r.ts)}</td>
                      <td className="max-w-[220px] px-2 py-1.5">
                        <div className="truncate text-text" title={r.label ?? undefined}>
                          {r.label ?? <span className="text-subtle">—</span>}
                        </div>
                      </td>
                      <td className="max-w-[220px] px-2 py-1.5">
                        <div className="truncate text-muted" title={r.corpusName}>
                          {r.corpusName}
                        </div>
                      </td>
                      <td className="px-2 py-1.5 whitespace-nowrap text-muted">{routeLabel(r)}</td>
                      <td className="px-2 py-1.5 text-right font-mono text-[11px] whitespace-nowrap tabular-nums text-text">
                        {r.reached}/{r.scored}
                        <span className="text-subtle"> · {r.scored === 0 ? "—" : `${r.reachedPct}%`}</span>
                        {r.skipped > 0 && (
                          <div className="text-[10px] text-cf-amber" title="Guardrail-only: reached, but the model was not called">
                            {r.skipped} model skipped
                          </div>
                        )}
                      </td>
                      <td className="px-2 py-1.5 text-right font-mono text-[11px] tabular-nums text-muted">{r.external}</td>
                      <td className="px-2 py-1.5 text-right font-mono text-[11px] tabular-nums text-muted">{r.guardrails}</td>
                      <td className="px-2 py-1.5 text-right font-mono text-[11px] tabular-nums text-muted">
                        {r.denied + r.pending + r.error}
                      </td>
                      <td className="px-2 py-1.5">
                        <button
                          type="button"
                          onClick={() => void remove(r.id)}
                          aria-label={`Delete run ${r.id}`}
                          title="Delete this saved run"
                          className="rounded-md p-1 text-subtle transition hover:text-cf-red"
                        >
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {picked.length === 1 && <SavedBenchmark id={picked[0]} />}
        {picked.length === 2 && <Comparison ids={picked} />}
      </div>
    </section>
  );
}

function downloadReport(run: RtSavedRun, ext: "md" | "json") {
  const report = buildBenchmarkReport(run, PROVIDER_LABELS);
  if (ext === "md") downloadFile(reportFilename(report, "md"), reportToMarkdown(report), "text/markdown");
  else downloadFile(reportFilename(report, "json"), JSON.stringify(report, null, 2), "application/json");
}

// One saved run's "Controls compared" card, redrawn from its stored rows by the same
// components and scoring the live run used (savedRunBenchmarkInput).
function SavedBenchmark({ id }: { id: number }) {
  const [run, setRun] = useState<RtSavedRun | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setRun(null);
    setErr(null);
    getRedTeamRun(id)
      .then((d) => {
        if (!live) return;
        if (!d.run) setErr(d.error ?? "This run no longer exists (deleted, or pruned by the 50-run limit).");
        else setRun(toSavedRun(d.run, d.results ?? []));
      })
      .catch((e) => live && setErr(errText(e)));
    return () => {
      live = false;
    };
  }, [id]);

  const view = useMemo(() => {
    if (!run) return null;
    const { corpus, results } = savedRunBenchmarkInput(run);
    const all = [...results.values()];
    const providers = providersIn(all);
    const attackCorpus = corpus.filter(isAttack);
    const benignCorpus = corpus.filter((a) => !isAttack(a));
    const attackList = attackCorpus.map((a) => results.get(a.id)!);
    const benignList = benignCorpus.map((a) => results.get(a.id)!);
    return {
      card: vendorScorecard(attackList, PROVIDER_LABELS, providers),
      falseBlocks: benignList.length > 0 ? falseBlockScores(benignList, PROVIDER_LABELS, providers) : null,
      benignBlocked: countBlockedByAny(benignList, providers),
      attackCorpus,
      benignCorpus,
      results,
      recorded: run.results.some((r) => r.vendors || r.lang),
    };
  }, [run]);

  return (
    <div className="mt-4 rounded-xl border border-line bg-surface-2/50 p-3.5">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] font-bold text-text">
        <BarChart3 size={14} className="text-accent" /> Benchmark {run && <RunTag run={run} />}
        {run && (
          // Open item H: the same numbers as a file (lib/benchmarkReport.ts). Saved runs
          // only — their prompts are the Worker's redacted previews.
          <span className="ml-auto flex items-center gap-1.5 font-normal">
            <button
              type="button"
              onClick={() => downloadReport(run, "md")}
              title="Download this benchmark as a Markdown report (redacted prompt previews, no vendor responses)"
              className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-[11.5px] text-muted hover:text-text"
            >
              <Download size={12} /> Report (.md)
            </button>
            <button
              type="button"
              onClick={() => downloadReport(run, "json")}
              title="Download the same numbers as JSON, to re-check or chart elsewhere"
              className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-[11.5px] text-muted hover:text-text"
            >
              <Download size={12} /> Data (.json)
            </button>
          </span>
        )}
      </div>
      {err && <div className="text-[12px] text-cf-red">{err}</div>}
      {!err && !view && (
        <div className="flex items-center gap-1.5 text-[12px] text-muted">
          <Loader2 size={13} className="animate-spin" /> Loading the run…
        </div>
      )}
      {view && !view.recorded && (
        <p className="text-[12px] text-muted">
          This run was saved before guardrail verdicts were stored with runs, so it has the edge results only — they are
          in the table above. Re-run and save to benchmark the guardrails.
        </p>
      )}
      {view && view.recorded && view.card.controls.length <= 1 && !view.falseBlocks && (
        <p className="text-[12px] text-muted">No external guardrail scanned any prompt in this run.</p>
      )}
      {view && view.recorded && (
        <VendorScorecard
          card={view.card}
          corpus={view.attackCorpus}
          benignCorpus={view.benignCorpus}
          falseBlocks={view.falseBlocks}
          benignBlocked={view.benignBlocked}
          results={view.results}
          labels={PROVIDER_LABELS}
        />
      )}
    </div>
  );
}

// Loads both runs and orders them by when they ran — the earlier is "before".
function Comparison({ ids }: { ids: number[] }) {
  const [pair, setPair] = useState<[RtSavedRun, RtSavedRun] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const key = ids.join(",");

  useEffect(() => {
    let live = true;
    setPair(null);
    setErr(null);
    Promise.all(ids.map((id) => getRedTeamRun(id)))
      .then((details) => {
        if (!live) return;
        const missing = details.find((d) => !d.run);
        if (missing) {
          setErr(missing.error ?? "One of the runs no longer exists (deleted, or pruned by the 50-run limit).");
          return;
        }
        const runs = details.map((d) => toSavedRun(d.run!, d.results ?? []));
        runs.sort((a, b) => a.ts - b.ts || a.id - b.id);
        setPair([runs[0], runs[1]]);
      })
      .catch((e) => live && setErr(errText(e)));
    return () => {
      live = false;
    };
    // Keyed on the ids' string form: `ids` is a new array every render.
  }, [key]);

  const diff = useMemo(() => (pair ? diffRuns(pair[0], pair[1]) : null), [pair]);

  return (
    <div className="mt-4 rounded-xl border border-line bg-surface-2/50 p-3.5">
      <div className="flex items-center gap-2 text-[12.5px] font-bold text-text">
        <GitCompare size={14} className="text-accent" /> Compare
      </div>
      {err && <div className="mt-2 text-[12px] text-cf-red">{err}</div>}
      {!err && !diff && (
        <div className="mt-2 flex items-center gap-1.5 text-[12px] text-muted">
          <Loader2 size={13} className="animate-spin" /> Loading both runs…
        </div>
      )}
      {pair && diff && <DiffView before={pair[0]} after={pair[1]} diff={diff} />}
      {pair && <ControlDeltaTable before={pair[0]} after={pair[1]} />}
    </div>
  );
}

function pctOf(s: { catchPct: number | null } | null): string {
  return s && s.catchPct !== null ? `${s.catchPct}%` : "—";
}
function fbPct(s: FalseBlockScore | null): string {
  return s && s.falseBlockPct !== null ? `${s.falseBlockPct}%` : "—";
}
// "+12 pts" / "−5 pts" / "" — only when both sides have a number. Points, not a
// percentage change: 40% → 50% is +10 points, and "+25%" would overstate it.
function delta(b: number | null | undefined, a: number | null | undefined, lowerIsBetter = false) {
  if (b == null || a == null || a === b) return null;
  const d = a - b;
  const good = lowerIsBetter ? d < 0 : d > 0;
  return (
    <span className={`ml-1 text-[10px] font-semibold ${good ? "text-cf-green" : "text-cf-red"}`}>
      {d > 0 ? "+" : "−"}
      {Math.abs(d)} pts
    </span>
  );
}

// Per control, before → after, over the prompts both runs contain (controlDeltas).
function ControlDeltaTable({ before, after }: { before: RtSavedRun; after: RtSavedRun }) {
  const d = useMemo(() => controlDeltas(before, after, PROVIDER_LABELS), [before, after]);
  const anyGuardrail = d.rows.some((r) => r.control !== "edge" && (r.before || r.after || r.fbBefore || r.fbAfter));
  if (!anyGuardrail && d.sharedHarmless === 0) return null;
  const showFb = d.sharedHarmless > 0;
  const thBase = "px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-subtle";
  const th = `${thBase} text-right`;
  const cell = "px-2 py-1.5 text-right font-mono text-[11px] whitespace-nowrap tabular-nums";
  return (
    <div className="mt-4">
      <div className="text-[12px] font-bold text-text">Each control, before → after</div>
      <div className="mt-0.5 text-[11px] text-muted">
        Over the {d.sharedAttacks} attack{d.sharedAttacks === 1 ? "" : "s"}
        {showFb ? ` and ${d.sharedHarmless} harmless prompt${d.sharedHarmless === 1 ? "" : "s"}` : ""} both runs contain;
        each side scored only on what that control scanned. "—" = not recorded in that run, never 0%.
      </div>
      <div className="relative mt-2 overflow-x-auto">
        <table className="w-full min-w-[520px] border-collapse">
          <thead>
            <tr>
              <th className={`${thBase} text-left`}>Control</th>
              <th className={th}>Catch before</th>
              <th className={th}>Catch after</th>
              {showFb && <th className={th}>False blocks before</th>}
              {showFb && <th className={th}>False blocks after</th>}
            </tr>
          </thead>
          <tbody>
            {d.rows.map((r) => (
              <tr key={r.control} className="border-t border-line">
                <td
                  className={`border-l-2 py-1.5 pr-2 pl-2.5 text-[12px] font-semibold whitespace-nowrap text-text ${
                    r.control === "edge" ? "border-l-cf-red" : "border-l-cf-amber"
                  }`}
                >
                  {r.label}
                </td>
                <td className={`${cell} text-muted`} title={r.before ? `${r.before.caught}/${r.before.scanned}` : "not recorded"}>
                  {pctOf(r.before)}
                </td>
                <td className={`${cell} text-text`} title={r.after ? `${r.after.caught}/${r.after.scanned}` : "not recorded"}>
                  {pctOf(r.after)}
                  {delta(r.before?.catchPct, r.after?.catchPct)}
                </td>
                {showFb && <td className={`${cell} text-muted`}>{fbPct(r.fbBefore)}</td>}
                {showFb && (
                  <td className={`${cell} text-text`}>
                    {fbPct(r.fbAfter)}
                    {delta(r.fbBefore?.falseBlockPct, r.fbAfter?.falseBlockPct, true)}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function pct(n: number, d: number): string {
  return d === 0 ? "—" : `${Math.round((n / d) * 100)}%`;
}

function DiffView({ before, after, diff }: { before: RtSavedRun; after: RtSavedRun; diff: RtRunDiff }) {
  const changed = diff.rows.filter((r) => r.status === "changed");
  const unchanged = diff.rows.filter((r) => r.status === "unchanged").length;
  const added = diff.rows.filter((r) => r.status === "added").length;
  const removed = diff.rows.filter((r) => r.status === "removed").length;
  const shared = changed.length + unchanged;
  const sameRoute =
    before.route === after.route &&
    (before.gatewayId ?? null) === (after.gatewayId ?? null) &&
    before.guarded === after.guarded;
  const s = summarizeDiff(diff);

  return (
    <div className="mt-2 flex flex-col gap-2.5 text-[12px]">
      <div className="flex flex-wrap items-center gap-2 text-muted">
        <RunTag run={before} /> <ArrowRight size={13} className="text-subtle" /> <RunTag run={after} />
      </div>

      {/* The warning first: it says the numbers below cover less than both runs. */}
      {diff.warning && (
        <div className="rounded-lg border border-cf-amber/50 bg-cf-amber/10 px-3 py-2 text-cf-amber">{diff.warning}</div>
      )}
      {!sameRoute && (
        <div className="rounded-lg border border-cf-amber/50 bg-cf-amber/10 px-3 py-2 text-cf-amber">
          Different routes ({routeLabel(before)} → {routeLabel(after)}).
          The edge verdict is the same on both, but Guardrails only exist on a gateway, so a change may come from the
          route rather than a rule.
        </div>
      )}

      {shared === 0 ? (
        <div className="text-muted">The two runs share no attacks, so there is nothing to compare.</div>
      ) : (
        <>
          <div className="text-text">
            On the <b>{shared}</b> attack{shared === 1 ? "" : "s"} in both runs, reached the model:{" "}
            <b className="font-mono">
              {diff.before.reached}/{diff.before.scored} ({pct(diff.before.reached, diff.before.scored)})
            </b>{" "}
            →{" "}
            <b className="font-mono">
              {diff.after.reached}/{diff.after.scored} ({pct(diff.after.reached, diff.after.scored)})
            </b>
            .
          </div>
          {/* Attack by attack, never reachedDelta alone — see summarizeDiff. */}
          <ul className="flex flex-col gap-0.5 text-text">
            {s.closedTotal > 0 && (
              <li>
                <b className="text-cf-green">{s.closedTotal} closed</b> — reached the model before, stopped now:{" "}
                {(
                  [
                    ["edge", "at the edge"],
                    ["external", "by an external guardrail"],
                    ["guardrails", "by AI Gateway Guardrails"],
                  ] as const
                )
                  .filter(([k]) => s.closed[k] > 0)
                  .map(([k, words]) => `${s.closed[k]} ${words}`)
                  .join(", ")}
                .
              </li>
            )}
            {s.opened > 0 && (
              <li>
                <b className="text-cf-red">{s.opened} opened</b> — reach the model now, did not before.
              </li>
            )}
            {s.lostVerdict > 0 && (
              <li>
                <b className="text-cf-amber">{s.lostVerdict} unknown</b> — reached the model before, no verdict in the
                later run (pending, failed or refused by a non-WAF layer). Neither a fix nor a regression; re-run to know.
              </li>
            )}
            {s.otherChanges > 0 && (
              <li className="text-muted">
                {s.otherChanges} other change{s.otherChanges === 1 ? "" : "s"} (stopped by a different control, or a
                verdict where there was none).
              </li>
            )}
            {changed.length === 0 && <li className="text-muted">No attack changed result.</li>}
          </ul>
          {diff.before.scored !== diff.after.scored && (
            <div className="text-[11.5px] text-muted">
              The scored counts differ — attacks with no verdict, a failed request, a non-WAF refusal or a block by a
              guardrail are outside the edge score — so read the percentages, not only the counts.
            </div>
          )}

          {changed.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-left">
                <thead className="text-[10px] uppercase tracking-wider text-subtle">
                  <tr>
                    <th scope="col" className="px-2 py-1 font-semibold">Attack</th>
                    <th scope="col" className="px-2 py-1 font-semibold">Category</th>
                    <th scope="col" className="px-2 py-1 font-semibold">Before</th>
                    <th scope="col" className="px-2 py-1 font-semibold">After</th>
                  </tr>
                </thead>
                <tbody>
                  {changed.map((r) => (
                    <tr key={r.attackKey} className="border-t border-line">
                      <td className="px-2 py-1 font-mono text-[11px] text-subtle">{r.attackKey}</td>
                      <td className="px-2 py-1 text-muted">{r.category}</td>
                      <td className="px-2 py-1">
                        <StatePill state={r.before!} />
                      </td>
                      <td className="px-2 py-1">
                        <StatePill state={r.after!} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <div className="text-[11.5px] text-subtle">
            {changed.length} changed · {unchanged} unchanged
            {added + removed > 0 &&
              ` · ${added} only in the later run, ${removed} only in the earlier run — not counted in the change above`}
          </div>
        </>
      )}

      <div className="text-[11px] text-subtle">
        A saved run does not record the external-guardrail or AI Gateway Guardrails settings in force, so a change in
        "external guardrail" or "guardrails" results may come from those settings rather than the edge.
      </div>
    </div>
  );
}

function RunTag({ run }: { run: RtSavedRun }) {
  return (
    <span className="rounded-full border border-line px-2 py-0.5">
      <span className="font-mono text-subtle">#{run.id}</span> {when(run.ts)}
      {run.label ? <span className="text-text"> · {run.label}</span> : null}
    </span>
  );
}
