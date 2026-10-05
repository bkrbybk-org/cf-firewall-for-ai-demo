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
import { ArrowRight, GitCompare, Loader2, Save, Trash2 } from "lucide-react";
import { deleteRedTeamRun, getRedTeamRun, listRedTeamRuns, saveRedTeamRun, type RedTeamRunSaveRequest } from "../../lib/api";
import { diffRuns, type RtRunDiff, type RtSavedRun } from "../../lib/redteam";
import { summarizeDiff, toSavedRun } from "../../lib/savedRuns";
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
              Tick two runs to compare them{picked.length === 1 ? " — one more" : ""}.
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

        {picked.length === 2 && <Comparison ids={picked} />}
      </div>
    </section>
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
