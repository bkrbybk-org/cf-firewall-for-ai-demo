// "Test all vendors": runs every fixed test sample against every vendor whose credentials are saved,
// ONE REQUEST AT A TIME (vendors rate-limit, and this is an admin action, not a benchmark), through the
// same endpoint as each card's own "Test connection". What to run and how to word an outcome lives in
// lib/testAll.ts, with the tests; this file is only the loop and the table.
//
// Honesty rules the page keeps (the reasons are in lib/testAll.ts):
//  - a failed test reads "error" and its text — never allow or block;
//  - a test not yet run reads "—", never blank and never "0 ms";
//  - the verdict is always a written word, so colour is never the only signal;
//  - the copied report holds named fields only: the table and each test's response shape (field names
//    and types, no text). A vendor's raw body, if one ever arrived, is not read.
import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Loader2, Lock } from "lucide-react";
import { testExternalGuardrail } from "../../lib/api";
import {
  cellFor,
  countRows,
  reportText,
  rowsFor,
  runKey,
  skippedText,
  TEST_ALL_SAMPLE_LABEL,
  testPlan,
  type CellTone,
  type TestAllOutcome,
  type TestPlan,
} from "../../lib/testAll";
import type { ExternalGuardrailConfig } from "../../lib/types";

// Same look as SettingsPage's BTN_CLS (not exported there).
const BTN_CLS =
  "rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] font-semibold text-text transition-colors hover:border-line-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50";

const TONE_CLS: Record<CellTone, string> = {
  allow: "text-cf-green-ink",
  block: "text-cf-red",
  partial: "text-cf-amber-ink",
  error: "text-cf-red",
  none: "text-subtle",
};

type Phase = "idle" | "running" | "stopped" | "finished";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// The endpoint answers JSON even for a 400 / 403 (`{ error }`), but a proxy in front of it may not.
// Anything that is not an object is an error, and the vendor's raw body is dropped here as well: the
// table and the report never read it, and there is no reason to keep it in memory.
function normalise(r: unknown): TestAllOutcome {
  if (!r || typeof r !== "object") return { error: "The server returned something that is not a test result" };
  const o = r as TestAllOutcome;
  if (o.result && typeof o.result === "object" && "raw" in o.result) {
    const { raw, ...result } = o.result;
    void raw;
    return { ...o, result };
  }
  return o;
}

export function TestAllVendors({ providers, canEdit }: { providers: ExternalGuardrailConfig[]; canEdit: boolean }) {
  const live = useMemo(() => testPlan(providers), [providers]);
  // The plan a run started with. The page may reload `providers` mid-run (a key saved elsewhere); the
  // table must keep describing what was actually run.
  const [frozen, setFrozen] = useState<TestPlan | null>(null);
  const plan = frozen ?? live;
  const [results, setResults] = useState<Record<string, TestAllOutcome>>({});
  const [phase, setPhase] = useState<Phase>("idle");
  const [stopping, setStopping] = useState(false);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const stopRef = useRef(false);
  const aliveRef = useRef(true);
  useEffect(() => {
    aliveRef.current = true;
    return () => {
      // Leaving the page stops the loop: no further request is sent for a page nobody is looking at.
      aliveRef.current = false;
      stopRef.current = true;
    };
  }, []);

  const rows = useMemo(() => rowsFor(plan.runs, results), [plan, results]);
  const counts = countRows(rows);
  const ran = counts.total - counts.notRun;
  const running = phase === "running";

  async function runAll() {
    const p = testPlan(providers);
    if (p.runs.length === 0) return;
    stopRef.current = false;
    setStopping(false);
    setCopy("idle");
    setFrozen(p);
    setResults({});
    setPhase("running");
    let completed = 0;
    for (const run of p.runs) {
      if (stopRef.current) break;
      let outcome: TestAllOutcome;
      try {
        outcome = normalise(await testExternalGuardrail(run.provider, run.sample));
      } catch (e) {
        // A network failure or a non-JSON body: no verdict, so it is recorded as an error with its reason.
        outcome = { error: `Request failed: ${errMsg(e)}` };
      }
      if (!aliveRef.current) return;
      completed++;
      setResults((prev) => ({ ...prev, [runKey(run)]: outcome }));
    }
    if (!aliveRef.current) return;
    setStopping(false);
    setPhase(completed < p.runs.length ? "stopped" : "finished");
  }

  function stop() {
    stopRef.current = true;
    setStopping(true);
  }

  async function copyReport() {
    try {
      await navigator.clipboard.writeText(reportText(rows, { skipped: plan.skipped, generatedAt: new Date().toISOString() }));
      setCopy("copied");
    } catch {
      setCopy("failed");
    }
  }

  const blockedReason = !canEdit
    ? "Only a guardrail admin can run tests"
    : live.runs.length === 0
      ? "No vendor has everything saved that a test needs"
      : null;

  return (
    <div className="space-y-3 rounded-2xl border border-line bg-surface p-4">
      <div>
        <h4 className="text-[13px] font-bold text-text">Test all vendors</h4>
        <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
          Sends every fixed test prompt to every vendor with a saved key, one request at a time, using the saved
          configuration. Each result is a real call to the vendor. A test that gets no verdict shows as{" "}
          <b>error</b>, never as allow or block.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => void runAll()}
          disabled={!canEdit || running || live.runs.length === 0}
          aria-describedby={blockedReason ? "test-all-why" : undefined}
          className={BTN_CLS}
        >
          {running ? "Running…" : `Run all tests (${live.runs.length})`}
        </button>
        {running && (
          <button type="button" onClick={stop} disabled={stopping} className={BTN_CLS}>
            {stopping ? "Stopping…" : "Stop"}
          </button>
        )}
        <button
          type="button"
          onClick={() => void copyReport()}
          disabled={ran === 0}
          className={BTN_CLS}
          title={ran === 0 ? "Run at least one test first" : undefined}
        >
          {copy === "copied" ? "Copied" : copy === "failed" ? "Copy failed" : "Copy report"}
        </button>
        {blockedReason && (
          <span id="test-all-why" className="flex items-center gap-1.5 text-[11.5px] text-muted">
            {!canEdit && <Lock size={12} className="shrink-0 text-cf-amber-ink" />}
            {blockedReason}
          </span>
        )}
      </div>

      <div role="status" aria-live="polite" className="text-[12px] text-muted">
        {phase === "running" && (
          <span className="flex items-center gap-1.5">
            <Loader2 size={13} className="animate-spin" />
            {stopping
              ? `Stopping after the current request — ${ran} of ${counts.total} done.`
              : `Running ${Math.min(ran + 1, counts.total)} of ${counts.total}…`}
          </span>
        )}
        {phase === "stopped" && (
          <span>
            Stopped after {ran} of {counts.total} tests — the other {counts.notRun} did not run (shown as —).
          </span>
        )}
        {phase === "finished" && (
          <span>
            Finished {counts.total} tests: {counts.answered} got a verdict, {counts.errors} got an error.
          </span>
        )}
      </div>

      {plan.skipped.length > 0 && <p className="text-[11.5px] leading-relaxed text-muted">{skippedText(plan.skipped)}</p>}

      {rows.length > 0 && (
        // `relative`: the sr-only caption is absolutely positioned and would otherwise escape this clip.
        <div className="relative overflow-x-auto rounded-xl border border-line">
          <table className="w-full min-w-[34rem] border-collapse text-left text-[12px]">
            <caption className="sr-only">Guardrail test results, one row per vendor and test prompt</caption>
            <thead>
              <tr className="border-b border-line bg-surface-2 text-[11px] text-muted">
                <th scope="col" className="px-3 py-1.5 font-semibold">Vendor</th>
                <th scope="col" className="px-3 py-1.5 font-semibold">Test</th>
                <th scope="col" className="px-3 py-1.5 font-semibold">Verdict</th>
                <th scope="col" className="px-3 py-1.5 text-right font-semibold">Latency</th>
                <th scope="col" className="px-3 py-1.5 text-right font-semibold">HTTP</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const c = cellFor(r.outcome);
                return (
                  <tr key={runKey(r)} className="border-b border-line last:border-b-0 align-top">
                    <td className="px-3 py-1.5 text-text">{r.label}</td>
                    <td className="px-3 py-1.5 text-muted">{TEST_ALL_SAMPLE_LABEL[r.sample]}</td>
                    <td className={`px-3 py-1.5 ${TONE_CLS[c.tone]}`}>
                      <span className="flex items-start gap-1.5">
                        {c.tone === "error" && <AlertTriangle size={13} className="mt-0.5 shrink-0" />}
                        <span className="min-w-0">
                          <b className="font-mono">{c.verdict}</b>
                          {c.detail && <span className="mt-0.5 block font-mono text-[11px] font-normal break-words">{c.detail}</span>}
                        </span>
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono whitespace-nowrap text-muted">{c.latency}</td>
                    <td className="px-3 py-1.5 text-right font-mono whitespace-nowrap text-muted">{c.http}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
