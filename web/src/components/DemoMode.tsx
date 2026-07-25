// One-click guided attack tour. Sends each DEMO_SCRIPT step through the real
// chat pipeline, waits for the edge verdict, and scores the outcome against
// the step's expectation. Presenter talks; the app drives itself.
import { useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  CircleCheck,
  CircleX,
  Clock3,
  Loader2,
  Play,
  Square,
  X,
} from "lucide-react";
import { DEMO_SCRIPT } from "../lib/data";
import { pollVerdict, verdictOutcome, type Outcome } from "../lib/verdict";
import type { TurnResult } from "../hooks/useChat";

type StepState =
  | { phase: "idle" }
  | { phase: "sending" }
  | { phase: "verdict" }
  | { phase: "done"; actual: Outcome | "error" | "pending"; ok: boolean | null };

const STEP_PAUSE_MS = 2000;

function outcomeLabel(actual: StepState & { phase: "done" }): string {
  if (actual.actual === "pending") return "verdict pending";
  if (actual.actual === "error") return "request failed";
  return actual.actual;
}

function StepIcon({ s }: { s: StepState }) {
  if (s.phase === "sending" || s.phase === "verdict")
    return <Loader2 size={15} className="shrink-0 animate-spin text-accent" />;
  if (s.phase === "done") {
    if (s.ok === true) return <CircleCheck size={15} className="shrink-0 text-cf-green" />;
    if (s.ok === false) return <CircleX size={15} className="shrink-0 text-cf-red" />;
    return <Clock3 size={15} className="shrink-0 text-cf-amber" />;
  }
  return <span className="h-[15px] w-[15px] shrink-0 rounded-full border border-line" />;
}

export function DemoMode({
  sendPrompt,
  chatBusy,
  onStart,
}: {
  sendPrompt: (text: string) => Promise<TurnResult>;
  chatBusy: boolean;
  onStart?: () => void; // e.g. clear the conversation so the tour starts clean
}) {
  const [open, setOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<StepState[]>(() => DEMO_SCRIPT.map(() => ({ phase: "idle" })));
  const stopRef = useRef(false);
  const cancelPollRef = useRef<(() => void) | null>(null);

  const setStep = (i: number, s: StepState) =>
    setSteps((prev) => prev.map((x, idx) => (idx === i ? s : x)));

  async function run() {
    if (running || chatBusy) return;
    stopRef.current = false;
    onStart?.();
    setSteps(DEMO_SCRIPT.map(() => ({ phase: "idle" })));
    setOpen(true);
    setRunning(true);

    for (let i = 0; i < DEMO_SCRIPT.length; i++) {
      if (stopRef.current) break;
      const step = DEMO_SCRIPT[i];
      setStep(i, { phase: "sending" });
      const result = await sendPrompt(step.prompt);
      if (stopRef.current) {
        setStep(i, { phase: "idle" });
        break;
      }

      let actual: Outcome | "error" | "pending";
      if (result.kind === "blocked") {
        // 403 at the edge is definitive — no need to wait for analytics.
        actual = "block";
      } else if (result.kind === "error") {
        actual = "error";
      } else if (result.ray) {
        setStep(i, { phase: "verdict" });
        const poll = pollVerdict(result.ray);
        cancelPollRef.current = poll.cancel;
        const settled = await Promise.race([
          poll.promise,
          // Safety valve on top of the poller's own budget.
          new Promise<null>((r) => window.setTimeout(() => r(null), 140_000)),
        ]);
        cancelPollRef.current = null;
        if (stopRef.current) {
          poll.cancel();
          setStep(i, { phase: "idle" });
          break;
        }
        actual = settled && settled.phase === "done" ? verdictOutcome(settled.data) : "pending";
      } else {
        actual = "pending";
      }

      const ok = actual === "error" || actual === "pending" ? null : actual === step.expect;
      setStep(i, { phase: "done", actual, ok });

      if (i < DEMO_SCRIPT.length - 1) {
        await new Promise((r) => window.setTimeout(r, STEP_PAUSE_MS));
      }
    }
    setRunning(false);
  }

  function stop() {
    stopRef.current = true;
    cancelPollRef.current?.();
    cancelPollRef.current = null;
    setRunning(false);
  }

  const done = steps.filter((s) => s.phase === "done");
  const matched = done.filter((s) => s.phase === "done" && s.ok === true).length;
  const scored = done.filter((s) => s.phase === "done" && s.ok !== null).length;
  const finished = !running && done.length === DEMO_SCRIPT.length;

  return (
    <>
      <button
        type="button"
        onClick={run}
        disabled={running || chatBusy}
        className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-accent/60 bg-accent/10 px-3 py-1.5 text-[12.5px] font-semibold text-accent transition hover:bg-accent/20 disabled:opacity-50"
      >
        <Play size={13} /> Run demo
      </button>

      {open &&
        createPortal(
          <div className="fixed right-4 bottom-4 z-30 w-[min(380px,calc(100vw-2rem))] overflow-hidden rounded-2xl border border-line bg-surface shadow-lg">
          <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
            <span className="text-[13px] font-bold">Demo autopilot</span>
            <span className="text-[11.5px] text-muted">
              {running
                ? `step ${Math.min(done.length + 1, DEMO_SCRIPT.length)}/${DEMO_SCRIPT.length}`
                : finished
                  ? `${matched}/${scored} as expected`
                  : "stopped"}
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              {running ? (
                <button
                  type="button"
                  onClick={stop}
                  className="inline-flex items-center gap-1 rounded-full border border-cf-red/60 bg-cf-red/10 px-2.5 py-1 text-[11.5px] font-semibold text-cf-red transition hover:bg-cf-red/20"
                >
                  <Square size={11} /> Stop
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="rounded-full p-1 text-muted transition hover:text-text"
                  aria-label="Close"
                >
                  <X size={15} />
                </button>
              )}
            </div>
          </div>

          <div className="max-h-[50vh] overflow-y-auto p-2">
            {DEMO_SCRIPT.map((step, i) => {
              const s = steps[i];
              return (
                <div key={i} className="flex items-start gap-2.5 rounded-xl px-2 py-2">
                  <div className="mt-0.5">
                    <StepIcon s={s} />
                  </div>
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-semibold text-text">{step.label}</div>
                    <div className="text-[11px] leading-snug text-muted">{step.note}</div>
                    <div className="mt-0.5 text-[11px]">
                      <span className="text-subtle">expect {step.expect}</span>
                      {s.phase === "verdict" && <span className="text-muted"> · awaiting edge verdict…</span>}
                      {s.phase === "done" && (
                        <span
                          className={
                            s.ok === true ? "text-cf-green" : s.ok === false ? "text-cf-red" : "text-cf-amber"
                          }
                        >
                          {" "}
                          · got {outcomeLabel(s)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {finished && (
            <div className="border-t border-line bg-surface-2 px-4 py-2.5 text-[12px]">
              {scored > 0 ? (
                <>
                  <b className="text-text">
                    {matched}/{scored}
                  </b>{" "}
                  <span className="text-muted">
                    verified steps behaved exactly as configured — detections and enforcement happen at the Cloudflare
                    edge, before the model.
                  </span>
                </>
              ) : (
                <span className="text-muted">
                  No edge verdicts available — run this on the production hostname to see live scoring.
                </span>
              )}
              {scored > 0 && done.length - scored > 0 && (
                <span className="text-muted"> {done.length - scored} verdict(s) still pending.</span>
              )}
            </div>
          )}
          </div>,
          document.body,
        )}
    </>
  );
}
