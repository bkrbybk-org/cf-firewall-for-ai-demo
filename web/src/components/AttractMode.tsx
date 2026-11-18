// Booth attract mode: the header button that plays DEMO_SCRIPT on a loop while nobody is at the booth, and stops the
// moment a visitor touches the screen or a key. The loop and its limits are lib/attractMode.ts; this file owns the
// browser side — the stop-on-touch listener, pausing while the tab is hidden, and the "try it yourself" pill.
// Never persisted: a reload, leaving booth mode or leaving the page stops it, so nothing loops unseen.
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Hand, Repeat, Square } from "lucide-react";
import type { TurnResult } from "../hooks/useChat";
import { ATTRACT_END_TEXT, runAttract, type AttractEnd } from "../lib/attractMode";
import { DEMO_SCRIPT } from "../lib/data";

// Clicks on these never count as a visitor: the button itself must be able to stop and start the loop.
const CONTROL = "[data-attract-control]";

export function AttractMode({
  sendPrompt,
  clear,
  chatBusy,
}: {
  sendPrompt: (text: string) => Promise<TurnResult>;
  clear: () => void;
  chatBusy: boolean;
}) {
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState<number | null>(null);
  const [ended, setEnded] = useState<AttractEnd | null>(null);
  const stopRef = useRef(false);

  function stop() {
    stopRef.current = true;
    setRunning(false);
    setStep(null);
  }

  // Leaving booth mode or the page unmounts this: the loop must not outlive it.
  useEffect(() => () => void (stopRef.current = true), []);

  // A visitor walked up: any touch, click or key outside the button hands the booth back to them. Capture phase and
  // no preventDefault, so their click on an attack in the library still loads it.
  useEffect(() => {
    if (!running) return;
    const onInput = (e: Event) => {
      if (e.target instanceof Element && e.target.closest(CONTROL)) return;
      stop();
    };
    window.addEventListener("pointerdown", onInput, true);
    window.addEventListener("keydown", onInput, true);
    return () => {
      window.removeEventListener("pointerdown", onInput, true);
      window.removeEventListener("keydown", onInput, true);
    };
  }, [running]);

  // Waits `ms` of VISIBLE time: a hidden tab spends no vendor calls, and the loop resumes where it was when the
  // screen is back. Wakes early once stopped.
  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      let left = ms;
      const tick = () => {
        if (stopRef.current || left <= 0) return resolve();
        if (!document.hidden) left -= 200;
        window.setTimeout(tick, 200);
      };
      tick();
    });
  }

  async function start() {
    if (running || chatBusy) return;
    stopRef.current = false;
    setEnded(null);
    setRunning(true);
    const end = await runAttract({
      prompts: DEMO_SCRIPT.map((s) => s.prompt),
      send: sendPrompt,
      clear,
      sleep,
      now: () => Date.now(),
      stopped: () => stopRef.current,
      onStep: setStep,
    });
    stopRef.current = true;
    setRunning(false);
    setStep(null);
    setEnded(end);
  }

  const title = running
    ? "Attract mode is playing the demo script on a loop. Touch the screen or press a key to stop."
    : ended && ended !== "stopped"
      ? ATTRACT_END_TEXT[ended]
      : "Attract mode: play the demo script on a loop until a visitor touches the screen (stops by itself after an hour)";

  return (
    <>
      <button
        type="button"
        data-attract-control
        aria-pressed={running}
        onClick={running ? stop : start}
        disabled={!running && chatBusy}
        title={title}
        className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50 ${
          running ? "border-cf-red/60 bg-cf-red/10 text-cf-red" : "border-line bg-surface-2 text-muted hover:text-text"
        }`}
      >
        {running ? <Square size={13} /> : <Repeat size={14} />} Attract mode{running ? " · on" : ""}
      </button>
      {!running && ended && ended !== "stopped" && (
        <span role="status" className="hidden text-[12px] text-cf-amber-ink md:inline">
          {ended === "timeLimit" ? "Attract mode stopped after an hour" : "Attract mode stopped: requests failing"}
        </span>
      )}
      {running &&
        createPortal(
          <div
            role="status"
            // Over the prompt input, which nobody uses while the loop runs — never over a verdict. One line.
            className="animate-rise pointer-events-none fixed bottom-4 left-1/2 z-30 flex -translate-x-1/2 items-center gap-2 rounded-full border-2 border-accent bg-surface px-5 py-2.5 text-[15px] font-semibold whitespace-nowrap text-text shadow-lg"
          >
            <Hand size={17} className="text-accent-ink" />
            Self-running demo — touch anywhere to try it yourself
            {step != null && (
              <span className="font-normal text-muted" title={DEMO_SCRIPT[step].label}>
                · {step + 1}/{DEMO_SCRIPT.length}
              </span>
            )}
          </div>,
          document.body,
        )}
    </>
  );
}
