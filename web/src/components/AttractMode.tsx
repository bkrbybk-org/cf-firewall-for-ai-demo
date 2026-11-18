// Booth attract mode: the header button that arms a loop of DEMO_SCRIPT for an unattended booth. A visitor's touch or
// key pauses it and hands the screen over; once nobody has touched it for ATTRACT_IDLE_MS it clears the chat (the next
// visitor never sees the last one's prompt) and resumes. The loop and its limits are lib/attractMode.ts; this file
// owns the browser side — the touch listener, the idle check, pausing while the tab is hidden, and the pill.
// Never persisted: a reload, leaving booth mode or leaving the page disarms it, so nothing loops unseen. The hour
// budget runs from arming, across pauses: an armed booth stops by itself within the hour however often it resumes.
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Hand, Pause, Repeat, Square } from "lucide-react";
import type { TurnResult } from "../hooks/useChat";
import { ATTRACT_END_TEXT, ATTRACT_IDLE_MS, attractResumeDue, runAttract, type AttractEnd } from "../lib/attractMode";
import { DEMO_SCRIPT } from "../lib/data";

// Clicks on these never count as a visitor: the button itself must be able to arm and disarm the loop.
const CONTROL = "[data-attract-control]";

type Phase = "off" | "playing" | "paused";

export function AttractMode({
  sendPrompt,
  clear,
  chatBusy,
}: {
  sendPrompt: (text: string) => Promise<TurnResult>;
  clear: () => void;
  chatBusy: boolean;
}) {
  const [phase, setPhaseState] = useState<Phase>("off");
  const [step, setStep] = useState<number | null>(null);
  const [ended, setEnded] = useState<AttractEnd | null>(null);
  const phaseRef = useRef<Phase>("off");
  const armedAt = useRef(0);
  const lastInput = useRef(0);
  // Each play gets a token; a loop whose token is stale stops at its next check. A resume after a pause must never
  // revive the previous loop, which may still be waiting on the request it sent before the visitor touched.
  const runToken = useRef(0);
  const busyRef = useRef(chatBusy);
  busyRef.current = chatBusy;

  function setPhase(p: Phase) {
    phaseRef.current = p;
    setPhaseState(p);
    if (p !== "playing") setStep(null);
  }

  // Leaving booth mode or the page unmounts this: no loop may outlive it.
  useEffect(
    () => () => {
      runToken.current++;
      phaseRef.current = "off";
    },
    [],
  );

  // Waits `ms` of VISIBLE time: a hidden tab spends no vendor calls. Wakes early once this loop is stale.
  function sleep(ms: number, token: number): Promise<void> {
    return new Promise((resolve) => {
      let left = ms;
      const tick = () => {
        if (runToken.current !== token || left <= 0) return resolve();
        if (!document.hidden) left -= 200;
        window.setTimeout(tick, 200);
      };
      tick();
    });
  }

  async function play() {
    const token = ++runToken.current;
    setEnded(null);
    setPhase("playing");
    const end = await runAttract({
      prompts: DEMO_SCRIPT.map((s) => s.prompt),
      send: sendPrompt,
      clear,
      sleep: (ms) => sleep(ms, token),
      now: () => Date.now(),
      stopped: () => runToken.current !== token,
      onStep: (i) => runToken.current === token && setStep(i),
      startedAt: armedAt.current,
    });
    if (runToken.current !== token && end === "stopped") return; // paused or disarmed: whoever did it set the phase
    runToken.current++;
    setPhase("off");
    setEnded(end);
  }

  function arm() {
    if (phaseRef.current !== "off" || chatBusy) return;
    armedAt.current = Date.now();
    void play();
  }

  function disarm() {
    runToken.current++;
    setPhase("off");
  }

  // A visitor walked up: any touch, click or key outside the button pauses the loop and hands the booth over; while
  // paused, every touch restarts the idle clock. Capture phase and no preventDefault, so the visitor's first click
  // (an attack in the library) still does what they meant.
  useEffect(() => {
    if (phase === "off") return;
    const onInput = (e: Event) => {
      if (e.target instanceof Element && e.target.closest(CONTROL)) return;
      lastInput.current = Date.now();
      if (phaseRef.current === "playing") {
        runToken.current++;
        setPhase("paused");
      }
    };
    window.addEventListener("pointerdown", onInput, true);
    window.addEventListener("keydown", onInput, true);
    return () => {
      window.removeEventListener("pointerdown", onInput, true);
      window.removeEventListener("keydown", onInput, true);
    };
  }, [phase]);

  // Paused: resume once the screen has been left alone, the visitor's own turn has come back, and the tab is visible.
  useEffect(() => {
    if (phase !== "paused") return;
    const id = window.setInterval(() => {
      if (document.hidden) return;
      const due = attractResumeDue({ lastInput: lastInput.current, now: Date.now(), busy: busyRef.current, armedAt: armedAt.current });
      if (due === "resume") void play();
      else if (due === "timeLimit") {
        setPhase("off");
        setEnded("timeLimit");
      }
    }, 1000);
    return () => window.clearInterval(id);
    // Keyed on the phase alone: play() reads refs and the chat's stable callbacks, so a stale closure is harmless.
  }, [phase]);

  const idleS = Math.round(ATTRACT_IDLE_MS / 1000);
  const title =
    phase === "playing"
      ? `Attract mode is playing the demo script. A touch or key pauses it; it resumes after ${idleS} s without one. Click to turn it off.`
      : phase === "paused"
        ? `Attract mode is paused for a visitor and resumes after ${idleS} s without a touch. Click to turn it off.`
        : ended && ended !== "stopped"
          ? ATTRACT_END_TEXT[ended]
          : `Attract mode: play the demo script on a loop; a visitor's touch pauses it, ${idleS} s idle resumes it (off by itself after an hour)`;

  return (
    <>
      <button
        type="button"
        data-attract-control
        aria-pressed={phase !== "off"}
        onClick={phase === "off" ? arm : disarm}
        disabled={phase === "off" && chatBusy}
        title={title}
        className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50 ${
          phase === "playing"
            ? "border-cf-red/60 bg-cf-red/10 text-cf-red"
            : phase === "paused"
              ? "border-accent/60 bg-accent/10 text-accent-ink"
              : "border-line bg-surface-2 text-muted hover:text-text"
        }`}
      >
        {phase === "playing" ? <Square size={13} /> : phase === "paused" ? <Pause size={13} /> : <Repeat size={14} />}
        {phase === "playing" ? " Attract mode · on" : phase === "paused" ? " Attract · paused" : " Attract mode"}
      </button>
      {phase === "paused" && (
        <span className="hidden text-[12px] text-muted md:inline">resumes after {idleS} s without a touch</span>
      )}
      {phase === "off" && ended && ended !== "stopped" && (
        <span role="status" className="hidden text-[12px] text-cf-amber-ink md:inline">
          {ended === "timeLimit" ? "Attract mode stopped after an hour" : "Attract mode stopped: requests failing"}
        </span>
      )}
      {phase === "playing" &&
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
