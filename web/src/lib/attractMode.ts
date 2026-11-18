// Booth attract mode (components/AttractMode.tsx): the booth screen plays the demo script by itself, one prompt at a
// time, until a visitor touches it. The loop lives here with its clock, chat and network injected, so the rules that
// keep it from running away are tested rather than trusted:
//   - every turn is real traffic. It goes through the edge, every enabled vendor and the model, and it counts in
//     Security Analytics, AI Gateway and the guardrail verdict counts like any visitor's. So the loop is paced (one
//     prompt per dwell), stops by itself after ATTRACT_MAX_MS, and stops after ATTRACT_MAX_ERRORS failures in a row
//     rather than hammer a backend that is down;
//   - each prompt is judged alone: the chat is cleared before every step, so with multi-turn on an earlier attack is
//     never sent as history and cannot change the next verdict.
import type { TurnResult } from "../hooks/useChat";

export const ATTRACT_DWELL_MS = 9_000; // the verdict stays on screen this long before the next prompt
export const ATTRACT_GAP_MS = 1_500; // the empty diagram shows this long before the next prompt is sent
export const ATTRACT_MAX_MS = 60 * 60 * 1000; // a forgotten booth screen stops spending vendor calls within the hour
export const ATTRACT_MAX_ERRORS = 3;
// A visitor pauses the loop; it resumes on its own once nobody has touched the screen for this long.
export const ATTRACT_IDLE_MS = 90_000;

export type AttractEnd = "stopped" | "timeLimit" | "errors";

export interface AttractDeps {
  prompts: readonly string[];
  send: (prompt: string) => Promise<TurnResult>;
  clear: () => void;
  // Resolves after `ms`, or early once stopped — the runner checks `stopped()` after every await.
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  stopped: () => boolean;
  onStep?: (index: number) => void;
  // When the presenter armed attract mode. The hour budget runs from here across every pause and resume, so a
  // visitor touching the screen never buys the loop another hour.
  startedAt?: number;
}

export async function runAttract(d: AttractDeps): Promise<AttractEnd> {
  if (d.prompts.length === 0) return "stopped";
  const started = d.startedAt ?? d.now();
  let errors = 0;
  for (let i = 0; ; i = (i + 1) % d.prompts.length) {
    if (d.stopped()) return "stopped";
    if (d.now() - started >= ATTRACT_MAX_MS) return "timeLimit";
    d.clear();
    d.onStep?.(i);
    await d.sleep(ATTRACT_GAP_MS);
    if (d.stopped()) return "stopped";
    const r = await d.send(d.prompts[i]);
    if (d.stopped()) return "stopped";
    errors = r.kind === "error" ? errors + 1 : 0;
    if (errors >= ATTRACT_MAX_ERRORS) return "errors";
    await d.sleep(ATTRACT_DWELL_MS);
  }
}

// Paused by a visitor: resume once nobody has touched the screen for ATTRACT_IDLE_MS — but never mid-request (the
// visitor's own turn is still coming back) and never past the hour budget.
export function attractResumeDue(o: { lastInput: number; now: number; busy: boolean; armedAt: number }): "resume" | "wait" | "timeLimit" {
  if (o.now - o.armedAt >= ATTRACT_MAX_MS) return "timeLimit";
  if (o.busy || o.now - o.lastInput < ATTRACT_IDLE_MS) return "wait";
  return "resume";
}

export const ATTRACT_END_TEXT: Record<AttractEnd, string> = {
  stopped: "Stopped",
  timeLimit: "Stopped after an hour, to save vendor calls — start it again to keep going",
  errors: `Stopped after ${ATTRACT_MAX_ERRORS} failed requests in a row`,
};
