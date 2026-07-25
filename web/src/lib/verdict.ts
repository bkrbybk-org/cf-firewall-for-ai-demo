// Shared edge-verdict logic: classification of raw Cloudflare actions and the
// GraphQL-ingestion-aware poller. Used by the <Verdict> chip and DemoMode.
import { getVerdict } from "./api";
import type { Verdict } from "./types";

export type Outcome = "block" | "challenge" | "log" | "allow";

export function classify(rawAction: string, hasRule: boolean): Outcome {
  const a = (rawAction || "").toLowerCase();
  if (/block|drop/.test(a)) return "block";
  if (/challenge/.test(a)) return "challenge";
  if (/link_maze/.test(a) || (/log/.test(a) && hasRule)) return "log";
  return "allow";
}

export function actionText(rawAction: string, cls: string): string {
  const a = (rawAction || "").toLowerCase();
  if (cls === "allow") return "allowed — no matching rule";
  if (a === "link_maze_injected") return "log (AI Labyrinth honeypot)";
  return rawAction;
}

// What the edge ultimately did to the request behind a completed verdict.
export function verdictOutcome(d: Verdict): Outcome {
  const hasRule = !!(d.rules && d.rules.length);
  const raw = (hasRule ? d.rules![0].action : d.securityAction || "") || "";
  return classify(raw, hasRule);
}

export type PollResult =
  | { phase: "done"; data: Verdict }
  | { phase: "disabled"; ray?: string }
  | { phase: "error"; message: string };

const MAX_TRIES = 26; // ~5s apart → up to ~130s of ingestion delay
const INTERVAL_MS = 5000;

// Poll /api/verdict until both analytics rows are visible (rule match + AI
// scores ingest independently, in no fixed order), the try budget runs out,
// or cancel() is called (the promise then never settles — callers are gone).
export function pollVerdict(
  ray: string,
  onProgress?: (tries: number) => void,
): { promise: Promise<PollResult>; cancel: () => void } {
  let cancelled = false;
  let timer: number | null = null;

  const promise = new Promise<PollResult>((resolve) => {
    let tries = 0;
    const tick = async () => {
      if (cancelled) return;
      tries++;
      let d: Verdict | null = null;
      try {
        d = await getVerdict(ray);
      } catch {
        /* keep polling */
      }
      if (cancelled) return;
      if (d) {
        if (d.configured === false) return resolve({ phase: "disabled", ray: d.ray });
        if (d.error) return resolve({ phase: "error", message: d.error });
        const ruleExpected = !["", "unknown", "allow"].includes((d.securityAction || "").toLowerCase());
        const ruleReady = !ruleExpected || (d.rules && d.rules.length);
        if (d.ai && ruleReady) return resolve({ phase: "done", data: d });
        if (tries >= MAX_TRIES && (d.ai || d.found)) return resolve({ phase: "done", data: d });
      }
      if (tries >= MAX_TRIES) {
        return resolve({
          phase: "error",
          message: "no edge event yet (ingestion delay, or AI Security not enabled)",
        });
      }
      onProgress?.(tries);
      timer = window.setTimeout(tick, INTERVAL_MS);
    };
    tick();
  });

  return {
    promise,
    cancel: () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    },
  };
}
