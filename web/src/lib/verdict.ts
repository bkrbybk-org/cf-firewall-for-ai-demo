// Shared edge-verdict logic: classification of raw Cloudflare actions and the
// GraphQL-ingestion-aware poller. Used by the <Verdict> chip and DemoMode.
import { getVerdict } from "./api";
import type { Verdict } from "./types";

// "denied" is not a WAF verdict: the edge returned an error status while no
// rule blocked anything, so the request was stopped by a layer the WAF cannot
// see (Cloudflare Access, rate limiting, a managed block without a matching
// custom rule). Kept distinct from "block" so the UI never credits AI
// Security for a rejection it had nothing to do with.
export type Outcome = "block" | "challenge" | "log" | "allow" | "denied";

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
//
// The rule list alone is not enough: a request can match only log-only rules
// (which never stop anything) and still come back 403 because something above
// the WAF rejected it. Trusting the rules there produced the worst kind of
// wrong — a trace claiming the prompt "reached the model" for a request that
// never ran the Worker — so the edge's own status decides when they disagree.
export function verdictOutcome(d: Verdict): Outcome {
  const hasRule = !!(d.rules && d.rules.length);
  const raw = (hasRule ? d.rules![0].action : d.securityAction || "") || "";
  const cls = classify(raw, hasRule);
  // A block/challenge already explains the status. Anything else paired with
  // an error status was stopped by a layer this verdict cannot attribute.
  const stoppedByRule = cls === "block" || cls === "challenge";
  if (!stoppedByRule && d.httpStatus != null && d.httpStatus >= 400) return "denied";
  return cls;
}

export type PollResult =
  | { phase: "done"; data: Verdict }
  | { phase: "disabled"; ray?: string }
  | { phase: "expired"; retentionDays: number }
  | { phase: "error"; message: string };

const MAX_TRIES = 26; // ~5s apart after the initial wait → up to ~190s of ingestion delay
const INTERVAL_MS = 5000;
const INITIAL_DELAY_MS = 60000; // edge analytics take a while to ingest — no point checking sooner

// A settled verdict never changes, so it is worth remembering: expanding the
// same prompt-log row twice, or revisiting a ray already resolved in chat,
// then costs nothing. Only terminal states are cached — a not-yet-ingested
// result must stay refetchable.
const cache = new Map<string, PollResult>();
const inflight = new Map<string, Promise<PollResult>>();

function remember(ray: string, r: PollResult): PollResult {
  if (r.phase === "done" || r.phase === "expired") cache.set(ray, r);
  return r;
}

// Decide whether a response can settle the lookup. Returns null to mean "keep
// waiting" — the two datasets behind a verdict (rule match + AI scores)
// ingest independently and in no fixed order, so a partial answer is normal
// early on. `final` accepts that partial answer: set on the last poll attempt
// and on a one-shot lookup, where waiting longer is not an option.
function resolveVerdict(d: Verdict, final: boolean): PollResult | null {
  if (d.configured === false) return { phase: "disabled", ray: d.ray };
  if (d.error) return { phase: "error", message: d.error };
  // Past retention there is nothing to wait for, so this settles even mid-poll.
  if (d.tooOld) return { phase: "expired", retentionDays: d.retentionDays ?? 0 };
  const ruleExpected = !["", "unknown", "allow"].includes((d.securityAction || "").toLowerCase());
  const ruleReady = !ruleExpected || (d.rules && d.rules.length);
  if (d.ai && ruleReady) return { phase: "done", data: d };
  if (final && (d.ai || d.found)) return { phase: "done", data: d };
  return null;
}

// Single best-effort lookup, for a request old enough that ingestion has
// long since finished. Polling there would only add dead time. Concurrent
// callers for the same ray share one request.
export function fetchVerdictOnce(ray: string, tsMs?: number): Promise<PollResult> {
  const hit = cache.get(ray);
  if (hit) return Promise.resolve(hit);
  const pending = inflight.get(ray);
  if (pending) return pending;

  const run = (async (): Promise<PollResult> => {
    try {
      const d = await getVerdict(ray, tsMs);
      return remember(
        ray,
        resolveVerdict(d, true) ?? {
          phase: "error",
          message: "no edge event recorded for this request",
        },
      );
    } catch (err) {
      return { phase: "error", message: "network error: " + err };
    } finally {
      inflight.delete(ray);
    }
  })();

  inflight.set(ray, run);
  return run;
}

// Poll /api/verdict until both analytics rows are visible, the try budget
// runs out, or cancel() is called (the promise then never settles — callers
// are gone). For a request that was just sent, where ingestion is genuinely
// still in flight; use fetchVerdictOnce for anything older.
export function pollVerdict(
  ray: string,
  onProgress?: (tries: number) => void,
  tsMs?: number,
): { promise: Promise<PollResult>; cancel: () => void } {
  let cancelled = false;
  let timer: number | null = null;

  const promise = new Promise<PollResult>((resolve) => {
    const hit = cache.get(ray);
    if (hit) {
      resolve(hit);
      return;
    }
    let tries = 0;
    const tick = async () => {
      if (cancelled) return;
      tries++;
      let d: Verdict | null = null;
      try {
        d = await getVerdict(ray, tsMs);
      } catch {
        /* keep polling */
      }
      if (cancelled) return;
      if (d) {
        const settled = resolveVerdict(d, tries >= MAX_TRIES);
        if (settled) return resolve(remember(ray, settled));
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
    timer = window.setTimeout(tick, INITIAL_DELAY_MS);
  });

  return {
    promise,
    cancel: () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    },
  };
}
