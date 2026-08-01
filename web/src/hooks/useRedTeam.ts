// Red-team batch runner. Fires the curated corpus through the REAL /api/chat
// pipeline, then resolves each request's edge verdict and scores it.
//
// Three phases, deliberately NOT one poll-per-attack (that would cost ≥60s each
// — 36 attacks ≈ 36 min):
//   1. SEND    — fire every prompt sequentially, collect {ray, ts, kind}.
//   2. SETTLE  — wait ONCE for GraphQL ingestion (~90s).
//   3. RESOLVE — batch-resolve every ray via fetchVerdictOnce (anchored to each
//                request's own ts, deduped by the module-level ray cache),
//                concurrency-capped so we don't hammer /api/verdict.
//
// The runner calls the API directly rather than going through useChat, so a run
// never touches the chat transcript. Rows still land in D1 (excludeFromLog is
// left false), so the Analytics → Prompt log tab is the persistent record.
import { useCallback, useRef, useState } from "react";
import { postChat } from "../lib/api";
import { fetchVerdictOnce, verdictOutcome } from "../lib/verdict";
import type { RedTeamAttack, RtResultState, RtRunResult } from "../lib/redteam";

export type RtPhase = "idle" | "sending" | "settling" | "resolving" | "done" | "stopped";

// Per-attack progress state shown in the table while a run is live.
export type RtAttackState = "queued" | "sending" | "sent" | "resolving" | RtResultState;

const SETTLE_MS = 90_000; // GraphQL ingestion lag before the one-shot lookups
const RESOLVE_CONCURRENCY = 6;

// Route the whole batch runs through. `direct` = plain Workers AI (the path the
// scan targeted). `gateway` sends through an AI Gateway, which adds Guardrails —
// so the guarded gateway can produce 2016/2017 blocks the edge WAF alone won't.
export interface RtRouteConfig {
  route: "direct" | "gateway";
  gatewayId?: string; // gateway route only
}

// One send through /api/chat, classified the same way useChat classifies a
// non-stream response — but with no side effects on the message store.
async function sendOne(
  prompt: string,
  cfg: RtRouteConfig,
): Promise<{ ray?: string; kind: "reply" | "blocked" | "guardrails" | "error" }> {
  try {
    // Minimal body: the server fills in the default model + system prompt.
    // stream:false so we get a JSON result with the ray.
    const gateway = cfg.route === "gateway";
    const res = await postChat({
      prompt,
      stream: false,
      gateway: gateway || undefined,
      gatewayId: gateway ? cfg.gatewayId || undefined : undefined,
    });
    if (res.mode === "stream") {
      // Shouldn't happen with stream:false, but treat a stream as a reply.
      return { ray: res.ray?.split("-")[0], kind: "reply" };
    }
    const { status, data } = res;
    const ray = data?.ray?.split("-")[0] || undefined;
    if (status === 403) return { ray, kind: "blocked" };
    if (data?.guardrailsBlocked) return { ray, kind: "guardrails" };
    if (status >= 200 && status < 300 && data?.reply) return { ray, kind: "reply" };
    return { ray, kind: "error" };
  } catch {
    return { kind: "error" };
  }
}

// Turn a settled send + its edge verdict into the final run state.
async function resolveState(
  ray: string | undefined,
  ts: number,
  kind: "reply" | "blocked" | "guardrails" | "error",
): Promise<RtResultState> {
  if (kind === "guardrails") return "guardrails";
  if (kind === "error") return "error";
  // A 200 reply is ground truth that the request reached the model; a 403 is
  // ground truth that something at the edge stopped it. The verdict lookup
  // refines *which* — but can never overturn those facts, so we clamp.
  if (!ray) return kind === "reply" ? "allow" : "block";

  const v = await fetchVerdictOnce(ray, ts);
  if (v.phase !== "done") {
    // No verdict ingested. Fall back to the send's own ground truth rather than
    // dropping the attack as unscored when we already know what happened.
    return kind === "reply" ? "allow" : "block";
  }
  const outcome = verdictOutcome(v.data); // block | challenge | log | allow | denied
  if (kind === "reply") {
    // Reached the model. If the verdict somehow says it was stopped, trust the
    // 200 and record it as reached (allow) — never claim a block for a request
    // the model actually answered.
    return outcome === "log" ? "log" : "allow";
  }
  // kind === "blocked": trust the verdict's block/denied/challenge distinction
  // (this is exactly where denied vs block matters — Access vs the WAF).
  return outcome === "log" || outcome === "allow" ? "denied" : outcome;
}

// Bounded-concurrency map, preserving input order in the callback.
async function mapPool<T>(items: T[], limit: number, fn: (item: T, i: number) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}

export interface RedTeamRun {
  phase: RtPhase;
  attackStates: Record<string, RtAttackState>;
  results: Map<string, RtRunResult>;
  settleLeftMs: number; // countdown shown during the settle phase
  /** The corpus is passed in per run — the built-in scan set or an uploaded CSV. */
  run: (cfg: RtRouteConfig, corpus: RedTeamAttack[]) => void;
  stop: () => void;
  /** Drop results. Required when the corpus changes: the scorecard sums every
   *  result in the map, so keeping them would score the OLD corpus beside the
   *  new corpus's table. */
  reset: () => void;
}

export function useRedTeam(): RedTeamRun {
  const [phase, setPhase] = useState<RtPhase>("idle");
  const [attackStates, setAttackStates] = useState<Record<string, RtAttackState>>({});
  const [results, setResults] = useState<Map<string, RtRunResult>>(new Map());
  const [settleLeftMs, setSettleLeftMs] = useState(0);
  const stopRef = useRef(false);
  const settleTimer = useRef<number | null>(null);

  const setOne = useCallback((id: string, s: RtAttackState) => {
    setAttackStates((prev) => ({ ...prev, [id]: s }));
  }, []);

  const stop = useCallback(() => {
    stopRef.current = true;
    if (settleTimer.current) window.clearInterval(settleTimer.current);
    setPhase("stopped");
  }, []);

  const run = useCallback(async (cfg: RtRouteConfig, corpus: RedTeamAttack[]) => {
    if (corpus.length === 0) return;
    stopRef.current = false;
    setResults(new Map());
    setSettleLeftMs(0);
    setAttackStates(Object.fromEntries(corpus.map((a) => [a.id, "queued" as RtAttackState])));
    setPhase("sending");

    // ── Phase 1: send ────────────────────────────────────────────────────
    const sent: { id: string; ray?: string; ts: number; kind: "reply" | "blocked" | "guardrails" | "error" }[] = [];
    for (const a of corpus) {
      if (stopRef.current) return;
      setOne(a.id, "sending");
      const ts = Date.now();
      const { ray, kind } = await sendOne(a.prompt, cfg);
      if (stopRef.current) return;
      sent.push({ id: a.id, ray, ts, kind });
      setOne(a.id, "sent");
    }

    // ── Phase 2: settle (one wait for the whole batch) ───────────────────
    setPhase("settling");
    setSettleLeftMs(SETTLE_MS);
    await new Promise<void>((resolve) => {
      const end = Date.now() + SETTLE_MS;
      settleTimer.current = window.setInterval(() => {
        const left = end - Date.now();
        if (stopRef.current || left <= 0) {
          if (settleTimer.current) window.clearInterval(settleTimer.current);
          setSettleLeftMs(0);
          resolve();
        } else {
          setSettleLeftMs(left);
        }
      }, 250);
    });
    if (stopRef.current) return;

    // ── Phase 3: resolve verdicts, concurrency-capped ────────────────────
    setPhase("resolving");
    const out = new Map<string, RtRunResult>();
    await mapPool(sent, RESOLVE_CONCURRENCY, async (s) => {
      if (stopRef.current) return;
      setOne(s.id, "resolving");
      const state = await resolveState(s.ray, s.ts, s.kind);
      if (stopRef.current) return;
      const result: RtRunResult = { id: s.id, ray: s.ray, ts: s.ts, state };
      out.set(s.id, result);
      setResults(new Map(out));
      setOne(s.id, state);
    });
    if (stopRef.current) return;
    setPhase("done");
  }, [setOne]);

  const reset = useCallback(() => {
    stopRef.current = true;
    if (settleTimer.current) window.clearInterval(settleTimer.current);
    setResults(new Map());
    setAttackStates({});
    setSettleLeftMs(0);
    setPhase("idle");
  }, []);

  return { phase, attackStates, results, settleLeftMs, run, stop, reset };
}
