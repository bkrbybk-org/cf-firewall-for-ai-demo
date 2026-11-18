// Booth mode's scoreboard (components/BoothScoreboard.tsx) and its background edge lookups.
//
// The tally counts where each finished turn ended, from the same banner logic the visitor sees (lib/boothView.ts),
// since this page load — in memory only, like the chat itself (lib/sessionStore.ts): a reload starts a fresh count,
// and the scoreboard says from when it counts.
//
// The edge lookups answer the one question a response cannot: did a log-only WAF rule match a prompt that went on?
// The edge log takes a minute or more to ingest, so the answer arrives later and is published to lib/verdictStore.ts,
// where the turn's banner, strip and the architecture diagram pick it up if they are still on screen. Attract mode
// sends a prompt every ~12 s and each lookup polls zone GraphQL for a minute or two, so lookups are capped: at most
// LOOKUP_ACTIVE at once and LOOKUP_QUEUED waiting, the oldest waiting one dropped first — and every drop is counted
// and shown ("not looked up"), never folded into "clean".
import type { TurnMsg } from "./boothView";
import { rayOf } from "./boothView";
import { createStore } from "./sessionStore";
import { pollVerdict, verdictOutcome } from "./verdict";
import { publishEdge } from "./verdictStore";

export type TallyKey = "edge" | "refused" | "vendors" | "gateway" | "fortiaigate" | "reached" | "passedOnly" | "failed";
export type LookupResult = "logged" | "clean" | "unavailable";

export interface Tally {
  since: number | null;
  turns: number;
  counts: Record<TallyKey, number>;
  lookups: Record<LookupResult, number> & { pending: number; skipped: number };
}

const ZERO: Tally = {
  since: null,
  turns: 0,
  counts: { edge: 0, refused: 0, vendors: 0, gateway: 0, fortiaigate: 0, reached: 0, passedOnly: 0, failed: 0 },
  lookups: { logged: 0, clean: 0, unavailable: 0, pending: 0, skipped: 0 },
};

// Where a finished turn ended. A 403 is credited to the edge's AI Security only when the response named the
// detection, as the banner does; a bare 403 is "refused" (Cloudflare Access answers 403 too).
export function tallyKey(m: TurnMsg): TallyKey | null {
  switch (m.kind) {
    case "blocked":
      return m.detection ? "edge" : "refused";
    case "external":
    case "replyWithheld":
      return "vendors";
    case "guardrails":
      return "gateway";
    case "fortiaigate":
      return "fortiaigate";
    case "assistant":
      return m.streaming ? null : "reached";
    case "guardrailOnly":
      return "passedOnly";
    case "error":
      return "failed";
    default:
      return null;
  }
}

// Only a turn that got past the edge has an open edge question, and only one with a ray can be looked up.
export function lookupRay(m: TurnMsg): string | undefined {
  if (m.kind === "blocked" || m.kind === "error") return undefined;
  if (m.kind === "assistant" && m.streaming) return undefined;
  return rayOf(m);
}

export const LOOKUP_ACTIVE = 2;
export const LOOKUP_QUEUED = 4;

// A bounded lookup queue, with the network injected so its limits are tested. `run` settles with the finding.
export function createLookupQueue(opts: {
  run: (ray: string) => Promise<LookupResult>;
  onChange: (delta: { result?: LookupResult; skipped?: number; pending: number }) => void;
  maxActive?: number;
  maxQueued?: number;
}) {
  const maxActive = opts.maxActive ?? LOOKUP_ACTIVE;
  const maxQueued = opts.maxQueued ?? LOOKUP_QUEUED;
  const queue: string[] = [];
  const seen = new Set<string>();
  let active = 0;
  const pending = () => active + queue.length;

  function pump() {
    while (active < maxActive && queue.length > 0) {
      const ray = queue.shift()!;
      active++;
      opts.run(ray).then(
        (result) => done(result),
        () => done("unavailable"),
      );
    }
  }
  function done(result: LookupResult) {
    active--;
    opts.onChange({ result, pending: pending() });
    pump();
  }

  return {
    add(ray: string) {
      if (seen.has(ray)) return;
      seen.add(ray);
      queue.push(ray);
      let skipped = 0;
      while (queue.length > maxQueued) {
        queue.shift(); // the oldest waiting turn is the one least likely to still be on screen
        skipped++;
      }
      opts.onChange({ skipped, pending: pending() });
      pump();
    },
    pending,
  };
}

export const boothTally = createStore<Tally>(ZERO);

function lookupEdge(ray: string): Promise<LookupResult> {
  return pollVerdict(ray).promise.then((r) => {
    if (r.phase !== "done") {
      publishEdge(ray, "unavailable");
      return "unavailable";
    }
    const outcome = verdictOutcome(r.data);
    publishEdge(ray, outcome);
    return outcome === "log" ? "logged" : outcome === "allow" ? "clean" : "unavailable";
  });
}

const queue = createLookupQueue({
  run: lookupEdge,
  onChange: ({ result, skipped = 0, pending }) =>
    boothTally.set((t) => ({
      ...t,
      lookups: {
        ...t.lookups,
        ...(result ? { [result]: t.lookups[result] + 1 } : {}),
        skipped: t.lookups.skipped + skipped,
        pending,
      },
    })),
});

const counted = new Set<number>();

export interface ScorePart {
  key: TallyKey;
  count: number;
  label: string;
}

const PART_LABEL: Record<TallyKey, string> = {
  edge: "blocked by Cloudflare AI Security",
  refused: "refused by the edge, not attributed",
  vendors: "stopped by partner guardrails",
  gateway: "stopped by AI Gateway",
  fortiaigate: "stopped by FortiAIGate",
  reached: "reached the model",
  passedOnly: "passed every check (model not called)",
  failed: "failed",
};
const ORDER: TallyKey[] = ["edge", "refused", "vendors", "gateway", "fortiaigate", "reached", "passedOnly", "failed"];

// The scoreboard's words. A zero category is left out rather than shown as "0" — absent is not a measurement — and
// the edge-log line counts only lookups that answered, naming the pending, dropped and unavailable ones beside it.
export function scoreboard(t: Tally): { parts: ScorePart[]; edgeLog: string | null } {
  const parts = ORDER.filter((k) => t.counts[k] > 0).map((k) => ({ key: k, count: t.counts[k], label: PART_LABEL[k] }));
  const l = t.lookups;
  const answered = l.logged + l.clean;
  if (answered + l.unavailable + l.pending + l.skipped === 0) return { parts, edgeLog: null };
  const extra = [
    l.pending ? `${l.pending} pending` : "",
    l.unavailable ? `${l.unavailable} unavailable` : "",
    l.skipped ? `${l.skipped} not looked up` : "",
  ].filter(Boolean);
  const head = answered
    ? `Edge log: ${l.logged} of ${answered} looked up matched a log-only rule`
    : "Edge log: no lookup has answered yet";
  return { parts, edgeLog: extra.length ? `${head} (${extra.join(", ")})` : head };
}

// Booth mode is showing: the scoreboard counts from now (once per page load).
export function startTally(now = Date.now()): void {
  if (boothTally.get().since == null) boothTally.set((t) => ({ ...t, since: now }));
}

// Count a finished turn once (message ids are unique per page load), and look its edge up when it has an open
// question. Idempotent, so a re-render or a remount never counts a turn twice.
export function recordTurn(m: TurnMsg): void {
  if (counted.has(m.id)) return;
  const key = tallyKey(m);
  if (!key) return;
  startTally();
  // A turn from before booth mode came on (still in the chat history) is outside "Since HH:MM": never counted.
  if (m.tsMs < (boothTally.get().since ?? 0)) return;
  counted.add(m.id);
  boothTally.set((t) => ({ ...t, turns: t.turns + 1, counts: { ...t.counts, [key]: t.counts[key] + 1 } }));
  const ray = lookupRay(m);
  if (ray) queue.add(ray);
}
