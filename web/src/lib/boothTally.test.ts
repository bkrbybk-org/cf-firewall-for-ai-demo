// Booth scoreboard and its background edge lookups (2026-11-18): count each turn once, inside the stated window,
// credit only what the banner credits, and never let attract mode flood the edge-log lookups.
import { describe, expect, it } from "vitest";
import type { TurnMsg } from "./boothView";
import { boothTally, createLookupQueue, lookupRay, recordTurn, scoreboard, startTally, tallyKey, type LookupResult, type Tally } from "./boothTally";
import type { GuardrailPipelineResult } from "./types";

const t = (id: number, tsMs = Date.now()) => ({ id, ts: "12:00:00", tsMs });
const P: GuardrailPipelineResult = { mode: "sequential", guardrailOnly: false, results: [], notRun: [], stoppedBy: null, latencyMs: 1 };

describe("tallyKey — the banner's credit, nothing more", () => {
  it("a 403 counts for AI Security only when the response named the detection", () => {
    expect(tallyKey({ ...t(1), kind: "blocked", raw: "{}", contentType: "application/json", detection: "pii" })).toBe("edge");
    expect(tallyKey({ ...t(2), kind: "blocked", raw: "<html>", contentType: "text/html" })).toBe("refused");
  });
  it("a streaming reply is not finished, so not counted yet", () => {
    expect(tallyKey({ ...t(3), kind: "assistant", text: "He", streaming: true, meta: {} })).toBeNull();
    expect(tallyKey({ ...t(3), kind: "assistant", text: "Hello", meta: {} })).toBe("reached");
  });
  it("each control gets its own count", () => {
    expect(tallyKey({ ...t(4), kind: "external", pipeline: P })).toBe("vendors");
    expect(tallyKey({ ...t(5), kind: "replyWithheld", pipeline: P, replyPipeline: P } as TurnMsg)).toBe("vendors");
    expect(tallyKey({ ...t(6), kind: "guardrails" })).toBe("gateway");
    expect(tallyKey({ ...t(7), kind: "fortiaigate", by: "fortiaigate" })).toBe("fortiaigate");
    expect(tallyKey({ ...t(8), kind: "error", text: "x" })).toBe("failed");
  });
});

describe("lookupRay — only an open edge question is looked up", () => {
  it("not for an edge block (the edge already answered) nor an error; yes for a reply with a ray", () => {
    expect(lookupRay({ ...t(1), kind: "blocked", ray: "r1", raw: "{}", contentType: "application/json", detection: "pii" })).toBeUndefined();
    expect(lookupRay({ ...t(2), kind: "assistant", text: "Hi", meta: { ray: "r2" } })).toBe("r2");
    expect(lookupRay({ ...t(3), kind: "assistant", text: "Hi", meta: {} })).toBeUndefined();
    expect(lookupRay({ ...t(4), kind: "external", ray: "r4", pipeline: P })).toBe("r4");
  });
});

describe("createLookupQueue — bounded, and every drop is counted", () => {
  function setup() {
    const started: string[] = [];
    const finish: Record<string, (r: LookupResult) => void> = {};
    const events: { result?: LookupResult; skipped?: number; pending: number }[] = [];
    const q = createLookupQueue({
      run: (ray) => {
        started.push(ray);
        return new Promise((res) => (finish[ray] = res));
      },
      onChange: (d) => events.push(d),
      maxActive: 2,
      maxQueued: 2,
    });
    return { q, started, finish, events };
  }

  it("runs at most maxActive at once, and starts the next as one finishes", async () => {
    const s = setup();
    ["a", "b", "c"].forEach((r) => s.q.add(r));
    expect(s.started).toEqual(["a", "b"]);
    s.finish.a("logged");
    await Promise.resolve();
    await Promise.resolve();
    expect(s.started).toEqual(["a", "b", "c"]);
    expect(s.events.some((e) => e.result === "logged")).toBe(true);
  });

  it("drops the OLDEST waiting ray past maxQueued and reports it as skipped", () => {
    const s = setup();
    ["a", "b", "c", "d", "e"].forEach((r) => s.q.add(r)); // a, b running; c, d queued; e pushes c out
    expect(s.events.reduce((n, e) => n + (e.skipped ?? 0), 0)).toBe(1);
    expect(s.q.pending()).toBe(4);
  });

  it("never looks the same ray up twice", () => {
    const s = setup();
    s.q.add("a");
    s.q.add("a");
    expect(s.started).toEqual(["a"]);
  });
});

describe("scoreboard — words with their gaps named", () => {
  const base: Tally = {
    since: 0,
    turns: 5,
    counts: { edge: 3, refused: 0, vendors: 1, gateway: 0, fortiaigate: 0, reached: 1, passedOnly: 0, failed: 0 },
    lookups: { logged: 0, clean: 0, unavailable: 0, pending: 0, skipped: 0 },
  };
  it("leaves a zero category out rather than show 0", () => {
    const s = scoreboard(base);
    expect(s.parts.map((p) => p.key)).toEqual(["edge", "vendors", "reached"]);
    expect(s.edgeLog).toBeNull();
  });
  it("counts only answered lookups, and names pending, unavailable and dropped ones beside them", () => {
    const s = scoreboard({ ...base, lookups: { logged: 1, clean: 2, unavailable: 1, pending: 2, skipped: 3 } });
    expect(s.edgeLog).toBe("Edge log: 1 of 3 looked up matched a log-only rule (2 pending, 1 unavailable, 3 not looked up)");
    const waiting = scoreboard({ ...base, lookups: { logged: 0, clean: 0, unavailable: 0, pending: 1, skipped: 0 } });
    expect(waiting.edgeLog).toBe("Edge log: no lookup has answered yet (1 pending)");
  });
});

describe("recordTurn — once per turn, inside the window", () => {
  it("counts a turn once however often it is recorded, and never a turn from before booth mode came on", () => {
    startTally(1_000);
    const before = boothTally.get().turns;
    recordTurn({ ...t(9001, 500), kind: "external", pipeline: P }); // older than "since"
    const reply: TurnMsg = { ...t(9002, 2_000), kind: "assistant", text: "Hi", meta: {} };
    recordTurn(reply);
    recordTurn(reply);
    expect(boothTally.get().turns).toBe(before + 1);
    expect(boothTally.get().counts.vendors).toBe(0);
  });
});
