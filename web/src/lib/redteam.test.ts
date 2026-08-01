// Tests for the red-team scoring model.
//
// The whole point of this feature is one honest number: how often did the
// Cloudflare EDGE fail to stop an attack. It is NOT Prisma's ASR (model
// compliance), and it must not silently absorb non-WAF outcomes into that
// number. These tests pin the denominator: only real edge verdicts
// (block/challenge/log/allow) count; `denied` (a non-WAF refusal),
// `guardrails`, `pending`, and `error` are shown but excluded — otherwise the
// percentage would either credit the WAF for a rejection it never made or
// punish it for ingestion lag.
import { describe, expect, it } from "vitest";
import {
  RT_CORPUS,
  scoreRun,
  byCategory,
  bySeverity,
  isReachedModel,
  isStoppedAtEdge,
  isScored,
  type RtRunResult,
  type RtResultState,
} from "./redteam";

const r = (id: string, state: RtResultState): RtRunResult => ({ id, state });

describe("scoreRun", () => {
  it("counts log AND allow as reached-model", () => {
    // A log-only rule did not stop the request — it reached the model. This is
    // the subtle case: `log` is a detection, not a defense.
    const s = scoreRun([r("a", "allow"), r("b", "log")]);
    expect(s.reached).toBe(2);
    expect(s.stopped).toBe(0);
    expect(s.scored).toBe(2);
    expect(s.reachedPct).toBe(100);
  });

  it("counts block and challenge as stopped, not reached", () => {
    const s = scoreRun([r("a", "block"), r("b", "challenge")]);
    expect(s.stopped).toBe(2);
    expect(s.reached).toBe(0);
    expect(s.reachedPct).toBe(0);
  });

  it("excludes denied from the denominator (non-WAF refusal)", () => {
    // 2 reached + 2 stopped + 1 denied. denied must not inflate or shrink the
    // rate: pct is 2/4 = 50, computed over the 4 scored only.
    const s = scoreRun([
      r("a", "allow"),
      r("b", "log"),
      r("c", "block"),
      r("d", "challenge"),
      r("e", "denied"),
    ]);
    expect(s.denied).toBe(1);
    expect(s.scored).toBe(4);
    expect(s.reached).toBe(2);
    expect(s.reachedPct).toBe(50);
  });

  it("excludes guardrails, pending and error from the denominator", () => {
    const s = scoreRun([
      r("a", "allow"),
      r("b", "guardrails"),
      r("c", "pending"),
      r("d", "error"),
    ]);
    expect(s.guardrails).toBe(1);
    expect(s.pending).toBe(1);
    expect(s.error).toBe(1);
    expect(s.scored).toBe(1); // only the allow
    expect(s.reachedPct).toBe(100); // 1/1, unaffected by the three excluded
    expect(s.total).toBe(4);
  });

  it("never divides by zero when nothing scored", () => {
    const s = scoreRun([r("a", "pending"), r("b", "error"), r("c", "denied")]);
    expect(s.scored).toBe(0);
    expect(s.reachedPct).toBe(0);
    expect(s.total).toBe(3);
  });

  it("rounds the percentage (2 of 3 reached → 67)", () => {
    const s = scoreRun([r("a", "allow"), r("b", "log"), r("c", "block")]);
    expect(s.reachedPct).toBe(67);
  });

  it("handles an empty run", () => {
    const s = scoreRun([]);
    expect(s).toMatchObject({ total: 0, scored: 0, reached: 0, reachedPct: 0 });
  });
});

describe("bucket predicates", () => {
  it("isReachedModel is exactly {allow, log}", () => {
    expect(isReachedModel("allow")).toBe(true);
    expect(isReachedModel("log")).toBe(true);
    expect(isReachedModel("block")).toBe(false);
    expect(isReachedModel("denied")).toBe(false);
    expect(isReachedModel("guardrails")).toBe(false);
    expect(isReachedModel("pending")).toBe(false);
  });

  it("isStoppedAtEdge is exactly {block, challenge}", () => {
    expect(isStoppedAtEdge("block")).toBe(true);
    expect(isStoppedAtEdge("challenge")).toBe(true);
    expect(isStoppedAtEdge("log")).toBe(false);
    expect(isStoppedAtEdge("denied")).toBe(false);
  });

  it("isScored excludes every non-verdict state", () => {
    for (const s of ["denied", "guardrails", "pending", "error"] as RtResultState[]) {
      expect(isScored(s)).toBe(false);
    }
    for (const s of ["block", "challenge", "log", "allow"] as RtResultState[]) {
      expect(isScored(s)).toBe(true);
    }
  });
});

describe("breakdowns", () => {
  const results = new Map<string, RtRunResult>([
    ["rt-01", r("rt-01", "allow")], // brand / critical
    ["rt-31", r("rt-31", "block")], // brand / low
  ]);

  it("byCategory tallies reached/scored/total per category and covers the whole corpus", () => {
    const rows = byCategory(RT_CORPUS, results);
    const totalAttacks = rows.reduce((n, x) => n + x.total, 0);
    expect(totalAttacks).toBe(RT_CORPUS.length);
    const brand = rows.find((x) => x.key === "Brand Tarnishing / Self-Criticism")!;
    expect(brand.reached).toBe(1); // rt-01 allow
    expect(brand.scored).toBe(2); // rt-01 allow + rt-31 block
    expect(brand.total).toBeGreaterThanOrEqual(2);
  });

  it("bySeverity is ordered critical→low and spans every attack", () => {
    const rows = bySeverity(RT_CORPUS, results);
    expect(rows.map((x) => x.key)).toEqual(["critical", "high", "medium", "low"]);
    expect(rows.reduce((n, x) => n + x.total, 0)).toBe(RT_CORPUS.length);
  });
});

describe("corpus integrity", () => {
  it("has 36 attacks with unique ids and non-empty prompts", () => {
    expect(RT_CORPUS).toHaveLength(36);
    expect(new Set(RT_CORPUS.map((a) => a.id)).size).toBe(36);
    expect(RT_CORPUS.every((a) => a.prompt.trim().length > 0)).toBe(true);
  });

  it("carries no leftover SARA-AM decomposition artifact (ำา)", () => {
    // The PDF font split ำ into ำ+า; the corpus must be repaired.
    expect(RT_CORPUS.some((a) => a.prompt.includes("ำา"))).toBe(false);
  });

  it("weights the two scan gap categories", () => {
    const brand = RT_CORPUS.filter((a) => a.category === "Brand Tarnishing / Self-Criticism").length;
    const political = RT_CORPUS.filter((a) => a.category.startsWith("Political")).length;
    expect(brand).toBeGreaterThanOrEqual(4);
    expect(political).toBeGreaterThanOrEqual(4);
  });
});
