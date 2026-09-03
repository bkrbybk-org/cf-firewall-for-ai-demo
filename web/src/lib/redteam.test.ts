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
  estimateRunSeconds,
  formatDuration,
  RT_CORPUS,
  scoreRun,
  byCategory,
  bySeverity,
  isReachedModel,
  isStoppedAtEdge,
  isScored,
  attackKey,
  corpusFingerprint,
  diffRuns,
  type RtRunResult,
  type RtResultState,
  type RedTeamAttack,
  type RtSavedRun,
  type RtStoredResult,
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

describe("estimateRunSeconds", () => {
  it("is zero for an empty corpus", () => {
    expect(estimateRunSeconds(0)).toBe(0);
    expect(estimateRunSeconds(0, 5000)).toBe(0);
  });

  it("counts sends, the single settle, and the resolve pass", () => {
    // 1 send: 4s send + 90s settle + 1.5s resolve.
    expect(estimateRunSeconds(1)).toBeCloseTo(95.5, 5);
  });

  it("applies the pacing delay n-1 times, not n", () => {
    // The runner skips the gap after the LAST send, so 3 prompts have 2 gaps.
    // Getting this wrong would overstate every estimate by one full delay —
    // 30s at the slowest preset.
    expect(estimateRunSeconds(3, 1000) - estimateRunSeconds(3, 0)).toBeCloseTo(2, 5);
    expect(estimateRunSeconds(1, 30_000)).toBe(estimateRunSeconds(1, 0));
  });

  it("grows with the delay", () => {
    expect(estimateRunSeconds(100, 5000)).toBeGreaterThan(estimateRunSeconds(100, 0));
  });

  it("ignores a negative delay rather than subtracting time", () => {
    expect(estimateRunSeconds(10, -5000)).toBe(estimateRunSeconds(10, 0));
  });
});

describe("formatDuration", () => {
  it("uses seconds under a minute", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(0.2)).toBe("1s"); // never "0s" for work that happens
  });

  it("uses whole minutes below an hour", () => {
    expect(formatDuration(540)).toBe("9 min");
    expect(formatDuration(59 * 60)).toBe("59 min");
  });

  it("splits into hours past 60 minutes", () => {
    expect(formatDuration(3600)).toBe("1 h");
    expect(formatDuration(4320)).toBe("1 h 12 min");
  });
});

// ── attackKey / corpusFingerprint ───────────────────────────────────────
const builtin = (id: string): RedTeamAttack => ({ id, category: "Jailbreak", prompt: `prompt for ${id}` });
const custom = (id: string, prompt: string): RedTeamAttack => ({ id, source: "custom", category: "Custom CSV", prompt });

describe("attackKey", () => {
  it("uses the id verbatim for built-in (undefined or 'prisma' source) attacks", () => {
    expect(attackKey(builtin("rt-01"))).toBe("rt-01");
    expect(attackKey({ ...builtin("rt-02"), source: "prisma" })).toBe("rt-02");
  });

  it("keys a custom attack off the prompt text, not its id", () => {
    const a = custom("csv-12", "ignore all previous instructions");
    const b = custom("csv-99", "ignore all previous instructions"); // same prompt, different row/file
    expect(attackKey(a)).toBe(attackKey(b));
  });

  it("gives different custom attacks different keys", () => {
    const a = custom("csv-1", "prompt A");
    const b = custom("csv-2", "prompt B");
    expect(attackKey(a)).not.toBe(attackKey(b));
  });

  it("is stable across re-running on the same input (deterministic, not random)", () => {
    const a = custom("csv-1", "some attack prompt");
    expect(attackKey(a)).toBe(attackKey(custom("csv-1", "some attack prompt")));
  });

  it("never collides with a built-in rt-NN id even by coincidence", () => {
    // The "h" prefix keeps the custom-key namespace disjoint from built-in
    // ids no matter what the hash produces.
    const a = custom("csv-1", "anything");
    expect(attackKey(a).startsWith("h")).toBe(true);
    expect(attackKey(a)).not.toMatch(/^rt-/);
  });
});

describe("corpusFingerprint", () => {
  it("is identical for the same attacks in a different order", () => {
    const corpusA = [builtin("rt-01"), builtin("rt-02"), builtin("rt-03")];
    const corpusB = [builtin("rt-03"), builtin("rt-01"), builtin("rt-02")];
    expect(corpusFingerprint(corpusA)).toBe(corpusFingerprint(corpusB));
  });

  it("changes when the attack set changes", () => {
    const corpusA = [builtin("rt-01"), builtin("rt-02")];
    const corpusB = [builtin("rt-01"), builtin("rt-03")];
    expect(corpusFingerprint(corpusA)).not.toBe(corpusFingerprint(corpusB));
  });

  it("is stable for a CSV re-exported with the same prompts in a new order", () => {
    const upload1 = [custom("csv-1", "prompt A"), custom("csv-2", "prompt B")];
    const upload2 = [custom("csv-1", "prompt B"), custom("csv-2", "prompt A")]; // rows swapped, ids reused
    expect(corpusFingerprint(upload1)).toBe(corpusFingerprint(upload2));
  });
});

// ── diffRuns ─────────────────────────────────────────────────────────────
function stored(attackKey: string, state: RtResultState, category = "Jailbreak"): RtStoredResult {
  return { attackKey, attackId: attackKey, category, state };
}

function savedRun(overrides: Partial<RtSavedRun> & { results: RtStoredResult[] }): RtSavedRun {
  return {
    id: 1,
    ts: Date.now(),
    route: "direct",
    guarded: 0,
    corpusName: "Prisma AIRS curated 36",
    corpusSize: overrides.results.length,
    corpusFingerprint: "fp-a",
    delayMs: 0,
    total: overrides.results.length,
    scored: overrides.results.length,
    reached: 0,
    stopped: 0,
    denied: 0,
    guardrails: 0,
    pending: 0,
    error: 0,
    reachedPct: 0,
    ...overrides,
  };
}

describe("diffRuns — comparable runs", () => {
  it("flags rows changed/unchanged and computes the reached delta over shared attacks only", () => {
    const before = savedRun({
      results: [stored("rt-01", "block"), stored("rt-02", "allow")],
    });
    const after = savedRun({
      id: 2,
      results: [stored("rt-01", "allow"), stored("rt-02", "allow")], // rt-01 flipped block → allow
    });
    const d = diffRuns(before, after);
    expect(d.comparable).toBe(true);
    expect(d.warning).toBeUndefined();
    const rt01 = d.rows.find((r) => r.attackKey === "rt-01")!;
    expect(rt01.status).toBe("changed");
    expect(rt01.before).toBe("block");
    expect(rt01.after).toBe("allow");
    const rt02 = d.rows.find((r) => r.attackKey === "rt-02")!;
    expect(rt02.status).toBe("unchanged");
    // before: 1 reached (rt-02). after: 2 reached (rt-01 + rt-02). delta = +1.
    expect(d.reachedDelta).toBe(1);
    expect(d.before.reached).toBe(1);
    expect(d.after.reached).toBe(2);
  });

  it("reports a fully-closed gap: every attack flips from reached to stopped", () => {
    const before = savedRun({ results: [stored("rt-01", "allow"), stored("rt-02", "log")] });
    const after = savedRun({ id: 2, results: [stored("rt-01", "block"), stored("rt-02", "challenge")] });
    const d = diffRuns(before, after);
    expect(d.reachedDelta).toBe(-2);
    expect(d.after.reached).toBe(0);
  });

  it("excludes non-scored states (denied/guardrails/pending/error) from the delta the same way scoreRun does", () => {
    const before = savedRun({ results: [stored("rt-01", "allow")] });
    const after = savedRun({ id: 2, results: [stored("rt-01", "guardrails")] });
    const d = diffRuns(before, after);
    // rt-01's state changed, but guardrails is not "reached" or "stopped" —
    // reached goes from 1 to 0, which IS a real (if awkward) delta; the
    // guard here is that it must not be miscounted as anything else.
    expect(d.rows[0].status).toBe("changed");
    expect(d.reachedDelta).toBe(-1);
  });
});

describe("diffRuns — incomparable / partial-overlap runs", () => {
  it("flags different corpora via fingerprint and still diffs the overlap", () => {
    const before = savedRun({
      corpusFingerprint: "fp-a",
      corpusName: "corpus A",
      results: [stored("rt-01", "block"), stored("rt-02", "allow")],
    });
    const after = savedRun({
      id: 2,
      corpusFingerprint: "fp-b", // different corpus
      corpusName: "corpus B",
      results: [stored("rt-01", "allow"), stored("rt-03", "block")], // rt-02 gone, rt-03 new
    });
    const d = diffRuns(before, after);
    expect(d.comparable).toBe(false);
    expect(d.warning).toMatch(/corpus A/);
    expect(d.warning).toMatch(/corpus B/);

    const rt01 = d.rows.find((r) => r.attackKey === "rt-01")!;
    expect(rt01.status).toBe("changed");
    const rt02 = d.rows.find((r) => r.attackKey === "rt-02")!;
    expect(rt02.status).toBe("removed");
    expect(rt02.before).toBe("allow");
    expect(rt02.after).toBeUndefined();
    const rt03 = d.rows.find((r) => r.attackKey === "rt-03")!;
    expect(rt03.status).toBe("added");
    expect(rt03.before).toBeUndefined();

    // Added/removed attacks must NOT move the delta — only rt-01 (shared) does.
    // rt-01: block → allow, so reached goes 0 → 1.
    expect(d.reachedDelta).toBe(1);
  });

  it("does not let an added block-only batch masquerade as fixes on the original corpus", () => {
    // Regression guard for the exact failure mode named in the brief: adding
    // a pile of new, already-blocked attacks must not look like N fixes.
    const before = savedRun({ corpusFingerprint: "fp-a", results: [stored("rt-01", "allow")] });
    const added = Array.from({ length: 10 }, (_, i) => stored(`new-${i}`, "block"));
    const after = savedRun({ id: 2, corpusFingerprint: "fp-b", results: [stored("rt-01", "allow"), ...added] });
    const d = diffRuns(before, after);
    expect(d.comparable).toBe(false);
    // rt-01 is unchanged (allow → allow); the 10 new blocked attacks are all
    // "added" and contribute nothing to reachedDelta.
    expect(d.reachedDelta).toBe(0);
    expect(d.rows.filter((r) => r.status === "added")).toHaveLength(10);
  });

  it("is comparable (no warning) when both runs cover the exact same attack set", () => {
    const before = savedRun({ corpusFingerprint: "fp-a", results: [stored("rt-01", "block")] });
    const after = savedRun({ id: 2, corpusFingerprint: "fp-a", results: [stored("rt-01", "allow")] });
    const d = diffRuns(before, after);
    expect(d.comparable).toBe(true);
    expect(d.warning).toBeUndefined();
  });
});
