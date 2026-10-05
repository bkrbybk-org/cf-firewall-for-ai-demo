// Tests for the nearest-rank percentile rule (PROGRESS bug #24).
//
// "The query runs" is not the bar — the old one ran for a month while ranking
// with truncation. These pin the rank rule against its definition, against the
// real local rows that exposed the bug, and against the handler's SQL so the
// truncating form cannot quietly come back.
import { describe, expect, it } from "vitest";
import handlersSrc from "./handlers.ts?raw";
import { nearestRank, nearestRankSql } from "./percentile";

// The definition, in floating point — what the integer form must equal.
const ceilRank = (n: number, pct: number) => Math.ceil((n * pct) / 100);

const pick = (sorted: number[], pct: number) => sorted[nearestRank(sorted.length, pct) - 1];

describe("nearestRank", () => {
  it("equals ⌈n·pct/100⌉ for every n up to 1000 at the percentiles we use", () => {
    for (const pct of [1, 50, 90, 95, 99, 100]) {
      for (let n = 1; n <= 1000; n++) expect(nearestRank(n, pct), `n=${n} pct=${pct}`).toBe(ceilRank(n, pct));
    }
  });

  it("is never below rank 1 or above n", () => {
    for (let n = 1; n <= 200; n++) {
      for (const pct of [1, 50, 95, 100]) {
        const r = nearestRank(n, pct);
        expect(r).toBeGreaterThanOrEqual(1);
        expect(r).toBeLessThanOrEqual(n);
      }
    }
  });

  // The real local prompt-log rows (2026-10-05), sorted per (route, guarded,
  // streamed), with the values a hand calculation gives. The old truncating SQL
  // returned the "was" values on these same rows.
  it.each([
    { rows: [77, 115, 800, 900, 1200, 1313, 2500], p50: 900, p95: 2500, was: [800, 1313] },
    { rows: [150, 180, 400], p50: 180, p95: 400, was: [150, 180] },
    { rows: [1100, 1300, 3000], p50: 1300, p95: 3000, was: [1100, 1300] },
    { rows: [220, 260], p50: 220, p95: 260, was: [220, 220] },
    { rows: [90, 1400, 1600, 5000], p50: 1400, p95: 5000, was: [1400, 1600] },
    { rows: [300], p50: 300, p95: 300, was: [300, 300] },
  ])("picks p50=$p50 p95=$p95 from $rows", ({ rows, p50, p95 }) => {
    expect(pick(rows, 50)).toBe(p50);
    expect(pick(rows, 95)).toBe(p95);
  });

  it("rejects inputs that are not a rank question", () => {
    expect(() => nearestRank(0, 50)).toThrow();
    expect(() => nearestRank(2.5, 50)).toThrow();
    expect(() => nearestRank(10, 0)).toThrow();
    expect(() => nearestRank(10, 95.5)).toThrow();
  });
});

describe("nearestRankSql", () => {
  it("is the same integer ceiling, written for SQLite's integer division", () => {
    expect(nearestRankSql("n2", 95)).toBe("((n2 * 95 + 99) / 100)");
    // Evaluate the expression with integer division, as SQLite does for two integers.
    for (let n = 1; n <= 500; n++) {
      const sql = nearestRankSql("n", 95).replace(/n/g, String(n));
      const [, a, b] = sql.match(/\(\((\d+) \* (\d+) \+ 99\) \/ 100\)/)!;
      expect(Math.trunc((Number(a) * Number(b) + 99) / 100), `n=${n}`).toBe(nearestRank(n, 95));
    }
  });

  it("refuses anything but a column name and an integer percentile", () => {
    expect(() => nearestRankSql("n2; DROP TABLE x", 95)).toThrow();
    expect(() => nearestRankSql("n2", 9.5)).toThrow();
  });

  it("is what the prompt-analytics handler actually uses — no truncating rank left", () => {
    expect(handlersSrc).toContain('nearestRankSql("n2", 50)');
    expect(handlersSrc).toContain('nearestRankSql("n2", 95)');
    expect(handlersSrc).not.toMatch(/CAST\(n2\s*\*\s*0\.\d+ AS INTEGER\)/);
  });
});
