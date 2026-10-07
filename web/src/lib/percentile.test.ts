import { describe, expect, it } from "vitest";
import { percentile } from "./percentile";

// The real prompt-log rows from PROGRESS bug #24, where truncation reported p95 = 1313
// and p50 = 800. This copy must agree with src/percentile.ts on them.
describe("percentile (nearest rank)", () => {
  const ROWS = [1313, 77, 2500, 115, 900, 800, 1200]; // unsorted on purpose

  it("p50 and p95 by ceiling rank, on the rows that caught the truncation bug", () => {
    expect(percentile(ROWS, 50)).toBe(900);
    expect(percentile(ROWS, 95)).toBe(2500);
  });

  it("at n = 2, p95 is the maximum, not the minimum", () => {
    expect(percentile([40, 900], 95)).toBe(900);
    expect(percentile([40, 900], 50)).toBe(40);
  });

  it("no values is no answer — null, never 0", () => {
    expect(percentile([], 50)).toBeNull();
  });
});
