import { describe, expect, it } from "vitest";
import { fmtInterval, wilson } from "./stats";

describe("wilson (95%)", () => {
  it("matches the published Wilson values", () => {
    // 3/3: 43.85–100; 0/3: 0–56.15; 5/10: 23.66–76.34 (standard tables, z = 1.96).
    const a = wilson(3, 3)!;
    expect(a.lo).toBeCloseTo(43.85, 1);
    expect(a.hi).toBe(100);
    const b = wilson(0, 3)!;
    expect(b.lo).toBe(0);
    expect(b.hi).toBeCloseTo(56.15, 1);
    const c = wilson(5, 10)!;
    expect(c.lo).toBeCloseTo(23.66, 1);
    expect(c.hi).toBeCloseTo(76.34, 1);
  });

  it("a perfect score is never a zero-width certainty", () => {
    expect(wilson(3, 3)!.lo).toBeLessThan(50);
  });

  it("no sample, or an impossible one, has no interval", () => {
    expect(wilson(0, 0)).toBeNull();
    expect(wilson(4, 3)).toBeNull();
  });

  it("prints rounded outward", () => {
    expect(fmtInterval(wilson(5, 10))).toBe("23–77%");
    expect(fmtInterval(null)).toBe("—");
  });
});
