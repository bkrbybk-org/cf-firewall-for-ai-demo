import { describe, expect, it } from "vitest";
import { estRate, estValue } from "./edgeEstimate";

// The real 24h answer from the zone (2026-10-12): estimate 12,377, 95% CI 11,229.8–13,524.2 from 3,513 samples.
const TOTAL = { estimate: 12377, lower: 11229.843276528798, upper: 13524.156723471202, sampleSize: 3513 };

describe("edge estimates on a tile", () => {
  it("always reads as an estimate, never a count", () => {
    expect(estValue(TOTAL)).toBe("≈12,377");
    expect(estValue({ estimate: 0, lower: null, upper: null, sampleSize: null })).toBe("≈0");
  });
  it("shows the interval only when the server had one", () => {
    expect(estRate(TOTAL, 0.95)).toBe("95% CI 11,230–13,524 · estimated");
    expect(estRate({ estimate: 3166, lower: null, upper: null, sampleSize: null }, 0.95)).toBe("estimated (sampled data)");
    // Half an interval is not one.
    expect(estRate({ estimate: 10, lower: 4, upper: null, sampleSize: 3 }, 0.95)).toBe("estimated (sampled data)");
  });
});
