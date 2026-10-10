import { describe, expect, it } from "vitest";
import { ago, healthText, vendorHealth } from "./vendorHealth";
import type { GuardrailAnalytics, GuardrailVendorStats } from "./types";

const NOW = Date.parse("2026-10-10T12:00:00Z");

function v(over: Partial<GuardrailVendorStats>): GuardrailVendorStats {
  return {
    provider: "prisma-airs", dir: "prompt", checked: 0, block: 0, allow: 0, alerts: 0, redaction: 0, incomplete: 0,
    error: 0, failedOpen: 0, notRun: 0, decided: 0, latencyN: 0, p50Ms: null, p95Ms: null, topDetections: [], lastTs: null,
    ...over,
  };
}
function data(vendors: GuardrailVendorStats[], over: Partial<GuardrailAnalytics> = {}): GuardrailAnalytics {
  return {
    configured: true, rangeHours: 24, since: "", until: "", source: "all", rowsRead: 0, rowsDropped: 0, capped: false, sampled: false,
    totals: { turns: 0, verdicts: 0, block: 0, alerts: 0, error: 0, failedOpen: 0 }, vendors, bucket: "hour", series: [],
    disagreements: { count: 0, latest: [] }, ...over,
  };
}

describe("vendorHealth", () => {
  it("merges the prompt and reply rows; a block is an answer, not a fault", () => {
    const h = vendorHealth(
      "prisma-airs",
      data([
        v({ dir: "prompt", checked: 30, block: 10, allow: 20, lastTs: NOW - 120_000 }),
        v({ dir: "reply", checked: 10, allow: 10, lastTs: NOW - 60_000 }),
        v({ provider: "lakera-guard", checked: 5, error: 5, lastTs: NOW }),
      ]),
    );
    expect(h).toMatchObject({ state: "ok", checked: 40, noVerdict: 0, lastTs: NOW - 60_000 });
    expect(healthText(h, NOW)).toBe("Last checked 1 min ago · last 24h: 40 checks, every one answered");
  });

  it("degraded when any check got no verdict, with the split and the rate", () => {
    const h = vendorHealth("cato-ai-security", data([v({ provider: "cato-ai-security", checked: 40, allow: 37, error: 2, failedOpen: 1, lastTs: NOW - 7_200_000 })]));
    expect(h).toMatchObject({ state: "degraded", noVerdict: 3, error: 2, failedOpen: 1 });
    expect(healthText(h, NOW)).toBe("Last checked 2 h ago · last 24h: 3 of 40 checks got no verdict (8%: 2 fail closed, 1 fail open)");
  });

  it("idle — never '0% errors' — when the vendor ran no check, even if it was listed as not run", () => {
    const h = vendorHealth("cisco-ai-defense", data([v({ provider: "cisco-ai-defense", dir: "reply", notRun: 12 })]));
    expect(h.state).toBe("idle");
    expect(healthText(h, NOW)).toBe("No checks in the last 24h");
    expect(vendorHealth("datadog-ai-guard", data([])).state).toBe("idle");
  });

  it("unknown — never healthy — when the data could not be read", () => {
    for (const d of [null, undefined, { configured: false } as GuardrailAnalytics, data([], { error: "Analytics Engine returned HTTP 502" })]) {
      expect(vendorHealth("prisma-airs", d).state).toBe("unknown");
    }
    expect(healthText(vendorHealth("prisma-airs", null), NOW)).toBe("Health unknown — the verdict data could not be read");
  });

  it("marks counts ≈ when the window was sampled", () => {
    const h = vendorHealth("prisma-airs", data([v({ checked: 4, error: 2, lastTs: NOW })], { sampled: true }));
    expect(healthText(h, NOW)).toContain("≈2 of ≈4 checks");
  });
});

describe("ago", () => {
  it("rounds to the unit a person reads", () => {
    expect(ago(NOW - 20_000, NOW)).toBe("just now");
    expect(ago(NOW - 5 * 60_000, NOW)).toBe("5 min ago");
    expect(ago(NOW - 3 * 3_600_000, NOW)).toBe("3 h ago");
    expect(ago(NOW - 3 * 86_400_000, NOW)).toBe("3 d ago");
  });
});
