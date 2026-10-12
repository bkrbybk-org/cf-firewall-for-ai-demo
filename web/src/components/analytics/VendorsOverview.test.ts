// The All-vendors comparison (vendor-agnostic Analytics, 2026-10-12): a cell the vendor's data cannot answer is "—"
// with a reason, never 0; the marks travel; a vendor with no checks says so.
import { describe, expect, it } from "vitest";
import type { Analytics, GatewayAnalytics, GuardrailAnalytics, GuardrailVendorStats } from "../../lib/types";
import { edgeRow, gatewayRow, guardrailRow } from "./VendorsOverview";

const v = (over: Partial<GuardrailVendorStats>): GuardrailVendorStats => ({
  provider: "lakera-guard", dir: "prompt", checked: 0, block: 0, allow: 0, alerts: 0, redaction: 0, incomplete: 0,
  error: 0, failedOpen: 0, notRun: 0, decided: 0, latencyN: 0, p50Ms: null, p95Ms: null, topDetections: [], lastTs: null,
  ...over,
});
const g = (vendors: GuardrailVendorStats[], over: Partial<GuardrailAnalytics> = {}): GuardrailAnalytics => ({
  configured: true, rangeHours: 24, since: "", until: "", source: "chat", rowsRead: 1, rowsDropped: 0, capped: false, sampled: false,
  totals: { turns: 0, verdicts: 0, block: 0, alerts: 0, error: 0, failedOpen: 0 }, vendors, bucket: "hour", series: [],
  disagreements: { count: 0, latest: [] }, provider: null, ...over,
});

describe("edgeRow", () => {
  it("blocks and logs from the AI Security rules' own tally; no checks, no outage, no latency — each '—' with why", () => {
    const r = edgeRow({
      configured: true,
      aiSecurity: { blocked: 3, logged: 31, other: 0, rules: [], classifiedBy: "expression", sampled: true, capped: false, zoneBlocked: 900 },
    } as unknown as Analytics);
    expect(r.blocks.v).toBe("≈3"); // never the zone-wide 900
    expect(r.flagged.v).toBe("≈31");
    for (const c of [r.checks, r.noVerdict, r.latency]) {
      expect(c.v).toBe("—");
      expect(c.why).toBeTruthy();
    }
  });
  it("unconfigured or failed: every cell '—', never 0", () => {
    for (const d of [null, { configured: false }, { configured: true, error: "x" }] as (Analytics | null)[]) {
      expect([edgeRow(d).blocks.v, edgeRow(d).flagged.v]).toEqual(["—", "—"]);
    }
  });
});

describe("gatewayRow", () => {
  it("counts model calls; Guardrails' verdicts are not in its logs; no 'p50 0 ms' without calls", () => {
    const busy = gatewayRow({ configured: true, gatewayId: "gw", requests: 12, errors: 1, p50Ms: 840, truncated: true } as GatewayAnalytics);
    expect(busy.checks.v).toBe("≥12");
    expect(busy.blocks.v).toBe("—");
    expect(busy.note).toContain("p50 840 ms model latency");
    const idle = gatewayRow({ configured: true, gatewayId: "gw", requests: 0, p50Ms: 0 } as GatewayAnalytics);
    expect(idle.note).toBe("no model call through gateway gw in the window");
  });
});

describe("guardrailRow", () => {
  it("that vendor's prompt checks, with replies in the note and the sampled mark", () => {
    const r = guardrailRow(
      "lakera-guard",
      g([v({ checked: 10, block: 4, alerts: 2, error: 1, failedOpen: 1, p50Ms: 90, latencyN: 9 }), v({ dir: "reply", checked: 5, block: 2 })], { sampled: true }),
    );
    expect([r.checks.v, r.blocks.v, r.flagged.v, r.noVerdict.v, r.latency.v]).toEqual(["≈10", "≈4", "≈2", "≈2", "90 ms"]);
    expect(r.note).toBe("replies: ≈5 checked · ≈2 withheld");
  });
  it("a vendor with no checks reads 0 checked and '—' elsewhere, with the reason", () => {
    const r = guardrailRow("datadog-ai-guard", g([v({ checked: 3 })]));
    expect(r.checks).toMatchObject({ v: "0" });
    expect([r.blocks.v, r.latency.v]).toEqual(["—", "—"]);
    expect(r.blocks.why).toMatch(/no prompt checked/);
  });
});
