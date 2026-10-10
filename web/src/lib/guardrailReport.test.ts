import { describe, expect, it } from "vitest";
import { GUARDRAIL_REPORT_SCHEMA, buildGuardrailReport, guardrailReportFilename, guardrailReportToMarkdown } from "./guardrailReport";
import type { GuardrailAnalytics, GuardrailVendorStats } from "./types";

const NOW = new Date("2026-10-10T12:00:00Z");
const label = (p: string) => ({ "prisma-airs": "Prisma AIRS", "lakera-guard": "Lakera Guard" } as Record<string, string>)[p] ?? p;

function v(over: Partial<GuardrailVendorStats>): GuardrailVendorStats {
  return {
    provider: "prisma-airs", dir: "prompt", checked: 0, block: 0, allow: 0, alerts: 0, redaction: 0, incomplete: 0,
    error: 0, failedOpen: 0, notRun: 0, decided: 0, latencyN: 0, p50Ms: null, p95Ms: null, topDetections: [], lastTs: null,
    ...over,
  };
}
function data(over: Partial<GuardrailAnalytics> = {}): GuardrailAnalytics {
  return {
    configured: true, rangeHours: 24, since: "2026-10-09T12:00:00.000Z", until: "2026-10-10T12:00:00.000Z", source: "chat",
    rowsRead: 12, rowsDropped: 0, capped: false, sampled: false,
    totals: { turns: 3, verdicts: 12, block: 2, alerts: 1, error: 1, failedOpen: 0 },
    vendors: [
      v({ checked: 3, block: 1, allow: 2, latencyN: 3, p50Ms: 300, p95Ms: 5000, topDetections: [{ name: "injection", count: 1 }] }),
      v({ provider: "lakera-guard", dir: "reply", checked: 0, notRun: 2 }),
    ],
    bucket: "hour",
    series: [],
    disagreements: {
      count: 1,
      latest: [{ ts: Date.parse("2026-10-10T10:15:00Z"), ray: "aaa", dir: "prompt", verdicts: [{ provider: "prisma-airs", outcome: "block", alerts: false }, { provider: "lakera-guard", outcome: "allow", alerts: true }] }],
    },
    ...over,
  };
}

describe("buildGuardrailReport", () => {
  it("carries the window, traffic and quality flags with the numbers, and labels vendors", () => {
    const r = buildGuardrailReport(data(), label, NOW);
    expect(r).toMatchObject({
      schema: GUARDRAIL_REPORT_SCHEMA,
      generatedAt: "2026-10-10T12:00:00.000Z",
      window: { hours: 24, traffic: "chat", since: "2026-10-09T12:00:00.000Z" },
      quality: { sampled: false, capped: false, rowsRead: 12, rowsDropped: 0 },
      totals: { verdicts: 12, block: 2 },
    });
    expect(r.vendors[0]).toMatchObject({ provider: "prisma-airs", label: "Prisma AIRS", p50Ms: 300 });
    expect(r.disagreements.latest[0]).toEqual({
      at: "2026-10-10T10:15:00.000Z",
      ray: "aaa",
      check: "prompt",
      verdicts: [
        { vendor: "Prisma AIRS", outcome: "block", alerts: false },
        { vendor: "Lakera Guard", outcome: "allow", alerts: true },
      ],
    });
  });
});

describe("guardrailReportToMarkdown", () => {
  it("states window and traffic, uses — for unmeasured latency, and lists the disagreement", () => {
    const md = guardrailReportToMarkdown(buildGuardrailReport(data(), label, NOW), (n) => (n === "injection" ? "Prompt injection" : n));
    expect(md).toContain("# External guardrail verdicts — last 24h");
    expect(md).toContain("- **Traffic:** chat traffic (Red Team runs excluded)");
    expect(md).toContain("| Prisma AIRS | prompt | 3 | 1 | 2 | 0 | 0 (0 / 0) | 0 |");
    expect(md).toContain("300 ms / 5000 ms (n=3)");
    expect(md).toContain("| Lakera Guard | reply | 0 | 0 | 0 | 0 | 0 (0 / 0) | 2 | — / — | — |");
    expect(md).toContain("Prompt injection 1");
    expect(md).toContain("Prisma AIRS: block; Lakera Guard: allow (alerts)");
    expect(md).not.toMatch(/Estimated|A floor/);
  });

  it("carries ≈ and the Estimated note when sampled, ≥ and the floor note when capped", () => {
    const sampled = guardrailReportToMarkdown(buildGuardrailReport(data({ sampled: true }), label, NOW));
    expect(sampled).toContain("> **Estimated.**");
    expect(sampled).toContain("- **Blocks:** ≈2");
    const capped = guardrailReportToMarkdown(buildGuardrailReport(data({ capped: true, rowsRead: 10000 }), label, NOW));
    expect(capped).toContain("> **A floor, not a total.** The read stopped at 10,000 rows");
    expect(capped).toContain("- **Blocks:** ≥2");
  });

  it("a hostile detector name cannot break the table or open a link", () => {
    const d = data({ vendors: [v({ checked: 1, block: 1, topDetections: [{ name: "x|y](https://evil.example)", count: 1 }] })] });
    const md = guardrailReportToMarkdown(buildGuardrailReport(d, label, NOW));
    const row = md.split("\n").find((l) => l.startsWith("| Prisma AIRS"))!;
    expect(row).toContain("x\\|y\\]\\(https\\://evil.example\\)");
    expect(row.split(/(?<!\\)\|/).length).toBe(12); // 10 cells + the two outer pipes
    // A vendor label is escaped too: a server newer than this bundle may send a provider id it shows as-is.
    const odd = guardrailReportToMarkdown(buildGuardrailReport(d, () => "Odd|Vendor", NOW));
    expect(odd).toContain("| Odd\\|Vendor | prompt |");
  });

  it("says so when nothing was checked", () => {
    const md = guardrailReportToMarkdown(buildGuardrailReport(data({ vendors: [], disagreements: { count: 0, latest: [] } }), label, NOW));
    expect(md).toContain("No external guardrail checked anything in this window.");
    expect(md).toContain("0 turn(s) where one vendor blocked");
  });
});

describe("guardrailReportFilename", () => {
  it("names window, traffic and time", () => {
    expect(guardrailReportFilename(buildGuardrailReport(data(), label, NOW), "md")).toBe("guardrail-verdicts-24h-chat-20261010-1200.md");
  });
});
