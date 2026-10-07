import { describe, expect, it } from "vitest";
import { fmtMs, stageLatency, vendorLatency } from "./vendorLatency";
import type { RtRunResult, RtVendorOutcome } from "./redteam";

const AIRS = "prisma-airs";
const r = (
  id: string,
  vendors: [RtVendorOutcome["verdict"], number | undefined][],
  stage?: number,
  mode: "parallel" | "sequential" = "parallel",
): RtRunResult => ({
  id,
  state: "allow",
  vendors: vendors.map(([verdict, latencyMs]) => ({ provider: AIRS, verdict, ...(latencyMs != null ? { latencyMs } : {}) })),
  pipelineMode: mode,
  ...(stage != null ? { pipelineLatencyMs: stage } : {}),
});

describe("vendorLatency", () => {
  it("nearest-rank p50/p95 over verdicts only", () => {
    const s = vendorLatency([r("a", [["block", 300]]), r("b", [["allow", 100]]), r("c", [["alerts", 200]])], AIRS);
    expect(s).toMatchObject({ n: 3, p50: 200, p95: 300, max: 300, errorsExcluded: 0 });
  });

  it("an error's time is excluded — a timeout measures our cap, not the vendor — but counted", () => {
    const s = vendorLatency([r("a", [["allow", 120]]), r("b", [["error", 5000]])], AIRS);
    expect(s).toMatchObject({ n: 1, p50: 120, p95: 120, errorsExcluded: 1 });
  });

  it("notRun and untimed verdicts never become 0 ms", () => {
    const s = vendorLatency([r("a", [["notRun", undefined]]), r("b", [["block", undefined]])], AIRS);
    expect(s).toMatchObject({ n: 0, p50: null, p95: null, untimed: 1 });
  });
});

describe("stageLatency", () => {
  it("splits by mode, and drops stages where a guardrail errored", () => {
    const st = stageLatency([
      r("a", [["allow", 100]], 110),
      r("b", [["error", 5000]], 5010),
      r("c", [["block", 200]], 450, "sequential"),
    ]);
    expect(st.map((s) => [s.mode, s.stat.n, s.stat.p50, s.stat.errorsExcluded])).toEqual([
      ["parallel", 1, 110, 1],
      ["sequential", 1, 450, 0],
    ]);
  });

  it("a run with no pipeline has no stage at all", () => {
    expect(stageLatency([{ id: "x", state: "block" }])).toEqual([]);
  });
});

describe("fmtMs", () => {
  it("ms under a second, seconds above, dash for none", () => {
    expect([fmtMs(842.4), fmtMs(1234), fmtMs(12_345), fmtMs(null)]).toEqual(["842 ms", "1.2 s", "12 s", "—"]);
  });
});
