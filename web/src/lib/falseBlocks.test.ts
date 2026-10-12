import { describe, expect, it } from "vitest";
import { labelledRows, MIN_FOR_RATE } from "./falseBlocks";
import type { GuardrailVendorStats } from "./types";

const v = (over: Partial<GuardrailVendorStats>): GuardrailVendorStats => ({
  provider: "lakera-guard",
  dir: "prompt",
  checked: 0,
  block: 0,
  allow: 0,
  alerts: 0,
  redaction: 0,
  incomplete: 0,
  error: 0,
  failedOpen: 0,
  notRun: 0,
  decided: 0,
  latencyN: 0,
  p50Ms: null,
  p95Ms: null,
  topDetections: [],
  lastTs: null,
  ...over,
});

describe("labelledRows", () => {
  it("rates false blocks over harmless VERDICTS and catches over attack verdicts, rounded", () => {
    const [row] = labelledRows([
      v({ labelled: { benign: { verdicts: 12, block: 3 }, attack: { verdicts: 20, block: 17 } } }),
    ]);
    expect(row.falseBlocks).toEqual({ verdicts: 12, block: 3, rate: "25 %", small: false });
    expect(row.catches).toEqual({ verdicts: 20, block: 17, rate: "85 %", small: false });
  });

  it("no verdicts is '—', never 0 %; a small sample is flagged", () => {
    const [row] = labelledRows([v({ labelled: { benign: { verdicts: 2, block: 1 }, attack: { verdicts: 0, block: 0 } } })]);
    expect(row.catches.rate).toBe("—");
    expect(row.catches.small).toBe(false);
    expect(row.falseBlocks).toMatchObject({ rate: "50 %", small: true });
    expect(MIN_FOR_RATE).toBe(10);
  });

  it("leaves out vendors with nothing labelled, and an older Worker with no `labelled` at all", () => {
    expect(labelledRows([v({}), v({ labelled: { benign: { verdicts: 0, block: 0 }, attack: { verdicts: 0, block: 0 } } })])).toEqual([]);
  });
});
