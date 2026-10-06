import { describe, expect, it } from "vitest";
import { balancedAccuracy, countBlockedByAny, falseBlockScores, toVendorOutcomes, vendorScorecard } from "./vendorScorecard";
import type { RtRunResult, RtVendorOutcome } from "./redteam";

const AIRS = "prisma-airs";
const AIDR = "crowdstrike-aidr";
const r = (id: string, state: RtRunResult["state"], vendors?: [string, RtVendorOutcome["verdict"]][], mode: "parallel" | "sequential" = "parallel"): RtRunResult => ({
  id,
  state,
  ...(vendors ? { vendors: vendors.map(([provider, verdict]) => ({ provider, verdict })), pipelineMode: mode } : {}),
});
const ctl = (card: ReturnType<typeof vendorScorecard>, c: string) => card.controls.find((x) => x.control === c)!;

describe("vendorScorecard", () => {
  it("scores the edge on every verdict, and each guardrail only on what it scanned", () => {
    const card = vendorScorecard([
      r("a", "block"), // edge caught; never reached the guardrails
      r("b", "external", [[AIRS, "block"], [AIDR, "allow"]]),
      r("c", "allow", [[AIRS, "allow"], [AIDR, "allow"]]),
      r("d", "external", [[AIRS, "allow"], [AIDR, "block"]]),
    ]);
    expect(ctl(card, "edge")).toMatchObject({ caught: 1, missed: 3, scanned: 4, catchPct: 25 });
    // The edge-refused attack is NOT a miss for the guardrails — they never saw it.
    expect(ctl(card, AIRS)).toMatchObject({ caught: 1, missed: 2, scanned: 3, notSeen: 1, catchPct: 33 });
    expect(ctl(card, AIDR)).toMatchObject({ caught: 1, missed: 2, scanned: 3, notSeen: 1 });
    expect(card.missedByAll).toBe(1); // "c"
    expect(card.unevenCoverage).toBe(false);
  });

  it("only-this-control counts catches every other control that scanned it missed", () => {
    const card = vendorScorecard([
      r("b", "external", [[AIRS, "block"], [AIDR, "allow"]]),
      r("e", "external", [[AIRS, "block"], [AIDR, "block"]]),
      r("a", "block"), // edge alone saw it — no other control scanned it, so not "only this"
    ]);
    expect(ctl(card, AIRS).onlyThis).toBe(1);
    expect(ctl(card, AIDR).onlyThis).toBe(0);
    expect(ctl(card, "edge").onlyThis).toBe(0);
  });

  it("an error is never a miss, Detect-mode alerts are not catches, notRun stays out", () => {
    const card = vendorScorecard(
      [
        r("x", "external", [[AIDR, "block"], [AIRS, "notRun"]], "sequential"),
        r("y", "allow", [[AIDR, "error"], [AIRS, "alerts"]], "sequential"),
      ],
    );
    expect(ctl(card, AIRS)).toMatchObject({ caught: 0, missed: 0, alerts: 1, scanned: 1, notRun: 1, catchPct: 0 });
    expect(ctl(card, AIDR)).toMatchObject({ caught: 1, errors: 1, scanned: 1, catchPct: 100 });
    expect(card.unevenCoverage).toBe(true);
    expect(card.modes).toEqual(["sequential"]);
  });

  it("a control that scanned nothing has no rate — never 0%", () => {
    const card = vendorScorecard([r("a", "block"), r("p", "pending"), r("q", "external", [[AIRS, "error"]])]);
    expect(ctl(card, AIRS)).toMatchObject({ scanned: 0, catchPct: null, errors: 1, notSeen: 2 });
    expect(ctl(card, "edge")).toMatchObject({ caught: 1, missed: 1, errors: 1 }); // pending is excluded, not a miss
  });

  it("flags a guardrail that skipped prompts another one scanned", () => {
    const card = vendorScorecard([r("a", "allow", [[AIRS, "allow"], [AIDR, "allow"]]), r("b", "allow", [[AIRS, "allow"]])]);
    expect(card.unevenCoverage).toBe(true);
  });

  it("toVendorOutcomes: errors stay errors, Detect mode is alerts, notRun is kept", () => {
    expect(
      toVendorOutcomes({
        mode: "sequential",
        guardrailOnly: false,
        latencyMs: 1,
        stoppedBy: AIDR,
        results: [
          { provider: AIDR, outcome: "block", latencyMs: 1 },
          { provider: "lakera-guard", outcome: "allow", detectOnly: true, latencyMs: 1 },
          { provider: "cisco-ai-defense", outcome: "error", failedOpen: true, latencyMs: 1 },
        ],
        notRun: [{ provider: AIRS, reason: "earlier stop" }],
      }),
    ).toEqual([
      { provider: AIDR, verdict: "block" },
      { provider: "lakera-guard", verdict: "alerts" },
      { provider: "cisco-ai-defense", verdict: "error" },
      { provider: AIRS, verdict: "notRun" },
    ]);
    expect(toVendorOutcomes(undefined)).toBeUndefined();
  });

  it("false blocks: a harmless prompt blocked is the mistake; edge-refused is not seen by the guardrails", () => {
    const fb = falseBlockScores([
      r("h1", "block"), // edge false block — the guardrails never saw it
      r("h2", "external", [[AIRS, "block"], [AIDR, "allow"]]),
      r("h3", "allow", [[AIRS, "allow"], [AIDR, "alerts"]]), // an alert let it through: not a block
    ]);
    const f = (c: string) => fb.find((x) => x.control === c)!;
    expect(f("edge")).toMatchObject({ blocked: 1, passed: 2, checked: 3, falseBlockPct: 33 });
    expect(f(AIRS)).toMatchObject({ blocked: 1, passed: 1, checked: 2, notSeen: 1, falseBlockPct: 50 });
    expect(f(AIDR)).toMatchObject({ blocked: 0, alerts: 1, checked: 2, falseBlockPct: 0 });
    expect(countBlockedByAny([r("h1", "block"), r("h2", "external", [[AIRS, "block"]]), r("h3", "allow", [[AIRS, "allow"]])])).toBe(2);
  });

  it("balanced accuracy: blocking everything scores 50, not 100; half a score is no score", () => {
    const attack = vendorScorecard([r("a", "external", [[AIRS, "block"]]), r("b", "external", [[AIRS, "block"]])]);
    const blocksAll = falseBlockScores([r("h", "external", [[AIRS, "block"]])]);
    expect(balancedAccuracy(ctl(attack, AIRS), blocksAll.find((x) => x.control === AIRS))).toBe(50);
    const passesHarmless = falseBlockScores([r("h", "allow", [[AIRS, "allow"]])]);
    expect(balancedAccuracy(ctl(attack, AIRS), passesHarmless.find((x) => x.control === AIRS))).toBe(100);
    expect(balancedAccuracy(ctl(attack, AIRS), undefined)).toBeNull();
    const none = falseBlockScores([r("h", "block")], {}, [AIRS]); // edge refused it: AIRS checked nothing
    expect(balancedAccuracy(ctl(attack, AIRS), none.find((x) => x.control === AIRS))).toBeNull();
  });

  it("a fixed provider list keeps the attack and harmless columns aligned", () => {
    const card = vendorScorecard([r("a", "block")], {}, [AIRS]);
    expect(card.controls.map((c) => c.control)).toEqual(["edge", AIRS]);
    expect(ctl(card, AIRS).catchPct).toBeNull();
  });

  it("uses the labels given, and lists the edge first", () => {
    const card = vendorScorecard([r("a", "allow", [[AIRS, "allow"]])], { [AIRS]: "Prisma AIRS" });
    expect(card.controls.map((c) => c.label)).toEqual(["Edge WAF", "Prisma AIRS"]);
  });
});
