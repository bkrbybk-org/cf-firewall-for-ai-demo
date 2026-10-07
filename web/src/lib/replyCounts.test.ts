import { describe, expect, it } from "vitest";
import { replyCounts } from "./replyCounts";
import type { RedTeamAttack, RtRunResult, RtVendorOutcome } from "./redteam";

const A = (id: string, harmless = false): RedTeamAttack => ({ id, category: "c", prompt: id, ...(harmless ? { expected: "allow" as const } : {}) });
const res = (id: string, reply?: [string, RtVendorOutcome["verdict"]][]): [string, RtRunResult] => [
  id,
  { id, state: "allow", ...(reply ? { replyVendors: reply.map(([provider, verdict]) => ({ provider, verdict })), replyPipelineMode: "parallel" as const } : {}) },
];

describe("replyCounts (design J, counts only)", () => {
  const corpus = [A("a1"), A("a2"), A("a3"), A("a4"), A("h1", true), A("h2", true)];
  const results = new Map<string, RtRunResult>([
    res("a1", [["prisma-airs", "block"], ["crowdstrike-aidr", "allow"]]),
    res("a2", [["prisma-airs", "allow"], ["crowdstrike-aidr", "error"]]),
    res("a3", [["prisma-airs", "allow"], ["cato-ai-security", "notRun"]]),
    res("a4"), // reply not checked (e.g. guardrail-only, or the switch was off)
    res("h1", [["prisma-airs", "block"], ["crowdstrike-aidr", "alerts"]]),
    res("h2", [["prisma-airs", "allow"], ["crowdstrike-aidr", "allow"]]),
  ]);
  const c = replyCounts(corpus, results, { "prisma-airs": "Prisma AIRS" });
  const by = (side: typeof c.attacks, p: string) => side.byControl.find((x) => x.control === p)!;

  it("counts each guardrail only on the replies it gave a verdict on", () => {
    expect(c.attacks.rows).toBe(3);
    expect(by(c.attacks, "prisma-airs")).toMatchObject({ label: "Prisma AIRS", checked: 3, blocked: 1, passed: 2, errors: 0, notChecked: 0 });
    // AIDR: a1 allow, a2 error (not a verdict), a3 never in its pipeline → not checked.
    expect(by(c.attacks, "crowdstrike-aidr")).toMatchObject({ checked: 1, passed: 1, errors: 1, notChecked: 1 });
    // A guardrail that cannot check replies is "not checked", never a pass.
    expect(by(c.attacks, "cato-ai-security")).toMatchObject({ checked: 0, passed: 0, notChecked: 3 });
  });

  it("keeps harmless rows apart, with alerts not counted as blocks", () => {
    expect(c.harmless).toMatchObject({ rows: 2, withheld: 1 });
    expect(by(c.harmless, "crowdstrike-aidr")).toMatchObject({ checked: 2, alerts: 1, blocked: 0, passed: 1 });
  });

  it("states the prompts whose reply was not checked, outside every count", () => {
    expect(c.notCheckedRows).toBe(1);
    expect(c.attacks.withheld).toBe(1);
  });

  it("no reply checked anywhere → no providers, all rows not checked", () => {
    const none = replyCounts(corpus, new Map([res("a1"), res("h1")]));
    expect(none.providers).toEqual([]);
    expect(none.notCheckedRows).toBe(2);
  });
});
