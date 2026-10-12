// The harmless Thai set (#16) and the scheduled re-run's copies of it (#15). The re-run's twelve prompts live in the
// Worker (src/scheduledCorpus.ts, data only) and must be EXACT copies of their sources here — a drift series built on
// a silently edited prompt would compare two different things.
import { describe, expect, it } from "vitest";
import { SCHEDULED_PROMPTS } from "../../../src/scheduledCorpus";
import { attackKey, isAttack, RT_CORPUS } from "./redteam";
import { RT_THAI_HARMLESS, THAI_HARMLESS_SOURCE } from "./thaiHarmless";

describe("RT_THAI_HARMLESS", () => {
  it("20 harmless rows: never attacks, unique ids, keyed by prompt, Thai script, one line, 20–160 characters", () => {
    expect(RT_THAI_HARMLESS).toHaveLength(20);
    expect(RT_THAI_HARMLESS.every((a) => !isAttack(a) && a.expected === "allow" && a.source === "dataset")).toBe(true);
    expect(new Set(RT_THAI_HARMLESS.map((a) => a.id)).size).toBe(20);
    expect(RT_THAI_HARMLESS.every((a) => attackKey(a).startsWith("h"))).toBe(true);
    for (const a of RT_THAI_HARMLESS) {
      expect(a.prompt, a.id).toMatch(/[฀-๿]/);
      expect(a.prompt, a.id).not.toMatch(/\n/);
      expect(a.prompt.length, a.id).toBeGreaterThanOrEqual(20);
      expect(a.prompt.length, a.id).toBeLessThanOrEqual(160);
    }
    expect(THAI_HARMLESS_SOURCE).toMatchObject({ dataset: "pythainlp/han-instruct-dataset-v4.0", license: "CC BY-SA 4.0" });
  });
});

describe("SCHEDULED_PROMPTS", () => {
  it("is the first six built-in attacks and six of the harmless Thai set, verbatim", () => {
    expect(SCHEDULED_PROMPTS).toHaveLength(12);
    const attacks = SCHEDULED_PROMPTS.filter((p) => p.expect === "attack");
    expect(attacks.map((p) => p.id)).toEqual(["rt-01", "rt-02", "rt-03", "rt-04", "rt-05", "rt-06"]);
    for (const p of attacks) expect(p.prompt, p.id).toBe(RT_CORPUS.find((a) => a.id === p.id)!.prompt);
    const harmless = SCHEDULED_PROMPTS.filter((p) => p.expect === "benign");
    expect(harmless).toHaveLength(6);
    const set = new Set(RT_THAI_HARMLESS.map((a) => a.prompt));
    for (const p of harmless) expect(set.has(p.prompt), p.id).toBe(true);
  });
});
