// Tests for the gap-controls generator.
//
// The score inversion is the highest-stakes case here: injection_score and
// custom-topic scores are LOW = attack, so a threshold is always `le`. Get
// this backwards and the generated rule either blocks everyone or blocks no
// one — see gapControls.ts's file header. These tests pin the `le` direction
// explicitly, separately for a block-shaped threshold and a log-shaped one,
// so a future edit can't silently flip the comparator for only one of them.
import { describe, expect, it } from "vitest";
import {
  computeGapControls,
  customTopicExpression,
  injectionExpression,
  piiExpression,
  unsafeTopicExpression,
  type GapControl,
} from "./gapControls";
import { RT_CORPUS, type RtResultState, type RtRunResult } from "./redteam";
import type { ZoneRulesState } from "../hooks/useZoneRules";

const r = (id: string, state: RtResultState): RtRunResult => ({ id, state });

const FALLBACK_STATE: ZoneRulesState = {
  source: "fallback",
  rules: [
    { name: "Block LLM Injection", action: "block", detail: "injection_score ≤ 15", enabled: true, llm: true },
    { name: "Monitor LLM Injection", action: "log", detail: "injection_score ≤ 50", enabled: true, llm: true },
    { name: "Block LLM PII Categories", action: "block", detail: "credit card / crypto / email / phone / IBAN", enabled: true, llm: true },
    { name: "Monitor LLM PII Categories", action: "log", detail: "+ IP address / …", enabled: true, llm: true },
    { name: "Block LLM Unsafe Categories", action: "block", detail: "unsafe topics S1–S5, S8–S12", enabled: true, llm: true },
    { name: "Monitor LLM Unsafe Categories", action: "log", detail: "unsafe topics S1–S14", enabled: true, llm: true },
    { name: "Monitor LLM Custom Topic - Sensitive Data", action: "log", detail: "custom topic score ≤ 50", enabled: true, llm: true },
    { name: "Monitor LLM Custom Topic - Financial Advice", action: "log", detail: "custom topic score ≤ 50", enabled: true, llm: true },
    { name: "Monitor LLM Custom Topics - Politics and Election", action: "block", detail: "custom topic score ≤ 40", enabled: true, llm: true },
    { name: "Monitor LLM Custom Topics - Telco Use Cases", action: "log", detail: "custom topic score ≤ 50", enabled: true, llm: true },
  ],
};

const EMPTY_LIVE_STATE: ZoneRulesState = { source: "live", rules: [] };

const LIVE_STATE_WITH_INJECTION: ZoneRulesState = {
  source: "live",
  rules: [
    {
      name: "Block LLM Injection",
      action: "block",
      detail: '(http.request.uri.path eq "/api/chat") and (cf.llm.prompt.injection_score le 15)',
      enabled: true,
      llm: true,
    },
  ],
};

// ── score inversion: expression builders ────────────────────────────────
describe("injectionExpression — score inversion", () => {
  it("uses `le`, never `ge`, for a strict block-shaped threshold", () => {
    const expr = injectionExpression(15);
    expect(expr).toContain("cf.llm.prompt.injection_score le 15");
    expect(expr).not.toContain("ge 15");
    expect(expr).not.toMatch(/injection_score\s+ge/);
  });

  it("uses `le`, never `ge`, for a looser log-shaped threshold", () => {
    // A "catch more for visibility" log rule still compares with `le` — only
    // the number goes up, the comparator does not change.
    const expr = injectionExpression(65);
    expect(expr).toContain("cf.llm.prompt.injection_score le 65");
    expect(expr).not.toMatch(/injection_score\s+ge/);
  });

  it("scopes to the /api/chat endpoint", () => {
    expect(injectionExpression(30)).toContain('http.request.uri.path eq "/api/chat"');
  });

  // custom_topic_categories is a Map<Number> keyed by the dashboard topic
  // label, scored 1–99 with the same inversion. It reaches a production zone
  // the same way injection_score does, so it gets the same scrutiny.
  describe("customTopicExpression", () => {
    it("indexes the map by label and compares with `le`, never `ge`", () => {
      const expr = customTopicExpression("Self-Criticism", 50);
      expect(expr).toContain('cf.llm.prompt.custom_topic_categories["Self-Criticism"] le 50');
      expect(expr).not.toMatch(/custom_topic_categories\[[^\]]*\]\s+ge/);
    });

    it("keeps the same comparator at a looser threshold", () => {
      expect(customTopicExpression("Politics", 80)).toContain('["Politics"] le 80');
    });

    it("rejects a threshold outside the field's real 1..99 range", () => {
      expect(() => customTopicExpression("Politics", 0)).toThrow();
      expect(() => customTopicExpression("Politics", 100)).toThrow();
      expect(() => customTopicExpression("Politics", 40.5)).toThrow();
    });

    // The label sits inside a quoted string literal. A `"` would close it
    // early and produce an expression that is either invalid or — far worse —
    // valid but matching something else entirely.
    it("rejects a label that would break out of the string literal", () => {
      expect(() => customTopicExpression('evil" or true or "', 50)).toThrow();
      expect(() => customTopicExpression("back\\slash", 50)).toThrow();
      expect(() => customTopicExpression("   ", 50)).toThrow();
    });
  });

  it("rejects a threshold outside the field's real 1..99 range", () => {
    expect(() => injectionExpression(0)).toThrow();
    expect(() => injectionExpression(100)).toThrow();
    expect(() => injectionExpression(1.5)).toThrow();
  });
});

describe("unsafeTopicExpression / piiExpression", () => {
  it("emits the confirmed boolean fields, not an invented score comparison", () => {
    expect(unsafeTopicExpression()).toContain("cf.llm.prompt.unsafe_topic_detected");
    expect(piiExpression()).toContain("cf.llm.prompt.pii_detected");
  });
});

// ── computeGapControls ───────────────────────────────────────────────────
describe("computeGapControls", () => {
  it("returns nothing when no results are in yet", () => {
    expect(computeGapControls(RT_CORPUS, new Map(), FALLBACK_STATE)).toEqual([]);
  });

  it("returns nothing when every scored attack was stopped at the edge (a real good outcome)", () => {
    const results = new Map<string, RtRunResult>(RT_CORPUS.map((a) => [a.id, r(a.id, "block")]));
    expect(computeGapControls(RT_CORPUS, results, FALLBACK_STATE)).toEqual([]);
  });

  it("only includes categories with reached > 0 in THIS run, not the corpus's scan numbers", () => {
    const results = new Map<string, RtRunResult>([
      ["rt-01", r("rt-01", "allow")], // Brand Tarnishing / Self-Criticism
      ["rt-31", r("rt-31", "block")], // Brand Tarnishing / Self-Criticism — stopped
      ["rt-02", r("rt-02", "block")], // Jailbreak — stopped, should not appear
    ]);
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    const brand = gaps.find((g) => g.category === "Brand Tarnishing / Self-Criticism")!;
    expect(brand).toBeDefined();
    expect(brand.reached).toBe(1);
    expect(brand.scored).toBe(2); // rt-01 allow + rt-31 block, tallied from THIS run
    expect(gaps.find((g) => g.category === "Jailbreak")).toBeUndefined();
  });

  it("maps Jailbreak / Prompt Injection / Adversarial Suffix to the injection mechanism with a `le` expression", () => {
    const results = new Map<string, RtRunResult>([
      ["rt-02", r("rt-02", "allow")], // Jailbreak
      ["rt-03", r("rt-03", "log")], // Prompt Injection
      ["rt-05", r("rt-05", "allow")], // Adversarial Suffix
    ]);
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    for (const cat of ["Jailbreak", "Prompt Injection", "Adversarial Suffix"]) {
      const g = gaps.find((x) => x.category === cat)!;
      expect(g.mechanism).toBe("injection");
      expect(g.expression).toMatch(/cf\.llm\.prompt\.injection_score le \d+/);
      expect(g.expression).not.toMatch(/ge \d+/);
    }
  });

  it("maps unsafe-topic categories (e.g. Hate / Toxic / Abuse) to the unsafe_topic mechanism", () => {
    const results = new Map<string, RtRunResult>([["rt-14", r("rt-14", "allow")]]); // Hate / Toxic / Abuse
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    const g = gaps.find((x) => x.category === "Hate / Toxic / Abuse")!;
    expect(g.mechanism).toBe("unsafe_topic");
    expect(g.expression).toContain("cf.llm.prompt.unsafe_topic_detected");
  });

  it("gives Brand Tarnishing / Self-Criticism a real custom-topic rule — the scan's largest gap", () => {
    const results = new Map<string, RtRunResult>([["rt-01", r("rt-01", "allow")]]);
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    const g = gaps.find((x) => x.category === "Brand Tarnishing / Self-Criticism")!;
    expect(g.mechanism).toBe("custom_topic_new");
    // custom_topic_categories is a real field (Ruleset Engine field reference),
    // and the topic key is knowable here because we are the ones proposing it.
    expect(g.expression).toContain('cf.llm.prompt.custom_topic_categories["Self-Criticism"]');
    expect(g.expression).toMatch(/ le \d+$/);
    expect(g.expression).not.toMatch(/ ge /);
    expect(g.coverage.exists).toBe(false);
    // The expression is inert until the topic exists, and a rule that never
    // matches is indistinguishable from one that works — so say so.
    expect(g.expressionNote).toMatch(/Create the topic first/);
  });

  it("routes Malware Generation and Remote Code Execution to AI Gateway, not a WAF expression", () => {
    const results = new Map<string, RtRunResult>([
      ["rt-16", r("rt-16", "allow")], // Malware Generation
      ["rt-20", r("rt-20", "allow")], // Remote Code Execution
    ]);
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    for (const cat of ["Malware Generation", "Remote Code Execution"]) {
      const g = gaps.find((x) => x.category === cat)!;
      expect(g.mechanism).toBe("ai_gateway");
      expect(g.expression).toBeNull();
      expect(g.coverage.confidence).toBe("not-applicable");
      expect(g.recommendation).toMatch(/Guardrails/);
    }
  });

  it("routes Political and Political Endorsements to the same existing custom-topic rule, name-matched only", () => {
    const results = new Map<string, RtRunResult>([
      ["rt-18", r("rt-18", "allow")], // Political Endorsements
      ["rt-28", r("rt-28", "allow")], // Political
    ]);
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    for (const cat of ["Political Endorsements", "Political"]) {
      const g = gaps.find((x) => x.category === cat)!;
      expect(g.mechanism).toBe("custom_topic_existing");
      expect(g.coverage.exists).toBe(true);
      expect(g.coverage.ruleName).toBe("Monitor LLM Custom Topics - Politics and Election");
      expect(g.coverage.confidence).toBe("fallback-name");
      // The topic KEY is not knowable from the zone (it reports rule
      // descriptions, not topic labels), so the expression must ship an
      // obvious placeholder rather than a guess that would compile and then
      // silently match nothing.
      expect(g.expression).toContain("<your topic label>");
      expect(g.expressionNote).toMatch(/Replace <your topic label>/);
    }
  });

  it("falls back to the generic unmapped message for a category with no known mechanism (custom CSV)", () => {
    const corpus = [{ id: "csv-1", category: "Custom CSV", prompt: "hello" }];
    const results = new Map<string, RtRunResult>([["csv-1", r("csv-1", "allow")]]);
    const gaps = computeGapControls(corpus as never, results, FALLBACK_STATE);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].mechanism).toBe("unmapped");
    expect(gaps[0].expression).toBeNull();
    expect(gaps[0].coverage.exists).toBe(false);
  });

  // ── provenance: live expression match vs live/fallback name match ────────
  it("reports live-expression confidence when a live rule's real expression matches the field", () => {
    const results = new Map<string, RtRunResult>([["rt-02", r("rt-02", "allow")]]); // Jailbreak
    const gaps = computeGapControls(RT_CORPUS, results, LIVE_STATE_WITH_INJECTION);
    const g = gaps.find((x) => x.category === "Jailbreak")!;
    expect(g.coverage.exists).toBe(true);
    expect(g.coverage.confidence).toBe("live-expression");
    expect(g.coverage.ruleName).toBe("Block LLM Injection");
  });

  it("reports fallback-name confidence (never live-expression) when the source is the static mirror", () => {
    const results = new Map<string, RtRunResult>([["rt-02", r("rt-02", "allow")]]); // Jailbreak
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    const g = gaps.find((x) => x.category === "Jailbreak")!;
    expect(g.coverage.exists).toBe(true);
    expect(g.coverage.confidence).toBe("fallback-name");
    // The mirror's "detail" is hand-written prose that happens to contain the
    // word "injection_score" — this must NOT be treated as an expression
    // match even though the substring is technically present.
    expect(g.coverage.confidence).not.toBe("live-expression");
  });

  it("reports no coverage when the live zone genuinely has no matching rule", () => {
    const results = new Map<string, RtRunResult>([["rt-02", r("rt-02", "allow")]]); // Jailbreak
    const gaps = computeGapControls(RT_CORPUS, results, EMPTY_LIVE_STATE);
    const g = gaps.find((x) => x.category === "Jailbreak")!;
    expect(g.coverage.exists).toBe(false);
    expect(g.coverage.confidence).toBe("none");
  });

  it("every gap carries reached <= scored, tallied from the run's own results", () => {
    const results = new Map<string, RtRunResult>([
      ["rt-02", r("rt-02", "allow")],
      ["rt-15", r("rt-15", "log")],
      ["rt-33", r("rt-33", "block")],
    ]); // three Jailbreak attacks: 2 reached, 1 stopped
    const gaps = computeGapControls(RT_CORPUS, results, FALLBACK_STATE);
    const g = gaps.find((x) => x.category === "Jailbreak")!;
    expect(g.reached).toBe(2);
    expect(g.scored).toBe(3);
    expect(g.reached).toBeLessThanOrEqual(g.scored);
  });
});

// Type-level smoke check that GapControl's shape matches what GapControls.tsx
// expects to render — a compile error here means the two drifted.
function assertShape(g: GapControl) {
  const _category: string = g.category;
  const _reached: number = g.reached;
  const _scored: number = g.scored;
  const _rec: string = g.recommendation;
  const _expr: string | null = g.expression;
  void _category, _reached, _scored, _rec, _expr;
}
void assertShape;
