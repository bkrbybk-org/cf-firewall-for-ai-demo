// Open bug #22: evidence under an AI control must count AI Security's events only.
// These are the shapes measured live on 2026-10-07 (firewallEventsAdaptiveGroups, 24 h).
import { describe, expect, it } from "vitest";
import { tallyAiSecurity, type RuleGroup } from "./aiSecurityTally";

const g = (action: string, description: string, count: number, sampleInterval = 1, ruleId = description): RuleGroup => ({
  action,
  description,
  ruleId,
  count,
  sampleInterval,
});

const LIVE = [
  g("block", "Geography-based rule", 5125, 1.43),
  g("block", "Sensitive Paths", 3583, 2.81),
  g("block", "[Account-Level] Block Attacks (Score LE 12)", 691, 4.97),
  g("log", "Block LLM Injection", 450),
  g("log", "[Account-Level] Detect LLM Injection", 465),
  g("log", "Monitor LLM PII Categories", 251),
];

describe("tallyAiSecurity", () => {
  it("never counts a non-LLM block as AI Security's — the bug #22 defect", () => {
    const t = tallyAiSecurity(LIVE, null);
    expect(t.blocked).toBe(0); // every AI Security rule was in Log mode that day
    expect(t.logged).toBe(450 + 465 + 251);
    expect(t.zoneBlocked).toBe(5125 + 3583 + 691); // context only
    expect(t.rules.map((r) => r.name)).not.toContain("Geography-based rule");
    expect(t.classifiedBy).toBe("name");
  });

  it("counts AI Security blocks when its rules do block", () => {
    const t = tallyAiSecurity([...LIVE, g("block", "Block LLM Unsafe Categories", 1643), g("block", "Block LLM Injection", 905)], null);
    expect(t.blocked).toBe(1643 + 905);
  });

  it("a live rule's expression decides, even against its name; unlisted rules fall back to the name", () => {
    const live = [
      { id: "r1", name: "Block LLM Injection", llm: true },
      { id: "r2", name: "Legacy LLM path block", llm: false }, // name says LLM, expression does not
    ];
    const t = tallyAiSecurity(
      [
        g("block", "Block LLM Injection", 10, 1, "r1"),
        g("block", "Legacy LLM path block", 99, 1, "r2"),
        g("block", "[Account-Level] Detect LLM Injection", 5, 1, "acct"), // not in the zone ruleset
      ],
      live,
    );
    expect(t.blocked).toBe(15);
    expect(t.rules.map((r) => [r.name, r.via])).toEqual([
      ["Block LLM Injection", "expression"],
      ["[Account-Level] Detect LLM Injection", "name"],
    ]);
    expect(t.classifiedBy).toBe("mixed");
  });

  it("a sampled AI Security group marks the counts as estimates; a sampled non-AI group does not", () => {
    // LIVE: geography/path rules sampled (interval 1.4–5), every LLM group unsampled.
    expect(tallyAiSecurity(LIVE, null).sampled).toBe(false);
    expect(tallyAiSecurity([...LIVE, g("log", "Monitor LLM Custom Topics", 396, 1.01)], null).sampled).toBe(true);
  });

  it("challenge and other actions are neither blocked nor logged", () => {
    const t = tallyAiSecurity([g("managed_challenge", "Challenge LLM abuse", 7)], null);
    expect(t).toMatchObject({ blocked: 0, logged: 0, other: 7 });
  });
});

// 2026-10-08: the zone's AI rules are readable once nested rulesets are opened, and the
// managed Firewall for AI rules are classified by Cloudflare's category.
describe("tallyAiSecurity — nested custom rules and managed AI rules", () => {
  const groups = [
    g("log", "Detects PII categories in the prompt", 12, 1, "mgd-pii"), // managed: no "LLM" in its name
    g("log", "Monitor LLM PII Categories", 12, 1, "mon-pii"),
    g("log", "Monitor Requests Token Count", 17, 1, "mon-tok"), // cf.llm.prompt.token_count; no "LLM" in its name
    g("log", "[Account-Level] Detect LLM Unsafe Prompt", 22, 1, "acct-1"), // not in the zone's rulesets
    g("block", "Geography-based rule", 4737, 1, "geo"),
  ];
  const live = [
    { id: "mon-pii", name: "Monitor LLM PII Categories", llm: true, via: "expression" as const },
    { id: "mon-tok", name: "Monitor Requests Token Count", llm: true, via: "expression" as const },
    { id: "geo", name: "Geography-based rule", llm: false, via: "expression" as const },
    { id: "mgd-pii", name: "Detects PII categories in the prompt", llm: true, via: "category" as const },
  ];

  it("counts the managed rule by category and the nested rule by expression — names alone missed both", () => {
    const before = tallyAiSecurity(groups, null);
    expect(before.logged).toBe(12 + 22); // only the two with "LLM" in their names
    const t = tallyAiSecurity(groups, live);
    expect(t.logged).toBe(12 + 12 + 17 + 22);
    expect(t.blocked).toBe(0);
    expect(t.rules.find((r) => r.name === "Detects PII categories in the prompt")?.via).toBe("category");
    expect(t.rules.find((r) => r.name === "Monitor Requests Token Count")?.via).toBe("expression");
    expect(t.rules.find((r) => r.name.startsWith("[Account-Level]"))?.via).toBe("name");
    expect(t.classifiedBy).toBe("mixed");
  });
});
