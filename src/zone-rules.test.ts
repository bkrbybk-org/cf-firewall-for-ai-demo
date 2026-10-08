// How a fired WAF rule is classified as an AI Security rule.
//
// This replaced name matching against a hand-maintained mirror. The mirror
// drifted whenever a rule was renamed in the dashboard, and a drifted mirror
// misfiles a rule into "not AI Security" — the demo then reports that its own
// controls did nothing, or credits them for a rule they never ran.
import { describe, expect, it } from "vitest";
import { aiManagedRules, flattenCustomRules, isLlmExpression } from "./cloudflare";

describe("isLlmExpression", () => {
  it("matches the cf.llm.* detection fields the demo's rules use", () => {
    expect(isLlmExpression('(http.request.uri.path eq "/api/chat" and cf.llm.prompt.pii_detected)')).toBe(true);
    expect(isLlmExpression("cf.llm.prompt.injection_score lt 20")).toBe(true);
    expect(isLlmExpression("cf.llm.prompt.unsafe_topic_detected")).toBe(true);
  });

  it("does not match unrelated zone rules", () => {
    // These three actually outrank the LLM rules by event count on the demo
    // zone, which is why misclassifying them is not a hypothetical problem.
    expect(isLlmExpression('ip.geoip.country in {"CN" "RU"}')).toBe(false);
    expect(isLlmExpression('http.user_agent contains "ZAP"')).toBe(false);
    expect(isLlmExpression('http.request.uri.path contains "/.env"')).toBe(false);
  });

  it("classifies by expression, not by name-like text in it", () => {
    // A rule whose text mentions LLM but which inspects nothing LLM-specific
    // is not an AI Security rule — the old name heuristic got this wrong.
    expect(isLlmExpression('http.request.uri.path contains "/llm-proxy"')).toBe(false);
    // …and one that inspects cf.llm.* IS, whatever it is called.
    expect(isLlmExpression("cf.llm.prompt.detected")).toBe(true);
  });

  it("is false for an empty or absent expression", () => {
    expect(isLlmExpression("")).toBe(false);
  });
});

// Open bug #12 update (2026-10-08): this zone's AI rules live INSIDE custom rulesets that
// an execute rule runs — "LLM Monitor Ruleset" (on; its block rules off) and "LLM
// Protection Ruleset" (its execute rule off). Shapes as read live that day.
describe("flattenCustomRules", () => {
  const entry = [
    { id: "geo", action: "block", description: "Geography-based rule", expression: 'ip.src.country in {"CN"}' },
    { id: "x-mon", action: "execute", description: "LLM Monitor Ruleset", expression: "true", action_parameters: { id: "mon" } },
    { id: "x-prot", action: "execute", description: "LLM Protection Ruleset", expression: "true", enabled: false, action_parameters: { id: "prot" } },
    { id: "x-acct", action: "execute", description: "Unreadable Ruleset", expression: "true", action_parameters: { id: "elsewhere" } },
  ];
  const nested = new Map([
    ["mon", { name: "LLM Monitor Ruleset", rules: [
      { id: "m-inj", action: "log", description: "Block LLM Injection", expression: "(cf.llm.prompt.injection_score le 15)" },
      { id: "m-pii", action: "block", description: "Block LLM PII Categories", expression: "any(cf.llm.prompt.pii_categories[*] in {\"EMAIL_ADDRESS\"})", enabled: false },
    ] }],
    ["prot", { name: "LLM Protection Ruleset", rules: [
      { id: "p-inj", action: "block", description: "Block LLM Injection", expression: "(cf.llm.prompt.injection_score le 15)" },
    ] }],
  ]);
  const rules = flattenCustomRules(entry, nested);
  const by = (id: string) => rules.find((r) => r.id === id)!;

  it("replaces each opened execute rule by its ruleset's rules, tagged with the ruleset", () => {
    expect(rules.map((r) => r.id)).toEqual(["geo", "m-inj", "m-pii", "p-inj", "x-acct"]);
    expect(by("m-inj")).toMatchObject({ ruleset: "LLM Monitor Ruleset", llm: true, action: "log", enabled: true });
    expect(by("geo").ruleset).toBeUndefined();
  });

  it("a nested rule is only as enabled as the execute rule that runs it", () => {
    // On inside its ruleset, but the Protection ruleset's execute rule is off: never evaluated.
    expect(by("p-inj")).toMatchObject({ action: "block", enabled: false });
    // Off inside a running ruleset: off.
    expect(by("m-pii").enabled).toBe(false);
  });

  it("an execute rule whose ruleset could not be read stays listed as itself — never a silent gap", () => {
    expect(by("x-acct")).toMatchObject({ action: "execute", llm: false, name: "Unreadable Ruleset" });
  });

  it("rules with the same name in two rulesets stay two rules, told apart by id", () => {
    expect(rules.filter((r) => r.name === "Block LLM Injection").map((r) => r.id)).toEqual(["m-inj", "p-inj"]);
  });
});

describe("aiManagedRules", () => {
  it("takes only rules Cloudflare tags firewall-for-ai — never by name", () => {
    expect(
      aiManagedRules([
        { id: "a", description: "Detects PII categories in the prompt", categories: ["firewall-for-ai"] },
        { id: "b", description: "Looks like an LLM rule", categories: ["owasp"] },
        { id: "c", description: "Detects prompt injection attacks and jailbreaking" },
      ]),
    ).toEqual([{ id: "a", name: "Detects PII categories in the prompt" }]);
  });
});
