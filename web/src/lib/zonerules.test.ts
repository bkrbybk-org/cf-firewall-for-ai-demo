// Client-side half of rule classification: given a rule name from
// firewallEventsAdaptive and whatever rule list is currently loaded, is it one
// of AI Security's rules?
import { describe, expect, it } from "vitest";
import { classifyRule, type ZoneRulesState } from "../hooks/useZoneRules";

const live = (rules: { name: string; llm: boolean }[]): ZoneRulesState => ({
  source: "live",
  rules: rules.map((r) => ({ name: r.name, action: "block", enabled: true, llm: r.llm })),
});

describe("classifyRule", () => {
  it("uses the live list's expression-derived flag", () => {
    const state = live([{ name: "Block LLM Injection", llm: true }]);
    expect(classifyRule("Block LLM Injection", state)).toBe(true);
  });

  it("keeps classifying a rule that was renamed away from 'LLM'", () => {
    // The whole point: the dashboard name no longer carries the meaning, the
    // expression does. Under the old name heuristic this returned false and
    // the rule silently moved to the "not AI Security" group.
    const state = live([{ name: "Prompt safety — inbound", llm: true }]);
    expect(classifyRule("Prompt safety — inbound", state)).toBe(true);
  });

  it("does not classify an unrelated rule that happens to say LLM", () => {
    const state = live([{ name: "Rate limit LLM proxy path", llm: false }]);
    expect(classifyRule("Rate limit LLM proxy path", state)).toBe(false);
  });

  it("matches names case- and whitespace-insensitively", () => {
    const state = live([{ name: "Block LLM PII Categories", llm: true }]);
    expect(classifyRule("  block llm pii categories  ", state)).toBe(true);
  });

  it("falls back to the name heuristic for rules absent from the list", () => {
    // Account-level rules never appear in a zone ruleset, so they always take
    // this path — degrade to "probably LLM" rather than dropping them.
    const state = live([{ name: "Block LLM Injection", llm: true }]);
    expect(classifyRule("[Account-Level] Monitor LLM Something", state)).toBe(true);
    expect(classifyRule("Geography-based rule", state)).toBe(false);
  });

  it("still classifies when only the static mirror is loaded", () => {
    const fallback: ZoneRulesState = { source: "fallback", rules: [] };
    expect(classifyRule("Monitor LLM Injection", fallback)).toBe(true);
    expect(classifyRule("(P) AI Red Team", fallback)).toBe(false);
  });
});
