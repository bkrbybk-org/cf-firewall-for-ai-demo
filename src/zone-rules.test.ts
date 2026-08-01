// How a fired WAF rule is classified as an AI Security rule.
//
// This replaced name matching against a hand-maintained mirror. The mirror
// drifted whenever a rule was renamed in the dashboard, and a drifted mirror
// misfiles a rule into "not AI Security" — the demo then reports that its own
// controls did nothing, or credits them for a rule they never ran.
import { describe, expect, it } from "vitest";
import { isLlmExpression } from "./cloudflare";

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
