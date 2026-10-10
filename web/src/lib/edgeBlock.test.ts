import { describe, expect, it } from "vitest";
import { detectionOfExpression, parseEdgeBlock, ruleForReasonCode } from "./edgeBlock";

// The body the deployed zone's PII rule returned on prod (PROGRESS Open bug #4).
const PROD_PII = {
  error: "request_blocked",
  reason_code: "LLM_PII_BLOCKED",
  message: "This request was blocked because it may contain sensitive personal or regulated data.",
  detail: "Please remove sensitive data such as payment, contact, or credential-related information and try again.",
  support_hint: "Please provide the cf-ray response header to support.",
};

describe("parseEdgeBlock", () => {
  it("reads the deployed zone's Custom JSON: detection from the code, the rule's own message", () => {
    expect(parseEdgeBlock(PROD_PII)).toEqual({
      structured: true,
      detection: "pii",
      reason: `${PROD_PII.message} ${PROD_PII.detail}`,
      code: "LLM_PII_BLOCKED",
    });
  });

  it("an unseen reason_code keeps its message and code but claims no detection type", () => {
    // Spelled like an injection rule — and still not labelled one: the name is a guess.
    const r = parseEdgeBlock({ error: "request_blocked", reason_code: "LLM_INJECTION_BLOCKED", message: "Blocked." });
    expect(r).toEqual({ structured: true, detection: undefined, reason: "Blocked.", code: "LLM_INJECTION_BLOCKED" });
  });

  it("does not resolve inherited keys as reason codes", () => {
    expect(parseEdgeBlock({ reason_code: "toString" }).detection).toBeUndefined();
    expect(parseEdgeBlock({ reason_code: "__proto__" }).detection).toBeUndefined();
  });

  it("still reads the legacy {blocked, detection, reason} shape", () => {
    expect(parseEdgeBlock({ blocked: true, detection: "injection", reason: "Prompt injection" })).toEqual({
      structured: true,
      detection: "injection",
      reason: "Prompt injection",
    });
    // An unknown legacy detection is not passed through as a label key.
    expect(parseEdgeBlock({ blocked: true, detection: "made_up" }).detection).toBeUndefined();
  });

  it("treats anything without a self-identifying field as unstructured", () => {
    for (const body of [null, undefined, "<html>", [], {}, { error: "request_blocked" }, { blocked: "true" }, { reason_code: "" }]) {
      expect(parseEdgeBlock(body).structured).toBe(false);
    }
  });

  it("uses whichever of message / detail exists", () => {
    expect(parseEdgeBlock({ reason_code: "X", detail: "only detail" }).reason).toBe("only detail");
    expect(parseEdgeBlock({ reason_code: "X" }).reason).toBeUndefined();
  });
});

// The zone's real LLM block rules (rule definitions read 2026-10-10): the same names and codes in two rulesets,
// with the Protection ruleset's rules effectively off between demos (Open bugs #28).
const LIVE = [
  { name: "Block LLM Injection", action: "block", ruleset: "LLM Protection Ruleset", reasonCode: "LLM_PROMPT_INJECTION_BLOCKED", detail: "(cf.llm.prompt.injection_score le 15)" },
  { name: "Block LLM PII Categories", action: "block", ruleset: "LLM Protection Ruleset", reasonCode: "LLM_PII_BLOCKED", detail: '(any(cf.llm.prompt.pii_categories[*] in {"CREDIT_CARD" "EMAIL_ADDRESS"}))' },
  { name: "Block LLM Unsafe Categories", action: "block", ruleset: "LLM Protection Ruleset", reasonCode: "LLM_UNSAFE_TOPIC_BLOCKED", detail: '(any(cf.llm.prompt.unsafe_topic_categories[*] in {"S1" "S2"}))' },
  { name: "Block LLM PII Categories", action: "block", ruleset: "LLM Monitor Ruleset", reasonCode: "LLM_PII_BLOCKED", detail: '(any(cf.llm.prompt.pii_categories[*] in {"CREDIT_CARD" "EMAIL_ADDRESS"}))' },
  { name: "Monitor LLM Custom Topics - NTT Test", action: "log", ruleset: "LLM Monitor Ruleset", detail: '(cf.llm.prompt.custom_topic_categories["competitors-ais"] le 50)' },
];

describe("detectionOfExpression", () => {
  it("names the one AI Security signal an expression tests, and nothing when it tests none or several", () => {
    expect(detectionOfExpression("(cf.llm.prompt.injection_score le 15)")).toBe("injection");
    expect(detectionOfExpression("cf.llm.prompt.pii_detected")).toBe("pii");
    expect(detectionOfExpression('any(cf.llm.prompt.unsafe_topic_categories[*] in {"S1"})')).toBe("unsafe_topic");
    expect(detectionOfExpression("cf.llm.prompt.pii_detected or cf.llm.prompt.injection_score lt 20")).toBeUndefined();
    expect(detectionOfExpression('cf.llm.prompt.custom_topic_categories["x"] le 30')).toBeUndefined();
    expect(detectionOfExpression("cf.waf.score lt 20")).toBeUndefined();
    expect(detectionOfExpression(undefined)).toBeUndefined();
  });
});

describe("ruleForReasonCode", () => {
  it("names the rule and its detection for a code no payload has shown yet", () => {
    expect(ruleForReasonCode("LLM_PROMPT_INJECTION_BLOCKED", LIVE)).toEqual({
      name: "Block LLM Injection",
      rulesets: ["LLM Protection Ruleset"],
      detection: "injection",
    });
    expect(ruleForReasonCode("LLM_UNSAFE_TOPIC_BLOCKED", LIVE)).toMatchObject({ detection: "unsafe_topic" });
  });
  it("a code held by the same rule in two rulesets: one name, both rulesets, the shared detection", () => {
    expect(ruleForReasonCode("LLM_PII_BLOCKED", LIVE)).toEqual({
      name: "Block LLM PII Categories",
      rulesets: ["LLM Protection Ruleset", "LLM Monitor Ruleset"],
      detection: "pii",
    });
  });
  it("claims no detection when the rules sharing a code disagree, and nothing for an unknown code", () => {
    const mixed = [...LIVE, { name: "Block odd", action: "block", reasonCode: "LLM_PII_BLOCKED", detail: "cf.llm.prompt.injection_score lt 5" }];
    expect(ruleForReasonCode("LLM_PII_BLOCKED", mixed)).toEqual({
      name: "2 rules",
      rulesets: ["LLM Protection Ruleset", "LLM Monitor Ruleset"],
    });
    expect(ruleForReasonCode("SOMETHING_ELSE", LIVE)).toBeNull();
    expect(ruleForReasonCode(undefined, LIVE)).toBeNull();
    // Only block rules answer with a block body.
    expect(ruleForReasonCode("X", [{ name: "log rule", action: "log", reasonCode: "X" }])).toBeNull();
  });
});
