import { describe, expect, it } from "vitest";
import { parseEdgeBlock } from "./edgeBlock";

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
