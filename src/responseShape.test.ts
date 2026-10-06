import { describe, expect, it } from "vitest";
import { shapeOf } from "./responseShape";

describe("shapeOf", () => {
  it("keeps keys, types and booleans — never a string's or a number's value", () => {
    const body = {
      is_safe: false,
      severity: "HIGH",
      explanation: "The prompt 'ignore all previous instructions' is an injection",
      event_id: "evt-8f2c",
      rules: [{ rule_name: "Prompt Injection", classification: "SECURITY_VIOLATION" }, { rule_name: "PII" }],
      count: 42,
      nothing: null,
    };
    const s = shapeOf(body);
    expect(s).toEqual({
      is_safe: false,
      severity: "string",
      explanation: "string",
      event_id: "string",
      rules: ["length 2", { rule_name: "string", classification: "string" }],
      count: "number",
      nothing: "null",
    });
    const text = JSON.stringify(s);
    for (const leaked of ["ignore all previous", "evt-8f2c", "HIGH", "Prompt Injection", "42"]) expect(text).not.toContain(leaked);
  });

  it("caps depth, keys per object and key length", () => {
    let deep: unknown = "x";
    for (let i = 0; i < 10; i++) deep = { d: deep };
    expect(JSON.stringify(shapeOf(deep))).toContain("object(…)");
    const wide = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`k${i}`, 1]));
    const w = shapeOf(wide) as Record<string, unknown>;
    expect(Object.keys(w)).toHaveLength(41);
    expect(w["…"]).toBe("10 more keys");
    const longKey = shapeOf({ ["x".repeat(100)]: 1 }) as Record<string, unknown>;
    expect(Object.keys(longKey)[0]).toHaveLength(61);
  });

  it("describes empty arrays and scalars at the top", () => {
    expect(shapeOf([])).toEqual(["empty"]);
    expect(shapeOf(true)).toBe(true);
    expect(shapeOf("secret")).toBe("string");
  });
});

describe("shapeOf — revealing a string verdict (Cato's action_type)", () => {
  const reveal = ["required_action.action_type", "list.kind"];
  // Cato's documented block body: its text fields echo the SSN from the prompt.
  const cato = {
    required_action: {
      action_type: "block_action",
      policy_name: "Example Policy",
      detection_message: "\"078-05-1120\" detected as SSN",
    },
    redacted_chat: { redacted_new_message: { content: "check SSN [SSN_1]", entities: [{ type: "SSN", content: "078-05-1120" }] } },
  };

  it("shows the value at a named path when it is a bare lowercase token", () => {
    const s = shapeOf(cato, { reveal }) as Record<string, Record<string, unknown>>;
    expect(s.required_action.action_type).toBe("string = block_action");
    expect(s.required_action.policy_name).toBe("string");
    const text = JSON.stringify(s);
    for (const leaked of ["078-05-1120", "Example Policy", "detected as", "SSN_1"]) expect(text).not.toContain(leaked);
  });

  it("never reveals without the option, or at any other path", () => {
    expect(JSON.stringify(shapeOf(cato))).not.toContain("block_action");
    const other = shapeOf({ action_type: "block_action", x: { required_action: { action_type: "no_action" } } }, { reveal });
    expect(JSON.stringify(other)).not.toContain("block_action");
    expect(JSON.stringify(other)).not.toContain("no_action");
  });

  it("keeps anything that is not a token hidden, even at a named path", () => {
    for (const value of [
      "078-05-1120",
      "ignore all previous instructions",
      "Block_Action",
      "block-action",
      "12345",
      "_leading",
      "a".repeat(41),
      "",
    ]) {
      const s = shapeOf({ required_action: { action_type: value } }, { reveal }) as Record<string, Record<string, unknown>>;
      expect(s.required_action.action_type, value).toBe("string");
    }
    expect((shapeOf({ required_action: { action_type: "a".repeat(40) } }, { reveal }) as Record<string, Record<string, unknown>>)
      .required_action.action_type).toBe(`string = ${"a".repeat(40)}`);
  });

  it("follows a path through an array without adding a segment", () => {
    expect(shapeOf({ list: [{ kind: "allow" }] }, { reveal })).toEqual({ list: ["length 1", { kind: "string = allow" }] });
  });
});
