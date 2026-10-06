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
