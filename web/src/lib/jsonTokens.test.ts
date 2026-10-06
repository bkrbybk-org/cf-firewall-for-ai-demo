import { describe, expect, it } from "vitest";
import { jsonTokens } from "./jsonTokens";

const pretty = (v: unknown) => JSON.stringify(v, null, 2);
const kinds = (s: string) => jsonTokens(s).filter((t) => t.kind !== "punct").map((t) => [t.kind, t.text]);

describe("jsonTokens", () => {
  it("tells keys from string values, and types every scalar", () => {
    const s = pretty({ action_type: "block_action", score: -0.5e3, flagged: true, required_action: null, n: 0 });
    expect(kinds(s)).toEqual([
      ["key", '"action_type"'],
      ["string", '"block_action"'],
      ["key", '"score"'],
      ["number", "-500"],
      ["key", '"flagged"'],
      ["boolean", "true"],
      ["key", '"required_action"'],
      ["null", "null"],
      ["key", '"n"'],
      ["number", "0"],
    ]);
  });

  it("never splits a string: numbers, booleans, colons and escaped quotes inside it stay in it", () => {
    const s = pretty({ message: '"078-05-1120" detected: true, null 42', "a:b": "x\\y" });
    expect(kinds(s)).toEqual([
      ["key", '"message"'],
      ["string", JSON.stringify('"078-05-1120" detected: true, null 42')],
      ["key", '"a:b"'],
      ["string", JSON.stringify("x\\y")],
    ]);
  });

  it("loses nothing: the tokens join back to the exact input", () => {
    const s = pretty({ a: [1, "two", { b: false, c: [] }], d: {}, e: "<img src=x onerror=alert(1)>" });
    expect(jsonTokens(s).map((t) => t.text).join("")).toBe(s);
  });

  it("keeps hostile content as a plain string token (rendered as text, never markup)", () => {
    const s = pretty({ e: "<script>alert(1)</script>" });
    expect(jsonTokens(s).find((t) => t.kind === "string")?.text).toBe('"<script>alert(1)</script>"');
  });

  it("handles array values and nesting: strings in arrays are values, not keys", () => {
    expect(kinds(pretty(["k", { k: ["v"] }]))).toEqual([
      ["string", '"k"'],
      ["key", '"k"'],
      ["string", '"v"'],
    ]);
  });
});
