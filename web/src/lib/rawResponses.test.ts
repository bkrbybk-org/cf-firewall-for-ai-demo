import { describe, expect, it } from "vitest";
import { RAW_RESPONSES_KEY, parseShowRaw, readShowRaw, writeShowRaw } from "./rawResponses";

// Raw vendor bodies can quote the prompt, so the switch is off unless explicitly on —
// a missing, odd or unreadable value must never turn it on.
describe("raw responses switch", () => {
  it("is on only for the exact stored word", () => {
    expect(parseShowRaw("on")).toBe(true);
    for (const v of ["off", "On", "true", "1", "yes", "", null, undefined]) expect(parseShowRaw(v), String(v)).toBe(false);
  });

  it("reads off when storage is missing or throws, and reports a refused write", () => {
    const throwing = {
      getItem: (): string | null => {
        throw new Error("SecurityError");
      },
      setItem: (): void => {
        throw new Error("QuotaExceededError");
      },
    };
    expect(readShowRaw(null)).toBe(false);
    expect(readShowRaw(throwing)).toBe(false);
    expect(writeShowRaw(throwing, true)).toBe(false);
    expect(writeShowRaw(null, true)).toBe(false);
  });

  it("round-trips through storage under its key", () => {
    const data = new Map<string, string>();
    const s = { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v) };
    expect(writeShowRaw(s, true)).toBe(true);
    expect(data.get(RAW_RESPONSES_KEY)).toBe("on");
    expect(readShowRaw(s)).toBe(true);
    writeShowRaw(s, false);
    expect(readShowRaw(s)).toBe(false);
  });
});
