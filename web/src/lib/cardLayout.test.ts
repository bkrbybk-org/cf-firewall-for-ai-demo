import { describe, expect, it } from "vitest";
import { CARD_LAYOUT_KEY, parseCardLayout, readCardLayout, writeCardLayout } from "./cardLayout";

function memory(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
  };
}

const throwing = {
  getItem: (): string | null => {
    throw new Error("SecurityError");
  },
  setItem: (): void => {
    throw new Error("QuotaExceededError");
  },
};

describe("parseCardLayout", () => {
  it("accepts only the exact word compact", () => {
    expect(parseCardLayout("compact")).toBe("compact");
    expect(parseCardLayout("columns")).toBe("columns");
    expect(parseCardLayout("Compact")).toBe("columns");
    expect(parseCardLayout("rows")).toBe("columns");
    expect(parseCardLayout("")).toBe("columns");
    expect(parseCardLayout(null)).toBe("columns");
    expect(parseCardLayout(undefined)).toBe("columns");
  });
});

describe("readCardLayout", () => {
  it("reads a stored choice", () => {
    expect(readCardLayout(memory({ [CARD_LAYOUT_KEY]: "compact" }))).toBe("compact");
  });
  it("defaults to columns when nothing is stored, storage is missing, or it throws", () => {
    expect(readCardLayout(memory())).toBe("columns");
    expect(readCardLayout(null)).toBe("columns");
    expect(readCardLayout(throwing)).toBe("columns");
  });
});

describe("writeCardLayout", () => {
  it("persists under the documented key and reports success", () => {
    const s = memory();
    expect(writeCardLayout(s, "compact")).toBe(true);
    expect(s.data.get(CARD_LAYOUT_KEY)).toBe("compact");
    expect(readCardLayout(s)).toBe("compact");
  });
  it("reports failure instead of throwing when storage refuses or is missing", () => {
    expect(writeCardLayout(throwing, "compact")).toBe(false);
    expect(writeCardLayout(null, "compact")).toBe(false);
  });
});
