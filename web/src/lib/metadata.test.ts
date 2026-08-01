// Tests for the AI Gateway custom-metadata parser.
//
// The five-entry cap matters because AI Gateway silently keeps only the first
// five and drops the rest with no error — so a regression here loses data
// invisibly. The panel and the send pipeline share this function precisely so
// the preview can't drift from what is transmitted.
import { describe, expect, it } from "vitest";
import { MAX_METADATA_ENTRIES, parseMetadata } from "./metadata";

describe("parseMetadata", () => {
  it("parses comma-separated key=value pairs", () => {
    expect(parseMetadata("plan=paid, team=telco")).toEqual({ plan: "paid", team: "telco" });
  });

  it("trims surrounding whitespace on keys and values", () => {
    expect(parseMetadata("  plan = paid  ")).toEqual({ plan: "paid" });
  });

  it("keeps '=' inside the value", () => {
    expect(parseMetadata("filter=a=b")).toEqual({ filter: "a=b" });
  });

  it("caps at the gateway's five-entry limit", () => {
    const six = "a=1,b=2,c=3,d=4,e=5,f=6";
    const out = parseMetadata(six)!;
    expect(Object.keys(out)).toHaveLength(MAX_METADATA_ENTRIES);
    // First five win — matches the gateway's own truncation order.
    expect(out).toEqual({ a: "1", b: "2", c: "3", d: "4", e: "5" });
    expect(out.f).toBeUndefined();
  });

  it("drops malformed pairs rather than emitting empty keys or values", () => {
    expect(parseMetadata("plan=paid, broken, =novalue, nokey=")).toEqual({ plan: "paid" });
  });

  it("returns undefined when nothing usable is present", () => {
    for (const raw of ["", "   ", "no-equals-sign", ",,,"]) {
      expect(parseMetadata(raw), `for ${JSON.stringify(raw)}`).toBeUndefined();
    }
  });
});
