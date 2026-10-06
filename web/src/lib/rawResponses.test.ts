import { describe, expect, it } from "vitest";
import { parseShowRaw } from "./rawResponses";
import { parseShowTurnDetails } from "./turnDetails";

// The two per-viewer switches fail in opposite, deliberate directions. Raw vendor bodies can
// quote the prompt, so that one is off unless explicitly on; the turn details are the demo's
// evidence of which control did what, so they are shown unless explicitly hidden. A missing,
// odd or unreadable value (null) must land on the safe side of each.
describe("per-viewer switches", () => {
  it("raw responses: on only for the exact stored word", () => {
    expect(parseShowRaw("on")).toBe(true);
    for (const v of ["off", "On", "true", "1", "yes", "", null, undefined]) expect(parseShowRaw(v), String(v)).toBe(false);
  });

  it("turn details: hidden only for the exact stored word", () => {
    expect(parseShowTurnDetails("off")).toBe(false);
    for (const v of ["on", "Off", "false", "0", "no", "", null, undefined]) {
      expect(parseShowTurnDetails(v), String(v)).toBe(true);
    }
  });
});
