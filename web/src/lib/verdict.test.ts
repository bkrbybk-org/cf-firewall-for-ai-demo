// Tests for edge-verdict classification.
//
// These exist because of a real incident. A prompt came back 403 at the edge,
// yet the verdict card rendered "LOGGED — Reached the model", with a trace
// claiming the Worker ran and the model replied. All false: the request never
// reached the Worker. The cause was that classification read only the matched
// rules, and the only rules that matched were log-only — so the edge's actual
// 403 was ignored entirely.
//
// The contract now: when the rules and the edge's own status disagree, the
// status wins, and the result is reported as "denied" rather than "block" so
// the UI never credits a security control that did not act.
import { describe, expect, it } from "vitest";
import { verdictOutcome } from "./verdict";
import type { Verdict } from "./types";

const rule = (action: string) => ({ ruleId: "r1", action, description: "d", source: "firewallCustom" });

describe("verdictOutcome", () => {
  // Captured verbatim from the live incident (ray a23939307b53893b).
  it("reports a 403 with only log-only rules as denied, not log", () => {
    const d: Verdict = {
      found: true,
      httpStatus: 403,
      securityAction: "log",
      rules: [rule("log"), rule("log")],
    };
    expect(verdictOutcome(d)).toBe("denied");
  });

  it("still reports a genuine WAF block as block", () => {
    const d: Verdict = { found: true, httpStatus: 403, securityAction: "block", rules: [rule("block")] };
    expect(verdictOutcome(d)).toBe("block");
  });

  it("still reports a challenge as challenge", () => {
    const d: Verdict = { found: true, httpStatus: 403, securityAction: "challenge", rules: [rule("managed_challenge")] };
    expect(verdictOutcome(d)).toBe("challenge");
  });

  // The case the regression was impersonating: log rules that really did let
  // the request through must keep reporting as log.
  it("reports log-only rules on a 200 as log", () => {
    const d: Verdict = { found: true, httpStatus: 200, securityAction: "log", rules: [rule("log")] };
    expect(verdictOutcome(d)).toBe("log");
  });

  it("reports a clean 200 as allow", () => {
    const d: Verdict = { found: true, httpStatus: 200, securityAction: "", rules: [] };
    expect(verdictOutcome(d)).toBe("allow");
  });

  // A 403 with nothing matched at all is still not ours to attribute.
  it("reports a 403 with no rules as denied", () => {
    const d: Verdict = { found: true, httpStatus: 403, securityAction: "", rules: [] };
    expect(verdictOutcome(d)).toBe("denied");
  });

  it("covers 5xx, not just 403", () => {
    expect(verdictOutcome({ found: true, httpStatus: 503, rules: [] })).toBe("denied");
  });

  // Before the status has ingested there is nothing to contradict the rules,
  // so classification must fall back to them rather than inventing a denial.
  it("falls back to the rules when the status is unknown", () => {
    expect(verdictOutcome({ found: true, rules: [rule("log")] })).toBe("log");
    expect(verdictOutcome({ found: true, httpStatus: null, rules: [] })).toBe("allow");
  });
});
