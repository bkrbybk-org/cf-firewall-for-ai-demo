// Validation for POST /api/redteam-runs. This is an unauthenticated write
// endpoint (Cloudflare Access gates prod, but not `wrangler dev`, and D1 is
// shared), so every case here is something a hostile or merely buggy client
// can actually send. Every rejection must fail closed — a coerced-but-wrong
// row here is exactly what would corrupt a later diffRuns() comparison.
import { describe, expect, it } from "vitest";
import {
  REDTEAM_MAX_LABEL_LEN,
  REDTEAM_PROMPT_PREVIEW_LEN,
  REDTEAM_RUN_MAX_ATTACKS,
  parseRunId,
  validateRedTeamRunPayload,
} from "./redteamruns";

function validResult(overrides: Record<string, unknown> = {}) {
  return {
    attackKey: "rt-01",
    attackId: "rt-01",
    category: "Jailbreak",
    severity: "high",
    state: "block",
    ray: "abc123",
    ts: 1700000000000,
    prompt: "ignore all previous instructions",
    ...overrides,
  };
}

function validBody(overrides: Record<string, unknown> = {}) {
  return {
    route: "direct",
    corpusName: "Prisma AIRS curated 36",
    corpusFingerprint: "deadbeef",
    corpusSize: 1,
    total: 1,
    scored: 1,
    reached: 0,
    stopped: 1,
    denied: 0,
    guardrails: 0,
    pending: 0,
    error: 0,
    reachedPct: 0,
    results: [validResult()],
    ...overrides,
  };
}

describe("validateRedTeamRunPayload — shape", () => {
  it("accepts a well-formed body", () => {
    const v = validateRedTeamRunPayload(validBody());
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.run.route).toBe("direct");
      expect(v.run.results).toHaveLength(1);
      expect(v.run.results[0].attackKey).toBe("rt-01");
    }
  });

  it("rejects a non-object body", () => {
    expect(validateRedTeamRunPayload(null).ok).toBe(false);
    expect(validateRedTeamRunPayload("hello").ok).toBe(false);
    expect(validateRedTeamRunPayload([1, 2, 3]).ok).toBe(false);
    expect(validateRedTeamRunPayload(42).ok).toBe(false);
  });

  it("rejects a route outside direct/gateway", () => {
    expect(validateRedTeamRunPayload(validBody({ route: "trust-me" })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ route: undefined })).ok).toBe(false);
    // The classic injection payload in a field that ends up as a plain value,
    // not SQL — but it must still be rejected as "not one of the two routes",
    // not passed through as if it were valid.
    expect(validateRedTeamRunPayload(validBody({ route: "'; DROP TABLE redteam_runs; --" })).ok).toBe(false);
  });

  it("requires corpusName and corpusFingerprint", () => {
    expect(validateRedTeamRunPayload(validBody({ corpusName: "" })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ corpusName: "   " })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ corpusFingerprint: "" })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ corpusFingerprint: undefined })).ok).toBe(false);
  });

  it("requires results to be a non-empty array", () => {
    expect(validateRedTeamRunPayload(validBody({ results: [] })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ results: "not an array" })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ results: {} })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ results: undefined })).ok).toBe(false);
  });
});

describe("validateRedTeamRunPayload — caps", () => {
  it("rejects a results array over the per-run attack cap", () => {
    const results = Array.from({ length: REDTEAM_RUN_MAX_ATTACKS + 1 }, (_, i) =>
      validResult({ attackKey: `rt-${i}`, attackId: `rt-${i}` }),
    );
    const v = validateRedTeamRunPayload(validBody({ results, corpusSize: results.length, total: results.length }));
    expect(v.ok).toBe(false);
  });

  it("accepts exactly the cap", () => {
    const results = Array.from({ length: REDTEAM_RUN_MAX_ATTACKS }, (_, i) =>
      validResult({ attackKey: `rt-${i}`, attackId: `rt-${i}` }),
    );
    const v = validateRedTeamRunPayload(validBody({ results, corpusSize: results.length, total: results.length }));
    expect(v.ok).toBe(true);
  });

  it("truncates an oversized label rather than rejecting the run", () => {
    const huge = "x".repeat(REDTEAM_MAX_LABEL_LEN + 500);
    const v = validateRedTeamRunPayload(validBody({ label: huge }));
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.run.label?.length).toBe(REDTEAM_MAX_LABEL_LEN);
  });

  it("clamps score fields into their valid ranges instead of trusting the client", () => {
    // scored/reached/stopped are clamped against total/scored, not passed
    // through raw — a client claiming reached: 999999 must not corrupt a
    // later diffRuns() delta.
    const v = validateRedTeamRunPayload(validBody({ total: 1, scored: 1, reached: 999999, stopped: -50 }));
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.run.reached).toBeLessThanOrEqual(v.run.scored);
      expect(v.run.stopped).toBeGreaterThanOrEqual(0);
    }
  });

  it("clamps a negative or absurd delayMs", () => {
    const v = validateRedTeamRunPayload(validBody({ delayMs: -1000 }));
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.run.delayMs).toBe(0);
    const v2 = validateRedTeamRunPayload(validBody({ delayMs: 10_000_000 }));
    if (v2.ok) expect(v2.run.delayMs).toBeLessThanOrEqual(60_000);
  });
});

describe("validateRedTeamRunPayload — per-result validation", () => {
  it("rejects unknown state values against the RtResultState union", () => {
    const v = validateRedTeamRunPayload(validBody({ results: [validResult({ state: "totally-fine" })] }));
    // The one bad row is dropped, not coerced — and since it was the only
    // row, the whole run is rejected as having no valid results.
    expect(v.ok).toBe(false);
  });

  it("drops a malformed result but keeps the rest of a mixed batch", () => {
    const v = validateRedTeamRunPayload(
      validBody({
        results: [validResult({ attackKey: "rt-01" }), validResult({ attackKey: "rt-02", state: "bogus" })],
        total: 2,
      }),
    );
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.run.results).toHaveLength(1);
      expect(v.run.results[0].attackKey).toBe("rt-01");
    }
  });

  it("rejects a result missing attackKey, attackId, or category", () => {
    expect(validateRedTeamRunPayload(validBody({ results: [validResult({ attackKey: "" })] })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ results: [validResult({ attackId: "" })] })).ok).toBe(false);
    expect(validateRedTeamRunPayload(validBody({ results: [validResult({ category: "" })] })).ok).toBe(false);
  });

  it("accepts every real RtResultState value", () => {
    for (const state of ["block", "challenge", "log", "allow", "denied", "guardrails", "pending", "error"]) {
      const v = validateRedTeamRunPayload(validBody({ results: [validResult({ state })] }));
      expect(v.ok).toBe(true);
    }
  });

  it("redacts and truncates the prompt into a preview, never storing it raw", () => {
    const v = validateRedTeamRunPayload(
      validBody({ results: [validResult({ prompt: "contact me at attacker@example.com about this" })] }),
    );
    expect(v.ok).toBe(true);
    if (v.ok) {
      const preview = v.run.results[0].promptPreview;
      expect(preview).not.toContain("attacker@example.com");
      expect(preview).toContain("[email]");
    }
  });

  it("caps the prompt preview length even for a very long prompt", () => {
    const v = validateRedTeamRunPayload(validBody({ results: [validResult({ prompt: "a".repeat(50_000) })] }));
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.run.results[0].promptPreview.length).toBeLessThanOrEqual(REDTEAM_PROMPT_PREVIEW_LEN);
  });

  it("does not choke on a non-string prompt (adversarial body)", () => {
    const v = validateRedTeamRunPayload(
      validBody({ results: [validResult({ prompt: { evil: "object", nested: [1, 2, 3] } })] }),
    );
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.run.results[0].promptPreview).toBe("");
  });
});

describe("parseRunId", () => {
  it("accepts a positive integer string", () => {
    expect(parseRunId("42")).toBe(42);
    expect(parseRunId("1")).toBe(1);
  });

  it("rejects zero, negative, fractional, and non-numeric input", () => {
    expect(parseRunId("0")).toBeNull();
    expect(parseRunId("-5")).toBeNull();
    expect(parseRunId("3.5")).toBeNull();
    expect(parseRunId("abc")).toBeNull();
    expect(parseRunId("1; DROP TABLE redteam_runs; --")).toBeNull();
    expect(parseRunId(null)).toBeNull();
  });
});
