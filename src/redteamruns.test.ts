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
  parseStoredVendors,
  toStoredVendorsJson,
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

  it("never stores reached + stopped above scored (bug #19)", () => {
    const v = validateRedTeamRunPayload(validBody({ total: 10, scored: 10, reached: 8, stopped: 9 }));
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.run.reached).toBe(8);
      expect(v.run.stopped).toBe(2);
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

// Benchmark fields (migration 0007). The vendors column must only ever hold known
// provider ids and verdict words — never vendor text — and a partial value would be
// a false statement about which guardrails saw the prompt.
describe("benchmark fields", () => {
  const P = ["prisma-airs", "crowdstrike-aidr"] as const;
  const good = { mode: "parallel", verdicts: [{ provider: "prisma-airs", verdict: "block" }, { provider: "crowdstrike-aidr", verdict: "alerts" }] };

  it("stores verdicts as compact JSON and reads them back", () => {
    const json = toStoredVendorsJson(good, P)!;
    expect(json).toBe('{"m":"parallel","v":[["prisma-airs","block"],["crowdstrike-aidr","alerts"]]}');
    expect(parseStoredVendors(json, P)).toEqual(good);
  });

  it("drops the whole value on any unknown provider, verdict, mode or duplicate — never stores the rest", () => {
    const bad = [
      { ...good, mode: "both" },
      { ...good, verdicts: [...good.verdicts, { provider: "evil-corp", verdict: "block" }] },
      { ...good, verdicts: [{ provider: "prisma-airs", verdict: "blocked <script>" }] },
      { ...good, verdicts: [good.verdicts[0], good.verdicts[0]] },
      { ...good, verdicts: [] },
      { ...good, verdicts: [{ provider: "prisma-airs", verdict: "block", message: "the SSN 078-05-1120" }] },
      "parallel",
      null,
    ];
    // The extra `message` key is ignored, not stored: only provider + verdict are copied.
    expect(toStoredVendorsJson(bad[5], P)).toBe('{"m":"parallel","v":[["prisma-airs","block"]]}');
    for (const b of bad.filter((_, i) => i !== 5)) expect(toStoredVendorsJson(b, P), JSON.stringify(b)).toBeNull();
  });

  it("timings: kept when they are a measurement, dropped alone when not — never the verdict beside them", () => {
    const json = toStoredVendorsJson(
      {
        mode: "parallel",
        latencyMs: 812.4,
        verdicts: [
          { provider: "prisma-airs", verdict: "block", latencyMs: 640 },
          { provider: "crowdstrike-aidr", verdict: "allow", latencyMs: -5 },
        ],
      },
      P,
    )!;
    expect(json).toBe('{"m":"parallel","v":[["prisma-airs","block",640],["crowdstrike-aidr","allow"]],"t":812}');
    expect(parseStoredVendors(json, P)).toEqual({
      mode: "parallel",
      latencyMs: 812,
      verdicts: [{ provider: "prisma-airs", verdict: "block", latencyMs: 640 }, { provider: "crowdstrike-aidr", verdict: "allow" }],
    });
    for (const bad of [Number.NaN, 60_001, "300", null]) {
      expect(toStoredVendorsJson({ mode: "parallel", latencyMs: bad, verdicts: [good.verdicts[0]] }, P)).toBe(
        '{"m":"parallel","v":[["prisma-airs","block"]]}',
      );
    }
  });

  it("a stored value that no longer validates reads as not recorded", () => {
    expect(parseStoredVendors('{"m":"parallel","v":[["gone-vendor","block"]]}', P)).toBeNull();
    expect(parseStoredVendors("not json", P)).toBeNull();
    expect(parseStoredVendors(null, P)).toBeNull();
  });

  it("validates expected, redacts and caps topic, and accepts only label-shaped lang", () => {
    const v = validateRedTeamRunPayload(
      validBody({
        results: [
          validResult({ expected: "allow", topic: "Ask about card 4111 1111 1111 1111 please", lang: "Thai + Latin script" }),
          validResult({ attackKey: "rt-02", expected: "yes", topic: "x".repeat(500), lang: "<img src=x>" }),
        ],
      }),
    );
    if (!v.ok) throw new Error(v.error);
    const [a, b] = v.run.results;
    expect(a.expected).toBe("allow");
    expect(a.topic).not.toContain("4111 1111 1111 1111");
    expect(a.lang).toBe("Thai + Latin script");
    expect(b.expected).toBeNull();
    expect(b.topic).toHaveLength(120);
    expect(b.lang).toBeNull();
  });
});

// Design J (migration 0008): the reply check is stored by exactly the rules of `vendors`.
describe("reply verdicts", () => {
  it("are kept as the same compact JSON, and an unknown provider drops the whole value", () => {
    const good = { mode: "parallel", verdicts: [{ provider: "prisma-airs", verdict: "block" }] };
    const ok = validateRedTeamRunPayload(validBody({ results: [validResult({ replyVendors: good })] }));
    expect(ok.ok && ok.run.results[0].replyVendors).toBe('{"m":"parallel","v":[["prisma-airs","block"]]}');
    const bad = validateRedTeamRunPayload(
      validBody({ results: [validResult({ replyVendors: { ...good, verdicts: [{ provider: "evil-corp", verdict: "block" }] } })] }),
    );
    expect(bad.ok && bad.run.results[0].replyVendors).toBeNull();
    const none = validateRedTeamRunPayload(validBody());
    expect(none.ok && none.run.results[0].replyVendors).toBeNull();
  });
});
