// Tests for the compliance-page evidence resolver (complianceEvidence.ts).
//
// The four cases below are the point of the feature, not incidental coverage:
// an evidence chip that cannot tell "nobody configured analytics" apart from
// "nobody sent traffic" apart from "traffic ran and the count really is zero"
// apart from "the row cap was hit, this number is a floor" is worse than no
// chip at all — it reads as a compliance claim the data doesn't back up.
import { describe, expect, it } from "vitest";
import { resolveEvidence } from "./complianceEvidence";
import type { Analytics, PromptAnalytics } from "./types";

const analytics = (over: Partial<Analytics> = {}): Analytics => ({
  configured: true,
  aiScored: 0,
  totalEvents: 0,
  actions: {},
  piiRequests: 0,
  unsafeTopics: [],
  truncated: false,
  ...over,
});

// AI Security's own tally (server: src/aiSecurityTally.ts). Defaults: unsampled,
// uncapped, classified by expression — override per case.
const ai = (over: Partial<NonNullable<Analytics["aiSecurity"]>> = {}): NonNullable<Analytics["aiSecurity"]> => ({
  blocked: 0,
  logged: 0,
  other: 0,
  rules: [],
  classifiedBy: "expression",
  sampled: false,
  capped: false,
  zoneBlocked: 0,
  ...over,
});

const promptAnalytics = (over: Partial<PromptAnalytics> = {}): PromptAnalytics => ({
  configured: true,
  total: 0,
  redactions: 0,
  ...over,
});

describe("resolveEvidence", () => {
  // 1. Unconfigured — the token/zone id is missing. Must render nothing, so
  // the status has to be distinguishable from every other state.
  describe("unconfigured", () => {
    it("injection-scoring: analytics.configured === false", () => {
      const r = resolveEvidence({ metric: "injection-scoring" }, analytics({ configured: false }), null, 24);
      expect(r.status).toBe("unconfigured");
      expect(r.headline).toBeUndefined();
    });

    it("injection-scoring: analytics is null (fetch failed)", () => {
      const r = resolveEvidence({ metric: "injection-scoring" }, null, null, 24);
      expect(r.status).toBe("unconfigured");
    });

    it("unsafe-topics: analytics.configured === false", () => {
      const r = resolveEvidence({ metric: "unsafe-topics" }, analytics({ configured: false }), null, 24);
      expect(r.status).toBe("unconfigured");
    });

    it("risk-window: analytics.configured === false", () => {
      const r = resolveEvidence({ metric: "risk-window" }, analytics({ configured: false }), null, 24);
      expect(r.status).toBe("unconfigured");
    });

    it("pii-detection: only unconfigured when BOTH sources are unconfigured", () => {
      const bothDown = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ configured: false }),
        promptAnalytics({ configured: false }),
        24,
      );
      expect(bothDown.status).toBe("unconfigured");

      // Edge analytics down but prompt-log up, with real log traffic: still
      // has something to say, so it must not collapse to "unconfigured".
      const edgeDown = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ configured: false }),
        promptAnalytics({ total: 10, redactions: 2 }),
        24,
      );
      expect(edgeDown.status).toBe("ok");
      expect(edgeDown.headline).toContain("2 redactions");
    });
  });

  // 2. No data in window — configured, but nobody generated traffic. Must
  // not read as "0 blocked", which would look like a control that failed.
  describe("no-data (empty window, not a zero)", () => {
    it("injection-scoring: aiScored is 0", () => {
      const r = resolveEvidence({ metric: "injection-scoring" }, analytics({ aiScored: 0 }), null, 24);
      expect(r.status).toBe("no-data");
      expect(r.headline).toBeUndefined();
    });

    it("unsafe-topics: aiScored is 0", () => {
      const r = resolveEvidence({ metric: "unsafe-topics" }, analytics({ aiScored: 0 }), null, 24);
      expect(r.status).toBe("no-data");
    });

    it("risk-window: totalEvents is 0", () => {
      const r = resolveEvidence({ metric: "risk-window" }, analytics({ totalEvents: 0 }), null, 24);
      expect(r.status).toBe("no-data");
    });

    it("pii-detection: both scored and logged are 0", () => {
      const r = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ aiScored: 0 }),
        promptAnalytics({ total: 0 }),
        24,
      );
      expect(r.status).toBe("no-data");
    });
  });

  // 3. Genuine zero — traffic happened, the sub-metric legitimately landed on
  // zero. Must render as "ok" with a real 0 in the headline, not fold into
  // no-data.
  describe("genuine zero (traffic happened, this count is really 0)", () => {
    it("injection-scoring: 500 scored, 0 blocked — and matches in Log mode said as such", () => {
      const r = resolveEvidence(
        { metric: "injection-scoring" },
        analytics({ aiScored: 500, actions: { log: 500 }, aiSecurity: ai({ logged: 450 }) }),
        null,
        24,
      );
      expect(r.status).toBe("ok");
      expect(r.headline).toBe("500 prompts scored · 0 blocked by AI Security rules (450 matched in Log mode)");
    });

    // Open bug #22: the zone's other blocks (Sensitive Paths, geography, CVE rules) were
    // reported under this AI control. They must never reach the headline.
    it("injection-scoring: zone-wide blocks are never AI Security's", () => {
      const r = resolveEvidence(
        { metric: "injection-scoring" },
        analytics({ aiScored: 500, actions: { block: 8318 }, aiSecurity: ai({ blocked: 2608, zoneBlocked: 8318 }) }),
        null,
        24,
      );
      expect(r.headline).toBe("500 prompts scored · 2,608 blocked by AI Security rules");
      expect(r.headline).not.toContain("8,318");
      // A Worker too old to send the tally: no "blocked" half at all, not the zone number.
      const old = resolveEvidence({ metric: "injection-scoring" }, analytics({ aiScored: 5, actions: { block: 8318 } }), null, 24);
      expect(old.headline).toBe("5 prompts scored");
    });

    it("injection-scoring: says how AI Security rules were identified, and when counts are estimates", () => {
      const r = resolveEvidence(
        { metric: "injection-scoring" },
        analytics({ aiScored: 5, aiSecurity: ai({ blocked: 40, classifiedBy: "name", sampled: true }) }),
        null,
        24,
      );
      expect(r.headline).toBe("5 prompts scored · ≈40 blocked by AI Security rules");
      expect(r.note).toContain("“LLM” rule name");
      expect(r.note).toContain("sampled estimates");
    });

    it("unsafe-topics: scored traffic, no topics matched", () => {
      const r = resolveEvidence(
        { metric: "unsafe-topics" },
        analytics({ aiScored: 120, unsafeTopics: [] }),
        null,
        24,
      );
      expect(r.status).toBe("ok");
      expect(r.headline).toBe("0 hits across 0 categories");
    });

    it("pii-detection: scored traffic, genuinely no PII", () => {
      const r = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ aiScored: 80, piiRequests: 0 }),
        promptAnalytics({ total: 30, redactions: 0 }),
        24,
      );
      expect(r.status).toBe("ok");
      expect(r.headline).toBe("0 of 80 scored prompts flagged PII at the edge · 0 redactions in the prompt log");
    });
  });

  // 4. Truncated — the 500-row dataset cap was hit, so counts are a floor.
  // Every number in the headline must read as "at least", never bare.
  describe("truncated (row cap hit — floor, not a total)", () => {
    it("pii-detection: a prompt-log window past retention makes the redaction count a floor", () => {
      const retention = { maxAgeDays: 90, maxRows: 1000, rows: 1000, oldestTs: 1, windowPartial: true };
      const r = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ configured: false }),
        promptAnalytics({ total: 1000, redactions: 40, retention }),
        24,
      );
      expect(r.floor).toBe(true);
      expect(r.headline).toBe("at least 40 redactions in the prompt log");
      const whole = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ configured: false }),
        promptAnalytics({ total: 10, redactions: 4, retention: { ...retention, rows: 10, windowPartial: false } }),
        24,
      );
      expect(whole.floor).toBe(false);
      expect(whole.headline).toBe("4 redactions in the prompt log");
    });

    it("injection-scoring marks the result as a floor and prefixes counts", () => {
      const r = resolveEvidence(
        { metric: "injection-scoring" },
        analytics({ aiScored: 500, actions: { block: 38 }, truncated: true, aiSecurity: ai({ blocked: 38, capped: true }) }),
        null,
        24,
      );
      expect(r.status).toBe("ok");
      expect(r.floor).toBe(true);
      expect(r.headline).toBe("at least 500 prompts scored · at least 38 blocked by AI Security rules");
    });

    it("unsafe-topics marks the result as a floor", () => {
      const r = resolveEvidence(
        { metric: "unsafe-topics" },
        analytics({ aiScored: 500, unsafeTopics: [{ code: "S1", count: 500 }], truncated: true }),
        null,
        24,
      );
      expect(r.floor).toBe(true);
      expect(r.headline).toContain("at least 500 hits");
    });

    it("risk-window marks the result as a floor", () => {
      const r = resolveEvidence(
        { metric: "risk-window" },
        analytics({ totalEvents: 500, truncated: true }),
        null,
        24,
      );
      expect(r.floor).toBe(true);
      expect(r.headline).toBe("at least 500 security events recorded (all WAF rules in the zone)");
    });

    it("pii-detection floor covers only the edge side — PromptAnalytics has no truncated field", () => {
      const r = resolveEvidence(
        { metric: "pii-detection" },
        analytics({ aiScored: 500, piiRequests: 40, truncated: true }),
        promptAnalytics({ total: 30, redactions: 5 }),
        24,
      );
      expect(r.floor).toBe(true);
      expect(r.headline).toBe(
        "at least 40 of at least 500 scored prompts flagged PII at the edge · 5 redactions in the prompt log",
      );
    });

    it("not truncated leaves floor falsy and counts bare", () => {
      const r = resolveEvidence(
        { metric: "injection-scoring" },
        analytics({ aiScored: 12, actions: { block: 1 }, truncated: false, aiSecurity: ai({ blocked: 1 }) }),
        null,
        24,
      );
      expect(r.floor).toBeFalsy();
      expect(r.headline).toBe("12 prompts scored · 1 blocked by AI Security rules");
    });
  });

  describe("window label", () => {
    it("renders hours under a day as '<n>h'", () => {
      expect(resolveEvidence({ metric: "risk-window" }, analytics({ totalEvents: 1 }), null, 1).windowLabel).toBe(
        "last 1h",
      );
    });

    it("renders exact-day multiples as '<n> day(s)'", () => {
      expect(resolveEvidence({ metric: "risk-window" }, analytics({ totalEvents: 1 }), null, 168).windowLabel).toBe(
        "last 7 days",
      );
      expect(resolveEvidence({ metric: "risk-window" }, analytics({ totalEvents: 1 }), null, 24).windowLabel).toBe(
        "last 1 day",
      );
    });
  });
});
