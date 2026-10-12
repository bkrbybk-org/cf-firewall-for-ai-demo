// Observed capabilities per vendor (vendor-agnostic Compliance, 2026-10-12). Pinned: exact-name classification only,
// "other" kept, "not seen" never read as "does not have it", "unobservable" never folded into "not seen", and every
// matrix cell pointing at a real control.
import { describe, expect, it } from "vitest";
import { FRAMEWORKS, MATRIX, shortControlId } from "./compliance";
import type { Analytics, GatewayAnalytics, GuardrailVendorStats } from "./types";
import { capabilitiesOf, classifyDetection, observeCloudflare, observeGuardrail, observedFor } from "./vendorCapabilities";

const stats = (over: Partial<GuardrailVendorStats>): GuardrailVendorStats => ({
  provider: "lakera-guard",
  dir: "prompt",
  checked: 0,
  block: 0,
  allow: 0,
  alerts: 0,
  redaction: 0,
  incomplete: 0,
  error: 0,
  failedOpen: 0,
  notRun: 0,
  decided: 0,
  latencyN: 0,
  p50Ms: null,
  p95Ms: null,
  topDetections: [],
  lastTs: null,
  ...over,
});

describe("classifyDetection", () => {
  it("classifies the exact names seen live, and nothing by resemblance", () => {
    expect(classifyDetection("prisma-airs", "injection")).toBe("prompt-injection");
    expect(classifyDetection("prisma-airs", "topic_violation")).toBe("custom-topics");
    expect(classifyDetection("crowdstrike-aidr", "malicious_prompt")).toBe("prompt-injection");
    expect(classifyDetection("crowdstrike-aidr", "confidential_and_pii_entity")).toBe("pii");
    expect(classifyDetection("cisco-ai-defense", "Prompt Injection")).toBe("prompt-injection");
    expect(classifyDetection("lakera-guard", "pii/us_social_security_number")).toBe("pii");
    expect(classifyDetection("lakera-guard", "moderated_content/crime")).toBe("unsafe-topics");
    expect(classifyDetection("cato-ai-security", "cw-ai-app - Personal Identifiers - Personal Identifiers")).toBe("pii");
    expect(classifyDetection("prisma-airs", "prompt:injection")).toBe("prompt-injection"); // a reply check's prompt finding
    // Near misses and unknowns stay unclassified.
    for (const [p, n] of [
      ["prisma-airs", "Injection"],
      ["prisma-airs", "agent"],
      ["crowdstrike-aidr", "language"],
      ["cisco-ai-defense", "prompt injection"],
      ["lakera-guard", "piix/email"],
      ["cato-ai-security", "cw-ai-app - Code Protection - Code Protection"],
      ["cato-ai-security", "Personal Identifiers"],
      ["lakera-guard", "toString"],
    ] as const) {
      expect(classifyDetection(p, n), `${p} ${n}`).toBeNull();
    }
  });
});

describe("observeGuardrail", () => {
  it("seen with its evidence, other names kept, reply checks as output moderation, the rest unobservable", () => {
    const o = observeGuardrail(
      "lakera-guard",
      [
        stats({ checked: 10, detections: [{ name: "prompt_attack", count: 5 }, { name: "pii/email", count: 2 }, { name: "unknown_links", count: 1 }] }),
        stats({ dir: "reply", checked: 4, block: 1, detections: [{ name: "moderated_content/crime", count: 4 }] }),
        stats({ provider: "prisma-airs", checked: 9, detections: [{ name: "dlp", count: 9 }] }), // another vendor: ignored
      ],
      "last 7 days",
    );
    expect(o.capabilities["prompt-injection"]).toEqual({ state: "seen", detail: "5 detections in the last 7 days", evidence: [{ name: "prompt_attack", count: 5 }] });
    expect(o.capabilities.pii.evidence).toEqual([{ name: "pii/email", count: 2 }]);
    // The reply's crime detection counts under unsafe topics AND shows as output moderation's evidence.
    expect(o.capabilities["unsafe-topics"].state).toBe("seen");
    expect(o.capabilities["output-moderation"]).toMatchObject({ state: "seen", detail: "checked 4 model replies in the last 7 days · 1 withheld" });
    expect(o.capabilities["custom-topics"]).toEqual({ state: "not-seen", detail: "none in 14 checks in the last 7 days", evidence: [] });
    expect(o.other).toEqual([{ name: "unknown_links", count: 1 }]);
    for (const c of ["rate-limiting", "logging", "provider-abstraction"] as const) expect(o.capabilities[c].state).toBe("unobservable");
  });

  // Cato cannot check replies: its reply rows are all "not run" — that is not output moderation.
  it("a reply row with only 'not run' entries is not output moderation", () => {
    const o = observeGuardrail("cato-ai-security", [stats({ provider: "cato-ai-security", dir: "reply", checked: 0, notRun: 6 })], "w");
    expect(o.capabilities["output-moderation"]).toEqual({ state: "not-seen", detail: "no reply checked in the w", evidence: [] });
  });

  it("with no checks at all, every detection capability is not seen — and says there were no checks", () => {
    const o = observeGuardrail("datadog-ai-guard", [], "last 7 days");
    expect(o.capabilities.pii).toEqual({ state: "not-seen", detail: "no checks in the last 7 days", evidence: [] });
    expect(o.capabilities["output-moderation"].state).toBe("not-seen");
  });
});

describe("observeCloudflare", () => {
  const edge = {
    configured: true,
    totalEvents: 40,
    aiScored: 12,
    scoreBuckets: [{ label: "1–20", count: 3 }],
    piiCategories: [{ name: "EMAIL_ADDRESS", count: 2 }],
    unsafeTopics: [],
    customTopics: [],
  } as unknown as Analytics;
  const gw = { configured: true, requests: 30, cachedRequests: 0, byModel: [{ model: "m", count: 30, tokensIn: 0, tokensOut: 0, cost: 0 }] } as unknown as GatewayAnalytics;
  it("reads the edge's detections and the gateway logs; Guardrails' verdicts are unobservable here", () => {
    const o = observeCloudflare(edge, gw, "last 7 days");
    expect(o.capabilities["prompt-injection"].state).toBe("seen");
    expect(o.capabilities.pii.evidence).toEqual([{ name: "EMAIL_ADDRESS", count: 2 }]);
    expect(o.capabilities["unsafe-topics"].state).toBe("not-seen");
    expect(o.capabilities["output-moderation"].state).toBe("unobservable");
    expect(o.capabilities["rate-limiting"].state).toBe("not-seen");
    expect(o.capabilities.logging.detail).toBe("30 gateway requests logged in the last 7 days");
    expect(o.capabilities["provider-abstraction"].state).toBe("seen");
  });
  it("unconfigured analytics are unobservable, never 'not seen'", () => {
    const o = observeCloudflare(null, null, "last 7 days");
    expect(o.capabilities["prompt-injection"].state).toBe("unobservable");
    expect(o.capabilities.pii.state).toBe("unobservable");
    expect(o.capabilities["provider-abstraction"].state).toBe("unobservable");
  });
});

describe("the matrix ↔ the framework controls", () => {
  it("every matrix cell names a control that exists in its framework", () => {
    for (const row of MATRIX) {
      for (const [fw, ids] of Object.entries(row.cells)) {
        const controls = FRAMEWORKS.find((f) => f.id === fw)!.controls.map((c) => c.id);
        for (const id of ids) expect(controls, `${row.id} → ${fw} ${id}`).toContain(id);
      }
    }
  });
  it("a control maps back to its capabilities, and is observed only through a seen one", () => {
    expect(capabilitiesOf("nist", "MEASURE 2.7")).toEqual(["prompt-injection"]);
    expect(capabilitiesOf("owasp", "LLM01")).toEqual(["prompt-injection", "unsafe-topics"]);
    const o = observeGuardrail("lakera-guard", [stats({ checked: 1, detections: [{ name: "prompt_attack", count: 1 }] })], "w");
    expect(observedFor(o, "owasp", "LLM01")).toEqual(["prompt-injection"]);
    expect(observedFor(o, "nist", "MEASURE 2.10")).toEqual([]);
  });
});

describe("shortControlId", () => {
  it("shortens only for display, and leaves other ids alone", () => {
    expect(shortControlId("Part 2 · 3.1")).toBe("P2 §3.1");
    expect(shortControlId("Part 1 · 2")).toBe("P1 §2");
    expect(shortControlId("Phase 4")).toBe("Ph.4");
    expect(shortControlId("§4.3 PDPA")).toBe("§4.3");
    expect(shortControlId("MEASURE 2.7")).toBe("MEASURE 2.7");
    expect(shortControlId("AML.T0051")).toBe("AML.T0051");
  });
});
