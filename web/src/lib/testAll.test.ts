import { describe, expect, it } from "vitest";
import { cellFor, countRows, reportText, rowsFor, runKey, skippedText, testPlan, type TestAllOutcome } from "./testAll";
import type { ExternalGuardrailConfig, ExternalGuardrailResult, ExternalGuardrailTestResult } from "./types";

function cfg(over: Partial<ExternalGuardrailConfig>): ExternalGuardrailConfig {
  return {
    provider: "prisma-airs", label: "Palo Alto Networks Prisma AIRS", supported: true, enabled: false, region: "us", endpoint: "",
    regions: [], profileName: "demo", requiresProfile: true, profileLabel: "AI security profile name", keyLabel: "API key",
    vendor: "Palo Alto Networks", failMode: "block", apiKeySet: true, apiKeyLast4: "abcd", updatedAt: null,
    ...over,
  };
}
function res(over: Partial<ExternalGuardrailResult>): ExternalGuardrailResult {
  return { provider: "prisma-airs", outcome: "allow", latencyMs: 120, ...over };
}
function ok(r: Partial<ExternalGuardrailResult>, over: Partial<ExternalGuardrailTestResult> = {}): ExternalGuardrailTestResult {
  return { ok: true, result: res(r), sample: "benign", ...over };
}

describe("testPlan", () => {
  it("runs the four prompt samples per testable vendor, reply samples only where replyCheck is true", () => {
    const plan = testPlan([
      cfg({ provider: "prisma-airs", label: "Prisma", replyCheck: true }),
      cfg({ provider: "lakera-guard", label: "Lakera", replyCheck: false }),
      cfg({ provider: "cato-ai-security", label: "Cato" }), // replyCheck absent
    ]);
    expect(plan.runs.map((r) => `${r.provider}:${r.sample}`)).toEqual([
      "prisma-airs:benign", "prisma-airs:attack", "prisma-airs:pii", "prisma-airs:thai", "prisma-airs:reply-benign", "prisma-airs:reply-pii",
      "lakera-guard:benign", "lakera-guard:attack", "lakera-guard:pii", "lakera-guard:thai",
      "cato-ai-security:benign", "cato-ai-security:attack", "cato-ai-security:pii", "cato-ai-security:thai",
    ]);
    expect(plan.skipped).toEqual([]);
  });

  it("lists every vendor it cannot test, with the reason — none dropped silently", () => {
    const plan = testPlan([
      cfg({ provider: "prisma-airs", label: "Prisma" }),
      cfg({ provider: "lakera-guard", label: "Lakera", apiKeySet: false }),
      cfg({ provider: "crowdstrike-aidr", label: "CrowdStrike", requiresProfile: false, keyLabel: "Collector token", apiKeySet: false }),
      cfg({ provider: "datadog-ai-guard", label: "Datadog", requiresProfile: false, secondKeyLabel: "Application key", secondKeySet: false }),
      cfg({ provider: "cisco-ai-defense", label: "Cisco", profileName: "" }),
      cfg({ provider: "cato-ai-security", label: "Cato", supported: false }),
    ]);
    expect(new Set(plan.runs.map((r) => r.provider))).toEqual(new Set(["prisma-airs"]));
    expect(plan.skipped.map((s) => [s.label, s.reason, s.kind])).toEqual([
      ["Lakera", "no API key saved", "key"],
      ["CrowdStrike", "no collector token saved", "key"],
      ["Datadog", "no application key saved", "key"],
      ["Cisco", "no AI security profile name set", "profile"],
      ["Cato", "not supported yet", "unsupported"],
    ]);
  });

  it("a vendor with two keys is testable only when both are saved; no profile needed when none is required", () => {
    const base = { requiresProfile: false, profileName: "", secondKeyLabel: "Application key" };
    expect(testPlan([cfg({ ...base, secondKeySet: true })]).runs).toHaveLength(4);
    expect(testPlan([cfg({ ...base, secondKeySet: false })]).runs).toHaveLength(0);
    expect(testPlan([cfg({ ...base, secondKeyLabel: null })]).runs).toHaveLength(4);
  });

  it("words the skipped heading so it is true of every entry", () => {
    const only = testPlan([cfg({ apiKeySet: false })]).skipped;
    expect(skippedText(only)).toBe("Skipped (no key saved): Palo Alto Networks Prisma AIRS — no API key saved");
    const mixed = testPlan([cfg({ apiKeySet: false }), cfg({ supported: false, label: "X" })]).skipped;
    expect(skippedText(mixed)).toMatch(/^Skipped \(not fully set up\): /);
  });
});

describe("cellFor", () => {
  it("not run reads em dash everywhere — never blank, never 0 ms", () => {
    for (const o of [undefined, null]) {
      expect(cellFor(o)).toEqual({ verdict: "—", tone: "none", latency: "—", http: "—", detail: "" });
    }
  });

  it("allow and block come from the provider's own verdict, with latency and HTTP status", () => {
    expect(cellFor(ok({ action: "allow", latencyMs: 412, httpStatus: 200 }))).toEqual({
      verdict: "allow", tone: "allow", latency: "412 ms", http: "200", detail: "",
    });
    expect(cellFor(ok({ action: "block", outcome: "block", latencyMs: 90 }))).toMatchObject({ verdict: "block", tone: "block", latency: "90 ms", http: "—" });
    // action wins over outcome; outcome is the fallback
    expect(cellFor(ok({ outcome: "block" })).verdict).toBe("block");
    expect(cellFor(ok({ action: "allow", outcome: "block" })).verdict).toBe("allow");
  });

  it("a real measured 0 ms on an answered test is shown; the HTTP status falls back to the response shape", () => {
    const c = cellFor(ok({ latencyMs: 0 }, { responseShape: { status: 200, shape: {} } }));
    expect(c).toMatchObject({ latency: "0 ms", http: "200" });
  });

  it("appends 'alerts only' and 'redaction requested' and grades such an allow as partial", () => {
    expect(cellFor(ok({ action: "allow", detectOnly: true }))).toMatchObject({ verdict: "allow · alerts only", tone: "partial" });
    expect(cellFor(ok({ action: "allow", transformed: true }))).toMatchObject({ verdict: "allow · redaction requested", tone: "partial" });
    expect(cellFor(ok({ action: "allow", detectOnly: true, transformed: true })).verdict).toBe("allow · alerts only · redaction requested");
    expect(cellFor(ok({ action: "allow", incomplete: true }))).toMatchObject({ verdict: "allow · incomplete", tone: "partial" });
    // a block stays a block
    expect(cellFor(ok({ action: "block", transformed: true }))).toMatchObject({ verdict: "block · redaction requested", tone: "block" });
  });

  it("ok:false is an error with its text — never allow or block, even if the result says allow", () => {
    const c = cellFor({ ok: false, result: res({ outcome: "allow", action: "allow", error: "HTTP 401 unauthorized", httpStatus: 401, latencyMs: 0 }) });
    expect(c).toEqual({ verdict: "error", tone: "error", latency: "—", http: "401", detail: "HTTP 401 unauthorized" });
    expect(cellFor({ ok: false, result: res({ outcome: "error", error: "timeout", latencyMs: 8000 }) })).toMatchObject({
      verdict: "error", tone: "error", latency: "8000 ms",
    });
  });

  it("a fetch / JSON failure or a bare { error } body (403 / 400) is an error", () => {
    expect(cellFor({ error: "Failed to fetch" })).toMatchObject({ verdict: "error", tone: "error", detail: "Failed to fetch", latency: "—", http: "—" });
    expect(cellFor({ error: "Only guardrail admins can do this" })).toMatchObject({ tone: "error", detail: "Only guardrail admins can do this" });
    expect(cellFor({})).toMatchObject({ verdict: "error", tone: "error", detail: "No error text was returned" });
  });

  it("an answer that is ok but carries no usable verdict is still an error", () => {
    expect(cellFor({ ok: true })).toMatchObject({ tone: "error" });
    expect(cellFor(ok({ outcome: "error" }))).toMatchObject({ verdict: "error", tone: "error" });
    expect(cellFor({ ok: true, result: res({ outcome: "maybe" as never }) })).toMatchObject({ tone: "error" });
  });

  it("no error can ever map to an allow-looking or block-looking tone", () => {
    const errors: TestAllOutcome[] = [
      { ok: false, result: res({ action: "allow" }) },
      { ok: false, result: res({ action: "block", outcome: "block" }) },
      { ok: false },
      { error: "x" },
      {},
      { ok: true },
    ];
    for (const e of errors) expect(["error"]).toContain(cellFor(e).tone);
  });

  it("error text is one bounded line", () => {
    const c = cellFor({ error: `line one\nline two ${"x".repeat(500)}` });
    expect(c.detail).not.toMatch(/\n/);
    expect(c.detail.length).toBeLessThanOrEqual(200);
    expect(c.detail.endsWith("…")).toBe(true);
  });
});

describe("rows and report", () => {
  const plan = testPlan([cfg({ label: "Prisma", replyCheck: true }), cfg({ provider: "lakera-guard", label: "Lakera", apiKeySet: false })]);
  const results: Record<string, TestAllOutcome> = {
    [runKey({ provider: "prisma-airs", sample: "benign" })]: ok({ action: "allow", latencyMs: 300, httpStatus: 200 }, { responseShape: { status: 200, shape: { flagged: "boolean" } } }),
    [runKey({ provider: "prisma-airs", sample: "attack" })]: ok({ action: "block", outcome: "block", latencyMs: 250, httpStatus: 200 }),
    [runKey({ provider: "prisma-airs", sample: "pii" })]: { error: "Failed to fetch" },
  };
  const rows = rowsFor(plan.runs, results);

  it("counts answered, errors and not run separately", () => {
    expect(countRows(rows)).toEqual({ total: 6, notRun: 3, answered: 2, errors: 1 });
  });

  it("reports every row, '—' for the ones not run, the error text in the table, and the shape JSON", () => {
    const t = reportText(rows, { skipped: plan.skipped, generatedAt: "2026-10-12T00:00:00Z" });
    expect(t).toContain("Ran 3 of 6 tests: 2 verdicts, 1 errors, 3 not run.");
    expect(t).toContain("Skipped (no key saved): Lakera — no API key saved.");
    expect(t).toContain("| Prisma | Connection works | allow | 300 ms | 200 |");
    expect(t).toContain("| Prisma | Attack prompt | block | 250 ms | 200 |");
    expect(t).toContain("| Prisma | PII prompt | error: Failed to fetch | — | — |");
    expect(t).toContain("| Prisma | Harmless reply | — | — | — |");
    expect(t).toContain('"flagged": "boolean"');
    expect(t).toContain("### Prisma — PII prompt\nNo response shape was returned.");
    expect(t).toContain("### Prisma — Harmless reply\nNot run.");
    expect(t).not.toMatch(/(^|\D)0 ms/);
  });

  it("never copies result.raw, a vendor message, or anything but named fields", () => {
    const leaky = ok(
      { action: "allow", latencyMs: 5, raw: { status: 200, body: { echoed: "SSN 123-45-6789" }, json: true, truncated: false }, summary: "found SSN 123-45-6789" },
      { responseShape: { status: 200, shape: { ok: "boolean" } } },
    );
    const t = reportText(rowsFor(plan.runs.slice(0, 1), { [runKey(plan.runs[0])]: leaky }));
    expect(t).not.toContain("123-45-6789");
    expect(t).not.toContain("echoed");
  });

  it("keeps a pipe or newline in an error from breaking the Markdown table", () => {
    const t = reportText(rowsFor(plan.runs.slice(0, 1), { [runKey(plan.runs[0])]: { error: "a | b\nc" } }));
    expect(t).toContain("| error: a \\| b c |");
  });
});
