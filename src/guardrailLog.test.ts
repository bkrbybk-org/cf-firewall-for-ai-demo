// Tests for the guardrail verdict log lines (src/guardrailLog.ts). What they pin: one line per vendor
// that ran AND per vendor listed as not run; the outcome vocabulary (an error is never an allow, fail-open
// is its own outcome); and the privacy allowlist — no prompt, reply, error text, raw body, summary or
// policy can reach a line, whatever the result object carries.
import { describe, expect, it } from "vitest";
import { VERDICT_EVENT, logVerdicts, sourceOf, verdictLines, type VerdictLine } from "./guardrailLog";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "./types";

const SECRET = "078-05-1120"; // the void sample SSN — must never appear in a line

function pipe(over: Partial<GuardrailPipelineResult>): GuardrailPipelineResult {
  return { mode: "sequential", guardrailOnly: false, results: [], notRun: [], stoppedBy: null, latencyMs: 0, ...over };
}
function res(over: Partial<ExternalGuardrailResult> & Pick<ExternalGuardrailResult, "provider" | "outcome">): ExternalGuardrailResult {
  return { latencyMs: 12, ...over };
}

describe("verdictLines", () => {
  it("one line per vendor that ran and per vendor not run, in a fixed vocabulary", () => {
    const lines = verdictLines(
      pipe({
        results: [
          res({ provider: "prisma-airs", outcome: "allow", detectOnly: false, scanId: "scan-1", httpStatus: 200 }),
          res({ provider: "lakera-guard", outcome: "block", detected: ["prompt_attack"], httpStatus: 200 }),
        ],
        notRun: [{ provider: "cato-ai-security", reason: "Not run: Check Point Lakera Guard blocked the prompt" }],
        stoppedBy: "lakera-guard",
      }),
      "chat",
      "8f1c2d3e4a5b6c7d-SIN", // the cf-ray header form: the colo suffix is dropped
    );
    expect(lines.map((l) => [l.provider, l.outcome, l.decided])).toEqual([
      ["prisma-airs", "allow", false],
      ["lakera-guard", "block", true],
      ["cato-ai-security", "not_run", false],
    ]);
    expect(lines[0]).toEqual({
      event: VERDICT_EVENT,
      v: 1,
      src: "chat",
      dir: "prompt",
      provider: "prisma-airs",
      outcome: "allow",
      alerts: false,
      redaction: false,
      incomplete: false,
      decided: false,
      ms: 12,
      status: 200,
      detected: "",
      ray: "8f1c2d3e4a5b6c7d",
      scanId: "scan-1",
      mode: "sequential",
      action: null,
    });
    expect(lines[1].detected).toBe("prompt_attack");
    expect(lines[2]).toMatchObject({ ms: null, status: null, detected: "" });
  });

  it("an error is error, or failed_open when the fail mode let the turn go on — never allow", () => {
    const lines = verdictLines(
      pipe({
        results: [
          res({ provider: "crowdstrike-aidr", outcome: "error", error: "x" }),
          res({ provider: "cato-ai-security", outcome: "error", error: "x", failedOpen: true }),
        ],
      }),
      "chat",
      null,
    );
    expect(lines.map((l) => l.outcome)).toEqual(["error", "failed_open"]);
  });

  it("flags describe a verdict: alerts and redaction only on an allow, never on an error", () => {
    const [allow, err] = verdictLines(
      pipe({
        results: [
          res({ provider: "datadog-ai-guard", outcome: "allow", detectOnly: true, transformed: true, category: "deny", detected: ["jailbreak"] }),
          res({ provider: "lakera-guard", outcome: "error", detectOnly: true, transformed: true, incomplete: true, detected: ["pii"] }),
        ],
      }),
      "redteam",
      null,
    );
    expect(allow).toMatchObject({ outcome: "allow", alerts: true, redaction: true, action: "deny", detected: "jailbreak", src: "redteam" });
    expect(err).toMatchObject({ outcome: "error", alerts: false, redaction: false, incomplete: false, detected: "" });
  });

  it("a reply check is marked as one", () => {
    const [l] = verdictLines(pipe({ direction: "reply", results: [res({ provider: "prisma-airs", outcome: "block" })] }), "chat", null);
    expect(l.dir).toBe("reply");
  });

  it("copies no prompt, reply, error text, raw body, summary or policy — and refuses odd names and ids", () => {
    const lines = verdictLines(
      pipe({
        results: [
          res({
            provider: "cato-ai-security",
            outcome: "block",
            error: `quoted ${SECRET}`,
            summary: `the user sent ${SECRET}`,
            policy: `policy for ${SECRET}`,
            category: SECRET,
            detected: ["SSN", `"${SECRET}" detected`, "x".repeat(81)],
            scanId: `id ${SECRET} <script>`,
            raw: { status: 200, body: { detection_message: SECRET }, json: true, truncated: false },
          }),
        ],
      }),
      "chat",
      null,
    );
    expect(lines[0]).toMatchObject({ detected: "SSN", scanId: null, action: null });
    const text = JSON.stringify(lines);
    expect(text).not.toContain("078");
    expect(text).not.toMatch(/quoted|the user sent|policy for|detection_message/);
  });
});

describe("logVerdicts", () => {
  it("writes each line as an object, does nothing without a pipeline, and never throws", () => {
    const got: VerdictLine[] = [];
    logVerdicts(pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" })] }), "chat", null, (l) => got.push(l));
    expect(got).toHaveLength(1);
    expect(typeof got[0]).toBe("object");
    logVerdicts(null, "chat", null, () => {
      throw new Error("must not be called");
    });
    expect(() =>
      logVerdicts(pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" })] }), "chat", null, () => {
        throw new Error("log sink down");
      }),
    ).not.toThrow();
  });
});

describe("sourceOf", () => {
  it("is redteam only for the exact header value; anything else is chat", () => {
    const req = (v?: string) => new Request("https://x/api/chat", { headers: v ? { "x-demo-source": v } : {} });
    expect(sourceOf(req("redteam"))).toBe("redteam");
    // (Header values are whitespace-trimmed by the platform, so "redteam " arrives as "redteam".)
    for (const v of [undefined, "RedTeam", "red team", "chat", "scanner"]) expect(sourceOf(req(v))).toBe("chat");
  });
});
