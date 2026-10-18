// Tests for the guardrail verdict log lines (src/guardrailLog.ts). What they pin: one line per vendor
// that ran AND per vendor listed as not run; the outcome vocabulary (an error is never an allow, fail-open
// is its own outcome); and the privacy allowlist — no prompt, reply, error text, raw body, summary or
// policy can reach a line, whatever the result object carries.
import { describe, expect, it } from "vitest";
import {
  AE_SCHEMA,
  VERDICT_EVENT,
  dataPointOf,
  PROMPT_HEADER,
  expectOf,
  logVerdicts,
  promptIdOf,
  sourceOf,
  verdictLines,
  type VerdictLine,
} from "./guardrailLog";
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
      redactionApplied: false,
      incomplete: false,
      decided: false,
      ms: 12,
      status: 200,
      detected: "",
      ray: "8f1c2d3e4a5b6c7d",
      scanId: "scan-1",
      mode: "sequential",
      action: null,
      expect: "",
      promptId: "",
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
    logVerdicts(pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" })] }), "chat", null, { sink: (l) => got.push(l) });
    expect(got).toHaveLength(1);
    expect(typeof got[0]).toBe("object");
    logVerdicts(null, "chat", null, {
      sink: () => {
        throw new Error("must not be called");
      },
    });
    expect(() =>
      logVerdicts(pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" })] }), "chat", null, {
        sink: () => {
          throw new Error("log sink down");
        },
      }),
    ).not.toThrow();
  });
});

// The column positions ARE the schema — src/guardrailAnalytics.ts reads exactly these.
describe("dataPointOf (Analytics Engine)", () => {
  it("puts each field in its fixed column, a per-point index, -1 / 0 for no latency / no status", () => {
    const [ran, skipped] = verdictLines(
      pipe({
        results: [res({ provider: "datadog-ai-guard", outcome: "allow", detectOnly: true, category: "abort", detected: ["jailbreak"], scanId: "e1", httpStatus: 200, latencyMs: 87 })],
        notRun: [{ provider: "cisco-ai-defense", reason: "Not run" }],
        stoppedBy: null,
        direction: "reply",
      }),
      "redteam",
      "abc-SIN",
    );
    expect(dataPointOf(ran)).toEqual({
      indexes: ["abc|reply|datadog-ai-guard"],
      blobs: [AE_SCHEMA, "redteam", "reply", "datadog-ai-guard", "allow", "jailbreak", "abc", "e1", "sequential", "abort", "", ""],
      doubles: [87, 200, 1, 0, 0, 0, 0],
    });
    expect(dataPointOf(skipped)).toEqual({
      indexes: ["abc|reply|cisco-ai-defense"],
      blobs: [AE_SCHEMA, "redteam", "reply", "cisco-ai-defense", "not_run", "", "abc", "", "sequential", "", "", ""],
      doubles: [-1, 0, 0, 0, 0, 0, 0],
    });
  });

  // #13 and #11: blob11 is the Red Team's label, double7 whether this vendor's redaction reached the model.
  it("carries the Red Team label (blob11) and an applied redaction (double7)", () => {
    const p = pipe({
      results: [res({ provider: "cato-ai-security", outcome: "allow", transformed: true, redactionApplied: true })],
      redactionAppliedBy: "cato-ai-security",
    });
    const [l] = verdictLines(p, "redteam", "r1", "benign");
    expect(l).toMatchObject({ expect: "benign", redaction: true, redactionApplied: true });
    expect(dataPointOf(l).blobs![10]).toBe("benign");
    expect(dataPointOf(l).doubles![6]).toBe(1);
    // A label means nothing on a chat turn: nobody curated that prompt.
    expect(verdictLines(p, "chat", "r1", "benign")[0].expect).toBe("");
    // An error is never "redaction applied", whatever it carries.
    const err = pipe({ results: [res({ provider: "cato-ai-security", outcome: "error", redactionApplied: true })] });
    expect(verdictLines(err, "chat", "r1")[0].redactionApplied).toBe(false);
  });

  // #7: no single vote decides a quorum; every vote does, when they stopped the turn — and none when outvoted.
  it("marks every vote as decided in a stopped quorum turn, and none when the block was outvoted", () => {
    const results = [
      res({ provider: "lakera-guard", outcome: "block" }),
      res({ provider: "prisma-airs", outcome: "block" }),
      res({ provider: "cato-ai-security", outcome: "error" }), // fail closed: a vote
      res({ provider: "cisco-ai-defense", outcome: "error", failedOpen: true }), // abstains
      res({ provider: "crowdstrike-aidr", outcome: "allow" }),
    ];
    const stopped = verdictLines(pipe({ mode: "quorum", results, stoppedBy: "lakera-guard" }), "chat", "r");
    expect(stopped.map((l) => l.decided)).toEqual([true, true, true, false, false]);
    expect(stopped[0].mode).toBe("quorum");
    const outvoted = verdictLines(pipe({ mode: "quorum", results: results.slice(0, 1), stoppedBy: null }), "chat", "r");
    expect(outvoted[0]).toMatchObject({ outcome: "block", decided: false });
  });

  // AE samples per index: a repeating index (the vendor) was sampled on prod after 7 points in 15 s.
  it("the index never repeats within a turn, and stays unique with no ray", () => {
    const lines = verdictLines(
      pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" }), res({ provider: "lakera-guard", outcome: "allow" })] }),
      "chat",
      "ray1",
    );
    const idx = lines.map((l) => dataPointOf(l).indexes![0]);
    expect(new Set(idx).size).toBe(idx.length);
    const noRay = verdictLines(pipe({ results: [res({ provider: "prisma-airs", outcome: "allow" })] }), "chat", null)[0];
    expect(dataPointOf(noRay).indexes![0]).not.toBe(dataPointOf(noRay).indexes![0]);
    expect(dataPointOf(noRay, () => "u1").indexes).toEqual(["u1|prompt|prisma-airs"]);
    expect(new TextEncoder().encode(dataPointOf(noRay, () => "x".repeat(36)).indexes![0] as string).length).toBeLessThanOrEqual(96);
  });

  it("logVerdicts writes one data point per line when bound, and a throwing dataset breaks nothing", () => {
    const points: unknown[] = [];
    const ae = { writeDataPoint: (d: unknown) => points.push(d) } as unknown as AnalyticsEngineDataset;
    const p = pipe({ results: [res({ provider: "prisma-airs", outcome: "block" })], notRun: [{ provider: "lakera-guard", reason: "x" }] });
    logVerdicts(p, "chat", null, { ae, sink: () => {} });
    expect(points).toHaveLength(2);
    const down = { writeDataPoint: () => { throw new Error("AE down"); } } as unknown as AnalyticsEngineDataset;
    expect(() => logVerdicts(p, "chat", null, { ae: down, sink: () => {} })).not.toThrow();
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

describe("expectOf", () => {
  it("reads only the exact labels; anything else is unlabelled", () => {
    const req = (v?: string) => new Request("https://x/api/chat", v == null ? {} : { headers: { "x-demo-expect": v } });
    expect(expectOf(req("benign"))).toBe("benign");
    expect(expectOf(req("attack"))).toBe("attack");
    for (const v of [undefined, "", "Benign", "harmless", "benign,attack"]) expect(expectOf(req(v)), String(v)).toBe("");
  });
});

// 2026-10-18: which curated prompt a verdict was for (blob12), so a change can be traced to its prompt.
describe("promptId", () => {
  const p = pipe({ results: [res({ provider: "lakera-guard", outcome: "block" })] });
  it("is kept on curated prompts only, and only in the id shape — never free text", () => {
    expect(verdictLines(p, "scheduled", "sch1", "benign", "han-600")[0].promptId).toBe("han-600");
    expect(verdictLines(p, "redteam", "r1", "attack", "rt-03~base64")[0].promptId).toBe("rt-03~base64");
    expect(verdictLines(p, "redteam", "r1", "benign", "h1a2b3c4d")[0].promptId).toBe("h1a2b3c4d");
    expect(verdictLines(p, "chat", "r1", "", "rt-03")[0].promptId).toBe(""); // a chat turn names no curated prompt
    for (const bad of ["", "RT-03", "rt 03", "rt-03; drop", "a".repeat(40), "-rt", "rt-03~", "ignore previous instructions"]) {
      expect(verdictLines(p, "redteam", "r1", "attack", bad)[0].promptId, bad).toBe("");
    }
  });
  it("goes to blob12, after the label", () => {
    const [l] = verdictLines(p, "scheduled", "sch1", "attack", "rt-01");
    expect(dataPointOf(l).blobs![10]).toBe("attack");
    expect(dataPointOf(l).blobs![11]).toBe("rt-01");
    expect(dataPointOf(l).blobs).toHaveLength(12);
  });
  it("reads the Red Team's header, shape-checked", () => {
    const req = (v?: string) => new Request("https://x/api/chat", { headers: v == null ? {} : { [PROMPT_HEADER]: v } });
    expect(promptIdOf(req("th-ok-07"))).toBe("th-ok-07");
    expect(promptIdOf(req())).toBe("");
    expect(promptIdOf(req("<script>"))).toBe("");
  });
});
