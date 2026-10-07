// Tests for the external-guardrail view model.
//
// This demo's credibility rests on never overstating what a control did, so these
// pin the places where a card could: crediting the wrong vendor with the stop, turning
// an outage into a verdict, or reading a partial scan as a clean pass.
import { describe, expect, it } from "vitest";
import { pipelineView, vendorTableColumn } from "./guardrailView";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "./types";

const AIRS = "prisma-airs" as const;
const AIDR = "crowdstrike-aidr" as const;

function result(over: Partial<ExternalGuardrailResult> & Pick<ExternalGuardrailResult, "provider">): ExternalGuardrailResult {
  return { outcome: "allow", latencyMs: 100, ...over };
}

function pipe(over: Partial<GuardrailPipelineResult>): GuardrailPipelineResult {
  return {
    mode: "sequential",
    guardrailOnly: false,
    results: [],
    notRun: [],
    stoppedBy: null,
    latencyMs: 250,
    ...over,
  };
}

describe("rule 1: the deciding result is the one stoppedBy names", () => {
  it("marks AIDR decided when it is results[1], and AIRS (results[0], an allow) is not", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIRS, outcome: "allow" }), result({ provider: AIDR, outcome: "block" })],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => [x.provider, x.decided])).toEqual([
      [AIRS, false],
      [AIDR, true],
    ]);
  });

  it("marks nothing decided when stoppedBy is null", () => {
    const v = pipelineView(pipe({ results: [result({ provider: AIRS })] }), "guardrailOnly");
    expect(v.vendors.every((x) => !x.decided)).toBe(true);
  });

  it("parallel with two blocks: both 'independent', none 'decided', whatever stoppedBy names", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [result({ provider: AIDR, outcome: "block" }), result({ provider: AIRS, outcome: "block" })],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => [x.provider, x.marker])).toEqual([
      [AIDR, "independent"],
      [AIRS, "independent"],
    ]);
    // The pipeline's own record is untouched — only what the card shows changes.
    expect(v.vendors.map((x) => x.decided)).toEqual([true, false]);
  });

  it("parallel with one block among allows: that block is 'decided'", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [result({ provider: AIDR, outcome: "allow" }), result({ provider: AIRS, outcome: "block" })],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => [x.provider, x.marker])).toEqual([
      [AIDR, null],
      [AIRS, "decided"],
    ]);
  });

  it("parallel with two blocks never marks a non-blocking vendor", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [
          result({ provider: AIDR, outcome: "block" }),
          result({ provider: AIRS, outcome: "block" }),
          result({ provider: "other-vendor" as never, outcome: "error", error: "timeout" }),
        ],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => x.marker)).toEqual(["independent", "independent", null]);
  });

  it("sequential keeps 'decided' on the stopper", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIDR, outcome: "block" })],
        notRun: [{ provider: AIRS, reason: "an earlier guardrail stopped the turn" }],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => x.marker)).toEqual(["decided", null]);
  });

  it("never marks a notRun entry decided", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIRS, outcome: "block" })],
        notRun: [{ provider: AIDR, reason: "an earlier guardrail stopped the turn" }],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.vendors.find((x) => x.provider === AIDR)?.decided).toBe(false);
  });
});

describe("rule 2: an error is never a verdict", () => {
  const errored = result({
    provider: AIRS,
    outcome: "error",
    detected: ["injection", "dlp"],
    category: "malicious",
    summary: "should not show",
    reportId: "r-1",
    error: "timeout after 3000 ms",
    httpStatus: 504,
  });

  it("is unavailable, with no findings even though `detected` has values", () => {
    const v = pipelineView(pipe({ results: [errored], stoppedBy: AIRS }), "blocked");
    const a = v.vendors[0]!;
    expect(a.state).toBe("unavailable");
    expect(a.stateLabel).toBe("unavailable");
    expect(a.findings).toEqual([]);
  });

  it("does not headline a block, and does not carry a verdict's category, summary or report", () => {
    const v = pipelineView(pipe({ results: [errored], stoppedBy: AIRS }), "blocked");
    expect(v.headline).toBe("Not sent to the model — Prisma AIRS unavailable");
    expect(v.headline).not.toMatch(/blocked by/i);
    const a = v.vendors[0]!;
    expect(a.reportId).toBeNull();
    const labels = a.details.map((d) => d.label);
    expect(labels).not.toContain("category");
    expect(labels).not.toContain("summary");
    expect(a.details).toContainEqual({ label: "error", value: "timeout after 3000 ms", mono: false });
    expect(a.details).toContainEqual({ label: "HTTP", value: "504", mono: true });
    expect(a.notes.join(" ")).toMatch(/not a verdict/i);
    expect(a.notes.join(" ")).toMatch(/fail closed/i);
  });

  it("is failedOpen when failedOpen is true, also without findings", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIDR, outcome: "error", failedOpen: true, detected: ["topic"] })],
        guardrailOnly: true,
      }),
      "guardrailOnly",
    );
    const a = v.vendors[0]!;
    expect(a.state).toBe("failedOpen");
    expect(a.stateLabel).toBe("no verdict (fail open)");
    expect(a.findings).toEqual([]);
    expect(a.notes).toContain("Could not be reached; set to fail open, so this prompt went on without its verdict");
  });

  // Cato's first live fail-open (2026-10-06) answered HTTP 200 in 299 ms and was refused by
  // the parser, yet the card said "Could not be reached". Say only what the result proves.
  it("says why there is no verdict: unreachable, an unreadable answer, or an HTTP error", () => {
    const note = (o: Partial<ExternalGuardrailResult>) =>
      pipelineView(pipe({ results: [result({ provider: AIDR, outcome: "error", failedOpen: true, ...o })] }), "guardrailOnly")
        .vendors[0]!.notes.join(" | ");
    expect(note({})).toContain("Could not be reached; set to fail open");
    expect(note({ httpStatus: 200 })).toContain("Answered, but not with a verdict this app can read; set to fail open");
    expect(note({ httpStatus: 200 })).not.toContain("reached");
    expect(note({ httpStatus: 401 })).toContain("Returned HTTP 401; set to fail open");
  });

  it("names the decided unavailable vendor when another vendor allowed first", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIRS, outcome: "allow" }), result({ provider: AIDR, outcome: "error" })],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.headline).toBe("Not sent to the model — CrowdStrike AIDR unavailable");
  });

  it("does not claim a stop it cannot support when stoppedBy has no result", () => {
    const v = pipelineView(pipe({ results: [], stoppedBy: AIDR }), "blocked");
    expect(v.headline).toBe("Stopped by CrowdStrike AIDR — no verdict shown");
    expect(v.headline).not.toMatch(/blocked by/i);
    expect(v.caveat).toMatch(/no matching block or failure/);
    expect(v.tone).toBe("neutral");
  });
});

describe("rule 3: headline and tone", () => {
  it("counts blocks out of the vendors that ran (notRun excluded) — sequential stop", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIRS, outcome: "block", detected: ["injection"] })],
        notRun: [{ provider: AIDR, reason: "skipped" }],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.headline).toBe("Blocked by 1 of 1 guardrail");
    expect(v.tone).toBe("warning");
  });

  it("parallel with two blocks reads 2 of 2", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [result({ provider: AIRS, outcome: "block" }), result({ provider: AIDR, outcome: "block" })],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.headline).toBe("Blocked by 2 of 2 guardrails");
  });

  it("counts one block of two when the other allowed", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [result({ provider: AIRS, outcome: "allow" }), result({ provider: AIDR, outcome: "block" })],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.headline).toBe("Blocked by 1 of 2 guardrails");
  });

  it("guardrail-only uses its own headline; neutral when everything allowed", () => {
    const v = pipelineView(pipe({ guardrailOnly: true, results: [result({ provider: AIRS })] }), "guardrailOnly");
    expect(v.headline).toBe("Model skipped — guardrail-only mode");
    expect(v.tone).toBe("neutral");
  });

  it("guardrail-only is warning when a guardrail blocked or was unavailable", () => {
    const blocked = pipelineView(
      pipe({ guardrailOnly: true, results: [result({ provider: AIRS, outcome: "block" })], stoppedBy: AIRS }),
      "guardrailOnly",
    );
    const down = pipelineView(
      pipe({ guardrailOnly: true, results: [result({ provider: AIRS, outcome: "error", failedOpen: true })] }),
      "guardrailOnly",
    );
    expect(blocked.tone).toBe("warning");
    expect(blocked.headline).toBe("Model skipped — guardrail-only mode");
    expect(down.tone).toBe("warning");
  });
});

describe("rule 4: subline", () => {
  it("parallel", () => {
    const v = pipelineView(
      pipe({ mode: "parallel", latencyMs: 412, results: [result({ provider: AIRS, outcome: "block" })], stoppedBy: AIRS }),
      "blocked",
    );
    expect(v.subline).toBe("parallel (waited for all) · 412 ms");
  });

  it("sequential", () => {
    const v = pipelineView(
      pipe({ latencyMs: 180, results: [result({ provider: AIRS, outcome: "block" })], stoppedBy: AIRS }),
      "blocked",
    );
    expect(v.subline).toBe("sequential · 180 ms");
  });

  it("guardrail-only appends model not called", () => {
    const v = pipelineView(pipe({ latencyMs: 90, results: [result({ provider: AIRS })] }), "guardrailOnly");
    expect(v.subline).toBe("sequential · 90 ms · model not called");
  });

  it("guardrail-only with zero results says nothing external is enabled", () => {
    const v = pipelineView(pipe({ guardrailOnly: true, results: [] }), "guardrailOnly");
    expect(v.subline).toBe("Passed the edge WAF; no external guardrail is enabled");
    expect(v.vendors).toEqual([]);
    expect(v.why).toBeNull();
    expect(v.tone).toBe("neutral");
  });
});

describe("rule 5: notRun entries", () => {
  it("follow the results, with state notRun, no latency and the reason in details", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIDR, outcome: "block" })],
        notRun: [{ provider: AIRS, reason: "stopped by CrowdStrike AIDR first" }],
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    expect(v.vendors.map((x) => x.provider)).toEqual([AIDR, AIRS]);
    const n = v.vendors[1]!;
    expect(n.state).toBe("notRun");
    expect(n.stateLabel).toBe("did not run");
    expect(n.latencyMs).toBeNull();
    expect(n.findings).toEqual([]);
    expect(n.reportId).toBeNull();
    expect(n.details).toEqual([{ label: "reason", value: "stopped by CrowdStrike AIDR first", mono: false }]);
  });

  it("keeps results in their given order, not configured order", () => {
    const v = pipelineView(
      pipe({ results: [result({ provider: AIDR }), result({ provider: AIRS })], guardrailOnly: true }),
      "guardrailOnly",
    );
    expect(v.vendors.map((x) => x.provider)).toEqual([AIDR, AIRS]);
  });
});

describe("rule 6: honesty notes", () => {
  it("incomplete", () => {
    const v = pipelineView(
      pipe({ results: [result({ provider: AIRS, outcome: "allow", incomplete: true })] }),
      "guardrailOnly",
    );
    const a = v.vendors[0]!;
    expect(a.notes).toContain("At least one detection service timed out — this verdict covers only the checks that ran");
    expect(a.stateLabel).toBe("allow");
    expect(a.partial).toBe(true);
  });

  it("transformed names the vendor and says the original prompt would reach the model", () => {
    const v = pipelineView(
      pipe({ results: [result({ provider: AIDR, outcome: "allow", transformed: true })] }),
      "guardrailOnly",
    );
    const a = v.vendors[0]!;
    expect(a.notes).toContain(
      "Redaction requested by CrowdStrike AIDR was not applied — the model would receive the original prompt",
    );
    expect(a.partial).toBe(true);
  });

  it("Lakera Detect mode is allow with alerts: findings shown, a note, partial — never a clean pass", () => {
    const v = pipelineView(
      pipe({
        results: [
          result({ provider: "lakera-guard", outcome: "allow", detectOnly: true, detected: ["prompt_attack", "pii/email"] }),
        ],
      }),
      "guardrailOnly",
    );
    const a = v.vendors[0]!;
    expect(a.stateLabel).toBe("allow");
    expect(a.partial).toBe(true);
    expect(a.findings).toEqual(["prompt_attack", "pii/email"]);
    expect(a.notes).toContain("Detect mode — Lakera Guard logged 2 detections but its project only alerts, so it did not block");
  });

  // Cato's real allow can carry detections with required_action null: the same "allow
  // with alerts", but said in Cato's terms — it has no project and no Detect mode.
  it("Cato alerts-only is allow with alerts, in Cato's own words", () => {
    const v = pipelineView(
      pipe({ results: [result({ provider: "cato-ai-security", outcome: "allow", detectOnly: true, detected: ["PII Policy", "SSN"] })] }),
      "guardrailOnly",
    );
    const a = v.vendors[0]!;
    expect(a.partial).toBe(true);
    expect(a.notes).toContain("Alerts only — Cato AI Security reported 2 detections but its policy required no action, so it did not block");
    expect(a.notes.join(" ")).not.toMatch(/project|Detect mode/);
  });

  it("detectOnly on an error is ignored — an error is still not a verdict", () => {
    const v = pipelineView(
      pipe({ results: [result({ provider: "lakera-guard", outcome: "error", detectOnly: true, error: "x" })], stoppedBy: "lakera-guard" }),
      "blocked",
    );
    expect(v.vendors[0]!.notes.some((n) => n.startsWith("Detect mode"))).toBe(false);
  });

  it("a clean allow has no notes and is not partial", () => {
    const v = pipelineView(pipe({ results: [result({ provider: AIRS })] }), "guardrailOnly");
    expect(v.vendors[0]!.notes).toEqual([]);
    expect(v.vendors[0]!.partial).toBe(false);
  });
});

describe("findings", () => {
  it("maps detected to labels, in order, deduped, falling back to the raw key", () => {
    const v = pipelineView(
      pipe({
        results: [result({ provider: AIRS, outcome: "block", detected: ["injection", "dlp", "injection", "novel_thing"] })],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.vendors[0]!.findings).toEqual(["Prompt injection", "Sensitive data (DLP)", "novel_thing"]);
  });
});

describe("details and report id", () => {
  it("lists policy, profile, category, the vendor's own id label, report_id and summary", () => {
    const v = pipelineView(
      pipe({
        results: [
          result({
            provider: AIDR,
            outcome: "block",
            policy: "pol-1",
            category: "malicious",
            scanId: "req-9",
            summary: "Malicious prompt was detected",
          }),
          result({ provider: AIRS, outcome: "block", profileName: "prof", scanId: "scan-1", reportId: "rep-1" }),
        ],
        mode: "parallel",
        stoppedBy: AIDR,
      }),
      "blocked",
    );
    const [aidr, airs] = v.vendors;
    expect(aidr!.details.map((d) => [d.label, d.value])).toEqual([
      ["policy", "pol-1"],
      ["category", "malicious"],
      ["request_id", "req-9"],
      ["summary", "Malicious prompt was detected"],
    ]);
    expect(airs!.details.map((d) => [d.label, d.value])).toEqual([
      ["profile", "prof"],
      ["scan_id", "scan-1"],
      ["report_id", "rep-1"],
    ]);
    expect(airs!.reportId).toBe("rep-1");
    expect(aidr!.reportId).toBeNull(); // only Prisma AIRS has a per-request report API
  });
});

describe("rule 7: why — case only is folded", () => {
  it("the same finding in different case is agreement, not a difference", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [
          result({ provider: AIRS, outcome: "block", detected: ["injection"] }), // labelled "Prompt injection"
          result({ provider: "cisco-ai-defense", outcome: "block", detected: ["Prompt Injection"] }),
        ],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.why).toBeNull();
  });

  it("different words stay different, shown in their first spelling", () => {
    const v = pipelineView(
      pipe({
        mode: "parallel",
        results: [
          result({ provider: AIRS, outcome: "block", detected: ["injection", "dlp"] }),
          result({ provider: "cisco-ai-defense", outcome: "block", detected: ["PROMPT INJECTION"] }),
        ],
        stoppedBy: AIRS,
      }),
      "blocked",
    );
    expect(v.why).toBe("Prompt injection — both · Sensitive data (DLP) — Prisma AIRS only");
  });
});

describe("rule 7: why", () => {
  const both = pipe({
    mode: "parallel",
    results: [
      result({ provider: AIDR, outcome: "block", detected: ["confidential_and_pii_entity", "topic", "language"] }),
      result({ provider: AIRS, outcome: "block", detected: ["confidential_and_pii_entity", "dlp"] }),
    ],
    stoppedBy: AIDR,
  });

  it("groups findings by which vendors raised them", () => {
    expect(pipelineView(both, "blocked").why).toBe(
      "Confidential / PII — both · Topic, Language — CrowdStrike AIDR only · Sensitive data (DLP) — Prisma AIRS only",
    );
  });

  it("is null when both found exactly the same thing", () => {
    const same = pipe({
      results: [
        result({ provider: AIDR, outcome: "block", detected: ["injection"] }),
        result({ provider: AIRS, outcome: "block", detected: ["injection"] }),
      ],
      stoppedBy: AIDR,
    });
    expect(pipelineView(same, "blocked").why).toBeNull();
  });

  it("is null when only one vendor found anything", () => {
    const one = pipe({
      results: [
        result({ provider: AIDR, outcome: "allow" }),
        result({ provider: AIRS, outcome: "block", detected: ["injection"] }),
      ],
      stoppedBy: AIRS,
    });
    expect(pipelineView(one, "blocked").why).toBeNull();
  });

  it("ignores an errored vendor's `detected` — an error found nothing", () => {
    const errored = pipe({
      results: [
        result({ provider: AIDR, outcome: "error", detected: ["topic"] }),
        result({ provider: AIRS, outcome: "block", detected: ["injection"] }),
      ],
      stoppedBy: AIRS,
    });
    expect(pipelineView(errored, "blocked").why).toBeNull();
  });
});

// The table layout's only new risk is an empty cell: "found nothing" and "gave no
// verdict" must never look alike, and a guardrail that never ran has no latency.
describe("table layout cells", () => {
  const CATO = "cato-ai-security" as const;
  const view = pipelineView(
    pipe({
      mode: "sequential",
      results: [
        result({ provider: AIDR, outcome: "allow", policy: "Default", scanId: "req_1" }),
        result({ provider: CATO, outcome: "error", failedOpen: true, httpStatus: 200, error: "verdict not recognised" }),
        result({ provider: AIRS, outcome: "block", detected: ["injection"], profileName: "demo-profile", scanId: "scan_9" }),
      ],
      notRun: [{ provider: "lakera-guard", reason: "Not run: Prisma AIRS already stopped the turn" }],
      stoppedBy: AIRS,
    }),
    "blocked",
  );
  const col = (p: string) => vendorTableColumn(view.vendors.find((v) => v.provider === p)!);

  it("says 'none reported' only for a verdict that found nothing", () => {
    expect(col(AIDR).detections).toBe("none reported");
    expect(col(AIRS).detections).toEqual(["Prompt injection"]);
  });

  it("shows a dash, never 'none reported', when there was no verdict — and says why", () => {
    expect(col(CATO).detections).toBe("—");
    expect(col(CATO).notes.join(" ")).toContain("verdict not recognised");
    expect(col(CATO).notes.join(" ")).toContain("Answered, but not with a verdict this app can read");
    expect(col("lakera-guard").detections).toBe("—");
    expect(col("lakera-guard").notes).toContain("Not run: Prisma AIRS already stopped the turn");
  });

  it("has no latency for a guardrail that never ran, rather than 0 ms", () => {
    expect(col("lakera-guard").latency).toBe("—");
    expect(col(AIDR).latency).toBe("100 ms");
  });

  it("names each reference id by the vendor's own field, and the policy or profile", () => {
    expect(col(AIDR).reference).toEqual({ label: "request_id", value: "req_1" });
    expect(col(AIRS).reference).toEqual({ label: "scan_id", value: "scan_9" });
    expect(col(CATO).reference).toBeNull();
    expect(col(AIDR).policy).toBe("Default");
    expect(col(AIRS).policy).toBe("demo-profile");
  });
});

describe("design J: a reply-check card is worded for the reply", () => {
  it("a block withholds the reply — never 'blocked' as if the prompt was", () => {
    const v = pipelineView(pipe({ direction: "reply", stoppedBy: AIRS, results: [result({ provider: AIRS, outcome: "block" })] }), "blocked");
    expect(v.headline).toBe("Reply withheld — blocked by 1 of 1 guardrail");
    expect(v.subline.startsWith("reply check · ")).toBe(true);
  });

  it("a fail-closed error withholds the reply and names the vendor", () => {
    const v = pipelineView(pipe({ direction: "reply", stoppedBy: AIRS, results: [result({ provider: AIRS, outcome: "error", error: "timeout" })] }), "blocked");
    expect(v.headline).toBe("Reply withheld — Prisma AIRS unavailable");
  });

  it("the prompt card is unchanged", () => {
    const v = pipelineView(pipe({ stoppedBy: AIRS, results: [result({ provider: AIRS, outcome: "block" })] }), "blocked");
    expect(v.headline).toBe("Blocked by 1 of 1 guardrail");
    expect(v.subline.startsWith("reply check")).toBe(false);
  });
});
