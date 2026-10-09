// Tests for the Datadog AI Guard client.
//
// Fixtures follow the shape of Datadog's own recorded calls (DataDog/system-tests cassettes, 2026-03):
// `data.id`, `type: "evaluations"`, `action`, `is_blocking_enabled`, `reason`, `tags`, `tag_probs`,
// `sds_findings[]` with `location.path`, `redaction_replacements[]`. The error bodies are the live ones
// (2026-10-09). The cases that matter most are the ones a lenient parser gets wrong: DENY with blocking
// off is allow WITH ALERTS (never a clean pass, never a block Datadog did not enforce); an unknown action
// is an error, never an allow; and nothing Datadog echoes (`reason`, redactions, locations) is copied.
import { describe, expect, it } from "vitest";
import {
  DATADOG_AI_GUARD_PATH,
  DATADOG_REGIONS,
  DATADOG_SERVICE,
  buildDatadogRequest,
  parseDatadogResponse,
  scanPromptWithDatadog,
} from "./datadogAiGuard";

const BASE = DATADOG_REGIONS[0].url;
const input = { baseUrl: BASE, apiKey: "dd-api-0000", appKey: "dd-app-1111", prompt: "hello" };

// The SSN is the long-void Woolworth sample number, a test value.
const SSN_FINDING = {
  rule_display_name: "US Social Security Number Scanner",
  rule_tag: "us_ssn",
  category: "ssn",
  location: { path: "messages[0].content", start_index: 10, end_index_exclusive: 21 },
};
const REASON = "Rule matches: jailbreak, instruction-override — user asked about 078-05-1120";

function evaluation(attrs: Record<string, unknown>) {
  return {
    data: {
      id: "484174a3-f6a3-45fe-876e-168bd52718bf",
      type: "evaluations",
      attributes: { action: "ALLOW", is_blocking_enabled: true, reason: "ok", tags: [], tag_probs: {}, ...attrs },
    },
  };
}

describe("buildDatadogRequest", () => {
  it("posts the prompt alone, with both keys in their headers, to the site's evaluate path", () => {
    const { url, init } = buildDatadogRequest(input);
    expect(url).toBe("https://app.datadoghq.com" + DATADOG_AI_GUARD_PATH);
    expect(DATADOG_AI_GUARD_PATH).toBe("/api/v2/ai-guard/evaluate");
    expect(init.headers).toEqual({ "content-type": "application/json", "dd-api-key": "dd-api-0000", "dd-application-key": "dd-app-1111" });
    // No system prompt, no history, no user or IP: the same single prompt every vendor gets.
    expect(JSON.parse(init.body as string)).toEqual({
      data: { attributes: { messages: [{ role: "user", content: "hello" }], meta: { service: DATADOG_SERVICE } } },
    });
  });

  it("puts the reply LAST for a reply check — AI Guard evaluates the last message", () => {
    const body = JSON.parse(buildDatadogRequest({ ...input, response: "the reply" }).init.body as string);
    expect(body.data.attributes.messages).toEqual([
      { role: "user", content: "hello" },
      { role: "assistant", content: "the reply" },
    ]);
  });
});

describe("parseDatadogResponse — verdicts", () => {
  it("ALLOW with nothing found is a clean allow, with the evaluation id", () => {
    expect(parseDatadogResponse(200, evaluation({}), 7)).toEqual({
      provider: "datadog-ai-guard",
      latencyMs: 7,
      httpStatus: 200,
      outcome: "allow",
      action: "allow",
      detected: [],
      scanId: "484174a3-f6a3-45fe-876e-168bd52718bf",
      reportId: null,
      profileName: null,
    });
  });

  it("DENY or ABORT with blocking on is a block, keeping which one", () => {
    const deny = parseDatadogResponse(200, evaluation({ action: "DENY", tags: ["jailbreak", "instruction-override"] }), 1);
    expect(deny).toMatchObject({ outcome: "block", action: "block", category: "deny", detected: ["jailbreak", "instruction-override"] });
    expect(deny.detectOnly).toBeUndefined();
    const abort = parseDatadogResponse(200, evaluation({ action: "ABORT", tags: ["data-exfiltration"] }), 1);
    expect(abort).toMatchObject({ outcome: "block", category: "abort", detected: ["data-exfiltration"] });
  });

  // The real recording: DENY with is_blocking_enabled false — Datadog's default monitor-only policy.
  it("DENY with blocking OFF is allow with alerts, never a clean pass and never a block", () => {
    const r = parseDatadogResponse(200, evaluation({ action: "DENY", is_blocking_enabled: false, tags: ["jailbreak"] }), 1);
    expect(r).toMatchObject({ outcome: "allow", action: "allow", category: "deny", detectOnly: true, detected: ["jailbreak"] });
    expect(parseDatadogResponse(200, evaluation({ action: "ABORT", is_blocking_enabled: false }), 1)).toMatchObject({
      outcome: "allow",
      category: "abort",
      detectOnly: true,
    });
  });

  // The docs' examples omit the field and say DENY "should be blocked": only an explicit false downgrades.
  it("DENY with is_blocking_enabled missing or not a boolean is still a block", () => {
    const { is_blocking_enabled: _, ...noFlag } = evaluation({ action: "DENY" }).data.attributes;
    expect(parseDatadogResponse(200, { data: { id: "x", attributes: noFlag } }, 1).outcome).toBe("block");
    expect(parseDatadogResponse(200, evaluation({ action: "DENY", is_blocking_enabled: "false" }), 1).outcome).toBe("block");
    expect(parseDatadogResponse(200, evaluation({ action: "DENY", is_blocking_enabled: 0 }), 1).outcome).toBe("block");
  });

  it("ALLOW with sensitive data found is allow with alerts; an offered redaction is 'not applied'", () => {
    const found = parseDatadogResponse(200, evaluation({ sds_findings: [SSN_FINDING] }), 1);
    expect(found).toMatchObject({ outcome: "allow", detectOnly: true, detected: ["us_ssn"] });
    expect(found.transformed).toBeUndefined();
    const redacted = parseDatadogResponse(
      200,
      evaluation({ sds_findings: [SSN_FINDING], redaction_replacements: [{ path: "messages[0].content", value: "[SSN]" }] }),
      1,
    );
    expect(redacted).toMatchObject({ outcome: "allow", detectOnly: true, transformed: true });
  });

  it("an unknown or differently-cased action is an error, never an allow", () => {
    expect(parseDatadogResponse(200, evaluation({ action: "MONITOR" }), 1)).toMatchObject({
      outcome: "error",
      error: expect.stringContaining('action was "MONITOR"'),
    });
    for (const action of ["allow", "", null, 1, ["ALLOW"]]) {
      expect(parseDatadogResponse(200, evaluation({ action }), 1).outcome, JSON.stringify(action)).toBe("error");
    }
    // A long or free-text value is not echoed.
    const r = parseDatadogResponse(200, evaluation({ action: "you asked about 078-05-1120" }), 1);
    expect(r.error).toContain("missing or not a known value");
    expect(r.error).not.toContain("078");
  });

  it("a 2xx with no data.attributes object is an error", () => {
    for (const body of [null, "ALLOW", {}, { data: null }, { data: { attributes: "ALLOW" } }, { action: "ALLOW" }]) {
      expect(parseDatadogResponse(200, body, 1).outcome, JSON.stringify(body)).toBe("error");
    }
  });
});

describe("parseDatadogResponse — privacy allowlist", () => {
  it("never copies reason, redactions, display names or locations — only shape-checked tags", () => {
    const body = evaluation({
      action: "DENY",
      reason: REASON,
      tags: ["jailbreak", "has space", "078-05-1120", 42, "a".repeat(61)],
      tag_probs: { jailbreak: 0.97 },
      sds_findings: [
        SSN_FINDING,
        { ...SSN_FINDING, rule_tag: "ssn 078-05-1120" }, // a custom rule cannot smuggle data through its tag
        { ...SSN_FINDING, rule_tag: "ssn_078051120" }, // ...even in a tag the charset alone would pass
        { rule_tag: "us_ssn" }, // duplicates collapse
      ],
      redaction_replacements: [{ path: "messages[0].content", value: "SSN 078-05-1120 → [SSN]" }],
    });
    const r = parseDatadogResponse(200, body, 1);
    expect(r.detected).toEqual(["jailbreak", "us_ssn"]);
    const text = JSON.stringify(r);
    for (const leaked of ["078", "Rule matches", "Scanner", "start_index", "messages[0]", "0.97"]) {
      expect(text, leaked).not.toContain(leaked);
    }
  });

  it("refuses an evaluation id that is not id-shaped", () => {
    const body = evaluation({});
    body.data.id = "id with spaces <script>";
    expect(parseDatadogResponse(200, body, 1).scanId).toBeNull();
  });
});

describe("parseDatadogResponse — reply attribution", () => {
  it("marks a finding in messages[0] (the prompt) as prompt:, and leaves the reply's as is", () => {
    const body = evaluation({
      sds_findings: [SSN_FINDING, { ...SSN_FINDING, rule_tag: "credit_card", location: { path: "messages[1].content" } }],
    });
    expect(parseDatadogResponse(200, body, 1, true).detected).toEqual(["prompt:us_ssn", "credit_card"]);
    // The prompt check is unchanged: messages[0] IS what it checks.
    expect(parseDatadogResponse(200, body, 1).detected).toEqual(["us_ssn", "credit_card"]);
  });
});

// LIVE bodies, probed 2026-10-09.
describe("parseDatadogResponse — live error bodies", () => {
  it("names 401 and 403 with what each can mean", () => {
    expect(parseDatadogResponse(401, { errors: ["Unauthorized"] }, 1)).toMatchObject({
      outcome: "error",
      httpStatus: 401,
      error: "Datadog AI Guard: Unauthorized (HTTP 401) — check the API key and the Datadog site",
    });
    expect(parseDatadogResponse(403, { errors: ["Forbidden"] }, 1).error).toBe(
      "Datadog AI Guard: Forbidden (HTTP 403) — check the application key, its ai_guard_evaluate scope, and that AI Guard is enabled for the organisation",
    );
    // JSON:API error objects are read too.
    expect(parseDatadogResponse(403, { errors: [{ title: "Forbidden", detail: "Missing scope" }] }, 1).error).toContain("Missing scope");
  });

  it("404 asks whether AI Guard is enabled; 429 says rate limited", () => {
    expect(parseDatadogResponse(404, { errors: ["Not found"] }, 1).error).toMatch(/HTTP 404 — is AI Guard enabled/);
    expect(parseDatadogResponse(429, { errors: ["Too many requests"] }, 1).error).toBe("Datadog AI Guard rate limited the request (HTTP 429)");
  });

  it("any other error's text is never shown — it could quote the prompt", () => {
    const r = parseDatadogResponse(400, { errors: ["invalid content: 'SSN 078-05-1120'"] }, 1);
    expect(r).toMatchObject({ outcome: "error", error: "Datadog AI Guard returned HTTP 400" });
    expect(parseDatadogResponse(502, "<html>bad gateway</html>", 1).error).toBe("Datadog AI Guard returned HTTP 502");
  });
});

describe("scanPromptWithDatadog", () => {
  it("sends the request with a timeout signal and parses the answer", async () => {
    let seen: { url: string; init?: RequestInit } | null = null;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seen = { url, init };
      return Response.json(evaluation({ action: "DENY", tags: ["jailbreak"] }));
    }) as typeof fetch;
    const r = await scanPromptWithDatadog(input, fetchImpl);
    expect(r).toMatchObject({ outcome: "block", detected: ["jailbreak"] });
    expect(seen!.url).toBe("https://app.datadoghq.com/api/v2/ai-guard/evaluate");
    expect(seen!.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("a reply check sends the reply last and marks the prompt's finding", async () => {
    let sent: { data: { attributes: { messages: { role: string }[] } } } | null = null;
    const fetchImpl = (async (_u: string, init?: RequestInit) => {
      sent = JSON.parse(init!.body as string);
      return Response.json(evaluation({ sds_findings: [SSN_FINDING] }));
    }) as typeof fetch;
    const r = await scanPromptWithDatadog({ ...input, response: "the reply" }, fetchImpl);
    expect(sent!.data.attributes.messages.map((m) => m.role)).toEqual(["user", "assistant"]);
    expect(r).toMatchObject({ outcome: "allow", detectOnly: true, detected: ["prompt:us_ssn"] });
  });

  it("network failure, timeout and a non-JSON 200 are errors, never an allow", async () => {
    const down = (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    expect(await scanPromptWithDatadog(input, down)).toMatchObject({
      outcome: "error",
      error: "Could not reach Datadog AI Guard: fetch failed",
    });
    const slow = ((_u: string, init?: RequestInit) =>
      new Promise((_, reject) => init!.signal!.addEventListener("abort", () => reject(init!.signal!.reason)))) as typeof fetch;
    expect(await scanPromptWithDatadog({ ...input, timeoutMs: 30 }, slow)).toMatchObject({
      outcome: "error",
      error: "Datadog AI Guard did not answer within 30 ms",
    });
    const html = (async () => new Response("<html>ok</html>", { status: 200 })) as typeof fetch;
    expect(await scanPromptWithDatadog(input, html)).toMatchObject({ outcome: "error", httpStatus: 200 });
  });
});
