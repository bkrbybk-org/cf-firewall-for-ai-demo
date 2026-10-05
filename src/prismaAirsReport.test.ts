// Tests for the Prisma AIRS report parser.
//
// The fixture uses the field names from PANW's OpenAPI spec and deliberately
// fills every field that can carry the prompt's own content (snippets, masked
// text, URLs, code blocks, the grounding explanation, byte offsets). The point
// of the parser is that none of it survives — the prompt log redacts PII before
// storing anything, and this panel must not undo that in the browser.
import { describe, expect, it } from "vitest";
import { fetchPrismaAirsReport, parseReportResponse, REPORT_ID_RE } from "./prismaAirsReport";

const SECRET_BITS = [
  "4111 1111 1111 1111", // a DLP snippet
  "CARD-MASKED-XXXX", // masked data
  "https://evil.example/payload", // a URL from the prompt
  "rm -rf /", // an extracted code block
  "the user asked to", // grounding explanation (model text about the prompt)
  "toxic snippet text",
  "ignore previous instructions", // an injection snippet
];

const report = {
  source: "AI-Runtime-API",
  report_id: "R126fe3c6-7a24-4d02-8e26-70966b14d573",
  scan_id: "126fe3c6-7a24-4d02-8e26-70966b14d573",
  transaction_id: "pan_9f5061f9-4d5c-413f-acc4-36a458c5afd7", // PANW's own id — not the tr_id we send (measured)
  detection_results: [
    {
      data_type: "prompt",
      detection_service: "dlp",
      verdict: "malicious",
      action: "block",
      result_detail: {
        dlp_report: {
          dlp_profile_name: "PCI",
          dlp_profile_version: 3,
          data_pattern_rule1_verdict: "MATCHED",
          data_pattern_rule2_verdict: "NOT MATCHED",
          data_pattern_detection_offsets: [
            { name: "Credit Card Number", high_confidence_detections: [[18, 37]], low_confidence_detections: [[1, 2], [3, 4]] },
          ],
        },
        dlp_snippets: { meta: {}, snippets: ["4111 1111 1111 1111"] },
      },
    },
    {
      data_type: "prompt",
      detection_service: "urlf",
      verdict: "malicious",
      action: "allow",
      result_detail: {
        urlf_report: [{ url: "https://evil.example/payload", risk_level: "high", action: "alert", categories: ["malware", "phishing"] }],
      },
    },
    {
      data_type: "prompt",
      detection_service: "malicious_code",
      verdict: "malicious",
      action: "block",
      result_detail: {
        mc_report: {
          all_code_blocks: ["rm -rf /"],
          code_analysis_by_type: [{ file_type: "bash", code_sha256: "abc" }],
          command_injection_report: [{ code_block: "rm -rf /", verdict: "malicious" }],
        },
      },
    },
    {
      data_type: "prompt",
      detection_service: "toxic_content",
      verdict: "malicious",
      action: "block",
      result_detail: { tc_report: { confidence: "high", toxic_categories: ["violence"] }, tc_snippets: ["toxic snippet text"] },
    },
    {
      data_type: "prompt",
      detection_service: "prompt injection",
      verdict: "malicious",
      action: "block",
      result_detail: { pi_report: { verdict: "malicious" }, pi_snippets: ["ignore previous instructions"] },
    },
    {
      data_type: "response",
      detection_service: "contextual grounding",
      verdict: "benign",
      action: "allow",
      result_detail: { cg_report: { status: "completed", category: "grounded", explanation: "the user asked to …" } },
    },
    { data_type: "prompt", verdict: "malicious", action: "block" }, // no service: dropped, cannot be attributed
  ],
};

describe("parseReportResponse", () => {
  const out = parseReportResponse(200, [report], report.report_id);

  it("keeps service, data type, verdict and action for each attributable detection", () => {
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.report).toMatchObject({ provider: "prisma-airs", scanId: report.scan_id, transactionId: "pan_9f5061f9-4d5c-413f-acc4-36a458c5afd7" });
    expect(out.report.detections.map((d) => [d.service, d.dataType, d.verdict, d.action])).toEqual([
      ["dlp", "prompt", "malicious", "block"],
      ["urlf", "prompt", "malicious", "allow"],
      ["malicious_code", "prompt", "malicious", "block"],
      ["toxic_content", "prompt", "malicious", "block"],
      ["prompt injection", "prompt", "malicious", "block"],
      ["contextual grounding", "response", "benign", "allow"],
    ]);
  });

  it("keeps verdict and action apart — a malicious verdict the profile only allows stays visible as such", () => {
    if (!out.ok) throw new Error("expected ok");
    const urlf = out.report.detections.find((d) => d.service === "urlf")!;
    expect([urlf.verdict, urlf.action]).toEqual(["malicious", "allow"]);
  });

  it("extracts names, categories and counts", () => {
    if (!out.ok) throw new Error("expected ok");
    const by = (svc: string) => out.report.detections.find((d) => d.service === svc)!.details;
    expect(by("dlp")).toEqual([
      "DLP profile: PCI (v3)",
      "Rule 1: MATCHED",
      "Rule 2: NOT MATCHED",
      "Pattern: Credit Card Number — 1 high, 2 low confidence",
    ]);
    expect(by("urlf")).toEqual(["1 URL — categories: malware, phishing · risk: high · URL action: alert"]);
    expect(by("malicious_code")).toEqual(["Code types: bash", "Command injection: 1 of 1 code block malicious"]);
    expect(by("toxic_content")).toEqual(["Toxic categories: violence", "Confidence: high"]);
    expect(by("contextual grounding")).toEqual(["Grounding: grounded (completed)"]);
  });

  it("never lets prompt content through: snippets, masked text, URLs, code, explanations, offsets", () => {
    const masked = { ...report, detection_results: [...report.detection_results, { detection_service: "dlp", result_detail: { masked_data: { data: "CARD-MASKED-XXXX" } } }] };
    const json = JSON.stringify(parseReportResponse(200, [masked], report.report_id));
    for (const bit of SECRET_BITS) expect(json, bit).not.toContain(bit);
    expect(json).not.toContain("[18,37]");
    expect(json).not.toContain("code_sha256");
  });

  it("matches the report by id, never just the first element", () => {
    const other = { ...report, report_id: "R-other" };
    const r = parseReportResponse(200, [other], report.report_id);
    expect(r).toMatchObject({ ok: false, pending: true });
  });

  it("an empty array is 'not there yet' — not an error, and not 'nothing detected'", () => {
    const r = parseReportResponse(200, [], report.report_id);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.pending).toBe(true);
  });

  it("reads PANW's real error body", () => {
    expect(parseReportResponse(403, { error: { message: "Invalid API Key or OAuth Token" } }, "R1")).toEqual({
      ok: false,
      error: "Invalid API Key or OAuth Token",
      httpStatus: 403,
    });
  });
});

describe("fetchPrismaAirsReport", () => {
  it("calls only the given host's report path, with the key in x-pan-token and the id encoded", async () => {
    let seen = "";
    let key = "";
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seen = url;
      key = (init?.headers as Record<string, string>)["x-pan-token"];
      return Response.json([report]);
    }) as typeof fetch;
    const r = await fetchPrismaAirsReport({ baseUrl: "https://service-de.api.aisecurity.paloaltonetworks.com", apiKey: "k", reportId: report.report_id }, fetchImpl);
    expect(seen).toBe(`https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/reports?report_ids=${report.report_id}`);
    expect(key).toBe("k");
    expect(r.ok).toBe(true);
  });

  it("refuses anything that is not an id, before any network call", async () => {
    const never = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    for (const id of ["R1&report_ids=R2", "../x", "R1 R2", "", "x".repeat(81)]) {
      expect(REPORT_ID_RE.test(id), id).toBe(false);
      expect(await fetchPrismaAirsReport({ baseUrl: "https://h", apiKey: "k", reportId: id }, never)).toMatchObject({ ok: false });
    }
  });

  it("never throws: a network failure is an error result", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("down");
    }) as typeof fetch;
    const r = await fetchPrismaAirsReport({ baseUrl: "https://h", apiKey: "k", reportId: "R1" }, fetchImpl);
    expect(r).toMatchObject({ ok: false, error: "Could not reach Prisma AIRS: down" });
  });
});
