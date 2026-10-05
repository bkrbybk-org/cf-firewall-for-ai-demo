// Tests for the Lakera Guard v2 client.
//
// Fields come from Lakera's own docs; only the error body has been seen live (a no-key
// probe, 2026-10-05 — and it differs from the docs). The cases that matter most are
// the ones a lenient parser gets wrong: a 2xx with no boolean `flagged` must be an
// error, never an allow; and Detect mode (where
// Lakera forces `flagged` false) must surface as "allow with alerts", never as a
// clean pass and never as a block.
import { describe, expect, it } from "vitest";
import {
  LAKERA_GUARD_PATH,
  LAKERA_REGIONS,
  buildLakeraRequest,
  parseLakeraResponse,
  scanPromptWithLakera,
} from "./lakeraGuard";

const BASE = LAKERA_REGIONS[0].url;
const input = { baseUrl: BASE, apiKey: "lak_secret", projectId: "project-1", prompt: "hello" };

const ok = (extra: Record<string, unknown> = {}) => ({
  flagged: false,
  metadata: { request_uuid: "req-1" },
  ...extra,
});
const hit = (type: string, detected = true) => ({ project_id: "project-1", policy_id: "p", detector_id: "d", detector_type: type, detected });

describe("buildLakeraRequest", () => {
  it("posts to /v2/guard with the API key as a Bearer", () => {
    const { url, init } = buildLakeraRequest(input);
    expect(LAKERA_GUARD_PATH).toBe("/v2/guard");
    expect(url).toBe("https://api.lakera.ai/v2/guard");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "content-type": "application/json", authorization: "Bearer lak_secret" });
  });

  it("builds the url from each region's host", () => {
    for (const r of LAKERA_REGIONS) {
      expect(buildLakeraRequest({ ...input, baseUrl: r.url }).url).toBe(`${r.url}/v2/guard`);
    }
  });

  it("sends exactly messages, project_id and breakdown", () => {
    const body = JSON.parse(buildLakeraRequest(input).init.body as string);
    expect(body).toEqual({ messages: [{ role: "user", content: "hello" }], project_id: "project-1", breakdown: true });
  });

  // payload:true returns the matched spans of the prompt; the app must not retain those.
  it("never asks for payload spans and never sends metadata", () => {
    const raw = buildLakeraRequest(input).init.body as string;
    const body = JSON.parse(raw);
    expect(body).not.toHaveProperty("payload");
    expect(body).not.toHaveProperty("metadata");
    expect(raw).not.toContain("lak_secret");
  });
});

describe("LAKERA_REGIONS", () => {
  it("only exposes the documented hosts", () => {
    expect(LAKERA_REGIONS.map((r) => r.url)).toEqual([
      "https://api.lakera.ai",
      "https://us.api.lakera.ai",
      "https://eu.api.lakera.ai",
      "https://ap-southeast-1.api.lakera.ai",
    ]);
  });
});

describe("parseLakeraResponse", () => {
  it("maps flagged:true to a block", () => {
    const r = parseLakeraResponse(200, ok({ flagged: true, action: "enforce", breakdown: [hit("prompt_attack")] }), 12, "project-1");
    expect(r).toMatchObject({
      provider: "lakera-guard",
      outcome: "block",
      action: "block",
      httpStatus: 200,
      latencyMs: 12,
      detected: ["prompt_attack"],
      scanId: "req-1",
      reportId: null,
      profileName: "project-1",
    });
    expect(r.detectOnly).toBeUndefined();
  });

  it("maps a clean scan to an allow, with no detectOnly", () => {
    const r = parseLakeraResponse(200, ok({ action: "enforce", breakdown: [hit("pii", false)] }), 5, "project-1");
    expect(r).toMatchObject({ outcome: "allow", action: "allow", detected: [] });
    expect(r.detectOnly).toBeUndefined();
  });

  it("Detect mode with detections is allow with alerts (detectOnly), not a block", () => {
    const r = parseLakeraResponse(200, ok({ action: "detect", breakdown: [hit("prompt_attack"), hit("pii", false)] }), 5);
    expect(r).toMatchObject({ outcome: "allow", action: "allow", detected: ["prompt_attack"], detectOnly: true });
  });

  it("Detect mode with nothing detected is a plain allow", () => {
    const r = parseLakeraResponse(200, ok({ action: "detect", breakdown: [hit("pii", false)] }), 5);
    expect(r.outcome).toBe("allow");
    expect(r.detectOnly).toBeUndefined();
  });

  it("only action:detect sets detectOnly — not enforce, not a missing action", () => {
    const enforce = parseLakeraResponse(200, ok({ action: "enforce", breakdown: [hit("pii")] }), 5);
    expect(enforce).toMatchObject({ outcome: "allow", detected: ["pii"] });
    expect(enforce.detectOnly).toBeUndefined();
    const none = parseLakeraResponse(200, ok({ breakdown: [hit("pii")] }), 5);
    expect(none.detectOnly).toBeUndefined();
  });

  it("treats a 2xx without a boolean `flagged` as an error, naming the bad value", () => {
    for (const body of [{}, { flagged: "false" }, { flagged: 0 }, { flagged: null }, null, "ok", []]) {
      const r = parseLakeraResponse(200, body, 1);
      expect(r.outcome).toBe("error");
      expect(r.action).toBeUndefined();
      expect(r.detected).toBeUndefined();
      expect(r.error).toMatch(/no usable verdict \(flagged = /);
    }
    expect(parseLakeraResponse(200, { flagged: "false" }, 1).error).toContain('"false"');
    expect(parseLakeraResponse(200, {}, 1).error).toContain("undefined");
  });

  it("dedupes detectors and ignores malformed breakdown entries", () => {
    const r = parseLakeraResponse(
      200,
      ok({
        flagged: true,
        breakdown: [hit("pii"), hit("pii"), hit("prompt_attack"), null, "x", 5, {}, { detected: true }, { detector_type: "link" }, { detected: "true", detector_type: "moderated_content" }, { detected: true, detector_type: "" }],
      }),
      1,
    );
    expect(r.detected).toEqual(["pii", "prompt_attack"]);
  });

  it("tolerates an absent or non-array breakdown", () => {
    expect(parseLakeraResponse(200, { flagged: false }, 1).detected).toEqual([]);
    expect(parseLakeraResponse(200, { flagged: false, breakdown: "nope" }, 1).detected).toEqual([]);
  });

  it("reads the scan id from metadata.request_uuid, else null", () => {
    expect(parseLakeraResponse(200, { flagged: false, metadata: { request_uuid: "abc" } }, 1).scanId).toBe("abc");
    expect(parseLakeraResponse(200, { flagged: false }, 1).scanId).toBeNull();
    expect(parseLakeraResponse(200, { flagged: false, metadata: { request_uuid: "" } }, 1).scanId).toBeNull();
    expect(parseLakeraResponse(200, { flagged: false, metadata: { request_uuid: 7 } }, 1).scanId).toBeNull();
  });

  it("has a null profileName when no project id is passed, and tolerates unknown fields", () => {
    const r = parseLakeraResponse(200, { flagged: false, brand_new_field: { a: 1 } }, 1);
    expect(r.profileName).toBeNull();
    expect(r.outcome).toBe("allow");
  });

  it("reads the documented {error, code, request_id} body for 400/401/500", () => {
    const body = (error: string, code: unknown) => ({ error, code, request_id: "r" });
    expect(parseLakeraResponse(400, body("Invalid request", "invalid_request"), 1)).toMatchObject({
      outcome: "error",
      httpStatus: 400,
      error: "Invalid request (invalid_request)",
    });
    expect(parseLakeraResponse(401, body("Unauthorized", 401), 1).error).toBe("Unauthorized (401)");
    expect(parseLakeraResponse(500, { error: "boom" }, 1).error).toBe("boom");
    expect(parseLakeraResponse(500, null, 1).error).toBe("Lakera Guard returned HTTP 500");
    expect(parseLakeraResponse(400, { error: 5, code: {} }, 1).error).toBe("Lakera Guard returned HTTP 400");
  });

  // The live body, which is NOT the documented one: probed 2026-10-05 with no key.
  it("reads the LIVE error body: `message` is the text, `error` the code", () => {
    const live = {
      error: "ErrMissingToken",
      message: "authentication token is missing",
      details: "",
      request_id: "01a10cb5-8ec0-71fd-ae85-6949abda6f18",
    };
    expect(parseLakeraResponse(401, live, 1)).toMatchObject({
      outcome: "error",
      httpStatus: 401,
      error: "authentication token is missing (ErrMissingToken)",
    });
  });

  it("says rate limited on 429, and it is an error rather than a verdict", () => {
    const r = parseLakeraResponse(429, { error: "Too many requests", code: "rate_limit" }, 1);
    expect(r.outcome).toBe("error");
    expect(r.error).toBe("Lakera Guard rate limited (HTTP 429): Too many requests (rate_limit)");
    expect(parseLakeraResponse(429, null, 1).error).toBe("Lakera Guard rate limited (HTTP 429)");
  });

  it("never reads a verdict out of a non-2xx body", () => {
    expect(parseLakeraResponse(500, { flagged: false }, 1).outcome).toBe("error");
  });
});

describe("scanPromptWithLakera", () => {
  it("sends the request and parses a block", async () => {
    let seen: { url: string; init?: RequestInit } | undefined;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seen = { url, init };
      return new Response(JSON.stringify(ok({ flagged: true, breakdown: [hit("prompt_attack")] })), { status: 200 });
    }) as typeof fetch;
    const r = await scanPromptWithLakera(input, fetchImpl);
    expect(seen?.url).toBe("https://api.lakera.ai/v2/guard");
    expect(seen?.init?.signal).toBeInstanceOf(AbortSignal);
    expect(r).toMatchObject({ outcome: "block", detected: ["prompt_attack"], profileName: "project-1" });
  });

  it("never throws: an unreachable provider is an error result", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const r = await scanPromptWithLakera(input, fetchImpl);
    expect(r).toMatchObject({ provider: "lakera-guard", outcome: "error" });
    expect(r.error).toMatch(/Could not reach Lakera Guard: network down/);
  });

  it("gives up after the timeout and says so", async () => {
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      })) as typeof fetch;
    const r = await scanPromptWithLakera({ ...input, timeoutMs: 30 }, fetchImpl);
    expect(r).toMatchObject({ outcome: "error", error: "Lakera Guard did not answer within 30 ms" });
  });

  it("treats a non-JSON body as an error with the status", async () => {
    const fetchImpl = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as typeof fetch;
    const r = await scanPromptWithLakera(input, fetchImpl);
    expect(r).toMatchObject({ outcome: "error", httpStatus: 502, error: "Lakera Guard returned HTTP 502" });
  });

  it("treats a non-JSON 200 as an error, not an allow", async () => {
    const fetchImpl = (async () => new Response("ok", { status: 200 })) as typeof fetch;
    expect((await scanPromptWithLakera(input, fetchImpl)).outcome).toBe("error");
  });
});
