// Tests for the CrowdStrike AIDR client.
//
// The request/response fields come from CrowdStrike's OpenAPI spec; the gateway
// error body was captured from the live endpoint (it is not in the spec). The
// cases that matter most are the ones a lenient parser gets wrong: a 200 with no
// boolean `blocked`, and a 202 (asynchronous) — both must be errors, never an
// allow, or a malformed or slow response would wave every prompt through.
import { describe, expect, it } from "vitest";
import { AIDR_REGIONS, buildAidrRequest, parseAidrResponse, scanPromptWithAidr } from "./crowdstrikeAidr";

const BASE = AIDR_REGIONS[0].url;
const input = { baseUrl: BASE, token: "pts_abc", prompt: "hello", model: "@cf/x", spanId: "abc123" };

describe("buildAidrRequest", () => {
  it("posts to the /aidr/aiguard path with the collector token as a Bearer", () => {
    const { url, init } = buildAidrRequest(input);
    // Not the spec's /v1/guard_chat_completions: that path is 404 on these hosts.
    expect(url).toBe("https://api.crowdstrike.com/aidr/aiguard/v1/guard_chat_completions");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer pts_abc");
  });

  it("sends the prompt as a chat-completions input event, correlated by span_id", () => {
    const body = JSON.parse(buildAidrRequest(input).init.body as string);
    expect(body.guard_input).toEqual({ messages: [{ role: "user", content: "hello" }] });
    expect(body.event_type).toBe("input");
    expect(body.span_id).toBe("abc123");
    expect(body.model).toBe("@cf/x");
  });

  // The prompt already leaves Cloudflare for a third party; the person behind it does not need to as well.
  it("never sends end-user identity (user_id, source_ip)", () => {
    const body = JSON.parse(buildAidrRequest(input).init.body as string);
    expect(body).not.toHaveProperty("user_id");
    expect(body).not.toHaveProperty("source_ip");
  });

  it("only exposes the three official regional hosts", () => {
    expect(AIDR_REGIONS.map((r) => r.url)).toEqual([
      "https://api.crowdstrike.com",
      "https://api.us-2.crowdstrike.com",
      "https://api.eu-1.crowdstrike.com",
    ]);
  });
});

describe("parseAidrResponse", () => {
  const ok = (result: unknown, extra = {}) => ({ request_id: "prq_1", status: "Success", summary: "s", result, ...extra });

  it("maps an allow", () => {
    const r = parseAidrResponse(200, ok({ blocked: false, transformed: false, policy: "aidr_input_policy", detectors: {} }), 40);
    expect(r).toMatchObject({ outcome: "allow", action: "allow", policy: "aidr_input_policy", scanId: "prq_1", latencyMs: 40 });
    expect(r.detected).toEqual([]);
    expect(r.transformed).toBeUndefined();
  });

  it("maps a block and lists only the detectors that fired", () => {
    const r = parseAidrResponse(
      200,
      ok({ blocked: true, detectors: { malicious_prompt: { detected: true }, competitors: { detected: false }, topic: {} } }),
      10,
    );
    expect(r.outcome).toBe("block");
    expect(r.detected).toEqual(["malicious_prompt"]);
  });

  it("takes the verdict from `blocked` alone, never from the detectors", () => {
    // The operator's policy chose to report-only; the app must not override it.
    const r = parseAidrResponse(200, ok({ blocked: false, detectors: { malicious_prompt: { detected: true } } }), 1);
    expect(r.outcome).toBe("allow");
  });

  it("flags a redaction the app does not apply", () => {
    expect(parseAidrResponse(200, ok({ blocked: false, transformed: true }), 1).transformed).toBe(true);
  });

  it("treats a 200 without a boolean `blocked` as an error, not an allow", () => {
    expect(parseAidrResponse(200, ok({ detectors: {} }), 1).outcome).toBe("error");
    expect(parseAidrResponse(200, ok({ blocked: "false" }), 1).outcome).toBe("error");
    expect(parseAidrResponse(200, null, 1).outcome).toBe("error");
  });

  it("treats 202 (asynchronous) as an error: there is no verdict to act on", () => {
    const r = parseAidrResponse(202, { status: "Accepted", result: { location: "x", ttl_mins: 5, retry_counter: 0 } }, 1);
    expect(r.outcome).toBe("error");
    expect(r.error).toMatch(/asynchronously/);
  });

  it("reads the live gateway's real error body", () => {
    const body = { meta: { trace_id: "t" }, errors: [{ code: 401, message: "Unauthorized: Please provide trace-id='t' to support" }] };
    expect(parseAidrResponse(401, body, 5)).toMatchObject({ outcome: "error", httpStatus: 401, error: "Unauthorized: Please provide trace-id='t' to support" });
  });

  it("also reads the spec's validation errors, and falls back to the status", () => {
    const body = { status: "ValidationError", result: { errors: [{ code: "FieldRequired", detail: "guard_input is required", source: "/" }] } };
    expect(parseAidrResponse(400, body, 1).error).toBe("FieldRequired: guard_input is required");
    expect(parseAidrResponse(400, { summary: "Bad request" }, 1).error).toBe("Bad request");
    expect(parseAidrResponse(500, null, 1).error).toBe("CrowdStrike AIDR returned HTTP 500");
  });
});

describe("scanPromptWithAidr", () => {
  it("never throws: an unreachable provider is an error result", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const r = await scanPromptWithAidr(input, fetchImpl);
    expect(r).toMatchObject({ provider: "crowdstrike-aidr", outcome: "error" });
    expect(r.error).toMatch(/Could not reach CrowdStrike AIDR: network down/);
  });

  it("gives up after the timeout and says so", async () => {
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      })) as typeof fetch;
    const r = await scanPromptWithAidr({ ...input, timeoutMs: 30 }, fetchImpl);
    expect(r.error).toBe("CrowdStrike AIDR did not answer within 30 ms");
  });

  it("treats a non-JSON body as an error with the status", async () => {
    const fetchImpl = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as typeof fetch;
    expect(await scanPromptWithAidr(input, fetchImpl)).toMatchObject({ outcome: "error", httpStatus: 502 });
  });
});
