// Tests for the Cisco AI Defense Inspection API client.
//
// The request/response fields come from Cisco's DevNet docs and have NOT yet been
// checked against a live payload (see the file header in ciscoAiDefense.ts). The
// cases that matter most are the ones a lenient parser gets wrong: a 2xx with no
// real boolean `is_safe`, and `severity` leaking into the verdict — either would
// let an error or a second opinion read as the policy's decision.
import { describe, expect, it } from "vitest";
import {
  CISCO_AID_REGIONS,
  buildCiscoAidRequest,
  parseCiscoAidResponse,
  scanPromptWithCiscoAid,
} from "./ciscoAiDefense";

const BASE = CISCO_AID_REGIONS[0].url;
const input = { baseUrl: BASE, apiKey: "key-secret-123", prompt: "hello", transactionId: "ray123" };

describe("buildCiscoAidRequest", () => {
  it("posts to /api/v1/inspect/chat on the chosen region with the key header", () => {
    const { url, init } = buildCiscoAidRequest(input);
    expect(url).toBe("https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat");
    expect(buildCiscoAidRequest({ ...input, baseUrl: CISCO_AID_REGIONS[1].url }).url).toBe(
      "https://ap.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat",
    );
    expect(buildCiscoAidRequest({ ...input, baseUrl: CISCO_AID_REGIONS[2].url }).url).toBe(
      "https://eu.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat",
    );
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      "content-type": "application/json",
      accept: "application/json",
      "X-Cisco-AI-Defense-API-Key": "key-secret-123",
    });
  });

  it("sends exactly the prompt and the correlation id, nothing else", () => {
    const body = JSON.parse(buildCiscoAidRequest(input).init.body as string);
    expect(body).toEqual({
      messages: [{ role: "user", content: "hello" }],
      metadata: { client_transaction_id: "ray123" },
    });
  });

  it("omits metadata entirely without a transaction id", () => {
    const body = JSON.parse(buildCiscoAidRequest({ ...input, transactionId: undefined }).init.body as string);
    expect(body).toEqual({ messages: [{ role: "user", content: "hello" }] });
    expect(body).not.toHaveProperty("metadata");
  });

  // The prompt already leaves Cloudflare for a third party; the person behind it does not need to as well.
  it("never sends end-user identity or a config, and never puts the key in the body", () => {
    const raw = buildCiscoAidRequest(input).init.body as string;
    const body = JSON.parse(raw);
    for (const k of ["user", "src_ip", "user_agent", "config"]) {
      expect(body).not.toHaveProperty(k);
      expect(body.metadata).not.toHaveProperty(k);
    }
    expect(raw).not.toContain("key-secret-123");
  });

  it("only exposes the three official regional hosts", () => {
    expect(CISCO_AID_REGIONS.map((r) => r.url)).toEqual([
      "https://us.api.inspect.aidefense.security.cisco.com",
      "https://ap.api.inspect.aidefense.security.cisco.com",
      "https://eu.api.inspect.aidefense.security.cisco.com",
    ]);
    expect(CISCO_AID_REGIONS.map((r) => r.url)).toContain(BASE);
  });
});

describe("parseCiscoAidResponse", () => {
  it("maps an allow; no event_id means no scanId, not an invented one", () => {
    const r = parseCiscoAidResponse(
      200,
      { classifications: ["NONE_VIOLATION"], severity: "NONE_SEVERITY", is_safe: true, rules: [] },
      40,
    );
    expect(r).toMatchObject({
      provider: "cisco-ai-defense",
      outcome: "allow",
      action: "allow",
      scanId: null,
      reportId: null,
      profileName: null,
      httpStatus: 200,
      latencyMs: 40,
    });
    expect(r.detected).toEqual([]);
  });

  it("maps a block with the event id, rule names and explanation", () => {
    const r = parseCiscoAidResponse(
      200,
      {
        is_safe: false,
        classifications: ["SECURITY_VIOLATION"],
        severity: "HIGH",
        explanation: "Prompt injection attempt",
        event_id: "evt-1",
        rules: [
          { rule_name: "Prompt Injection", classification: "SECURITY_VIOLATION" },
          { rule_name: "Jailbreak", classification: "SECURITY_VIOLATION" },
        ],
      },
      10,
    );
    expect(r).toMatchObject({ outcome: "block", action: "block", scanId: "evt-1", summary: "Prompt injection attempt" });
    expect(r.detected).toEqual(["Prompt Injection", "Jailbreak"]);
  });

  it("takes the verdict from `is_safe` alone: severity never overrides it, in either direction", () => {
    const safeButHigh = parseCiscoAidResponse(200, { is_safe: true, severity: "HIGH", classifications: [] }, 1);
    expect(safeButHigh.outcome).toBe("allow");
    expect(safeButHigh.action).toBe("allow");
    const unsafeButNone = parseCiscoAidResponse(
      200,
      { is_safe: false, severity: "NONE_SEVERITY", classifications: ["PRIVACY_VIOLATION"] },
      1,
    );
    expect(unsafeButNone.outcome).toBe("block");
    expect(unsafeButNone.action).toBe("block");
  });

  it("treats a 2xx without a real boolean `is_safe` as an error, never an allow", () => {
    for (const bad of [undefined, null, "false", "true", 0, 1, {}, []]) {
      const body = bad === undefined ? { severity: "NONE_SEVERITY" } : { is_safe: bad, severity: "NONE_SEVERITY" };
      const r = parseCiscoAidResponse(200, body, 1);
      expect(r.outcome, JSON.stringify(bad)).toBe("error");
      expect(r.action).toBeUndefined();
      expect(r.detected).toBeUndefined();
      expect(r.error).toMatch(/no usable verdict \(is_safe = /);
    }
    expect(parseCiscoAidResponse(200, { is_safe: "false" }, 1).error).toContain(`"false"`);
    expect(parseCiscoAidResponse(200, { is_safe: 0 }, 1).error).toContain("is_safe = 0");
    expect(parseCiscoAidResponse(200, { is_safe: null }, 1).error).toContain("is_safe = null");
    expect(parseCiscoAidResponse(200, {}, 1).error).toContain("is_safe = undefined");
    // A body that is not an object at all.
    expect(parseCiscoAidResponse(200, null, 1).outcome).toBe("error");
    expect(parseCiscoAidResponse(200, "ok", 1).outcome).toBe("error");
  });

  it("reads detections from rule names, deduplicated, skipping non-strings", () => {
    const r = parseCiscoAidResponse(
      200,
      {
        is_safe: false,
        classifications: ["SECURITY_VIOLATION"],
        rules: [{ rule_name: "PII" }, { rule_name: "PII" }, { rule_name: 7 }, null, {}, { rule_name: "Toxicity" }],
      },
      1,
    );
    expect(r.detected).toEqual(["PII", "Toxicity"]);
  });

  it("falls back to classifications when no rule is named, deduplicated and without NONE_VIOLATION", () => {
    const r = parseCiscoAidResponse(
      200,
      {
        is_safe: false,
        classifications: ["SECURITY_VIOLATION", "NONE_VIOLATION", "SECURITY_VIOLATION", "PRIVACY_VIOLATION", 3],
        rules: [{ classification: "SECURITY_VIOLATION" }],
      },
      1,
    );
    expect(r.detected).toEqual(["SECURITY_VIOLATION", "PRIVACY_VIOLATION"]);
    // Rules win over classifications: the verdict never comes from the first classification either.
    expect(parseCiscoAidResponse(200, { is_safe: true, classifications: ["SECURITY_VIOLATION"] }, 1).outcome).toBe("allow");
  });

  it("takes event_id only when it is a non-empty string", () => {
    expect(parseCiscoAidResponse(200, { is_safe: false, event_id: "e-9" }, 1).scanId).toBe("e-9");
    expect(parseCiscoAidResponse(200, { is_safe: false, event_id: "" }, 1).scanId).toBeNull();
    expect(parseCiscoAidResponse(200, { is_safe: false, event_id: 12 }, 1).scanId).toBeNull();
    expect(parseCiscoAidResponse(200, { is_safe: false }, 1).scanId).toBeNull();
  });

  it("tolerates unknown extra fields and leaves summary unset when explanation is empty", () => {
    const r = parseCiscoAidResponse(
      200,
      { is_safe: true, explanation: "", attack_technique: "NONE", client_transaction_id: "ray", surprise: { a: 1 } },
      1,
    );
    expect(r.outcome).toBe("allow");
    expect(r.summary).toBeUndefined();
  });

  // The live body, probed 2026-10-05 with no key — richer than the documented {message}.
  it("reads the LIVE error body and keeps its `details`", () => {
    const live = { code: 401, message: "Unauthorized", details: ["failed to validate request: missing api key"] };
    expect(parseCiscoAidResponse(401, live, 5).error).toBe("Unauthorized: failed to validate request: missing api key");
    expect(parseCiscoAidResponse(404, { code: 5, message: "Not Found", details: [] }, 5).error).toBe("Not Found");
  });

  it("reads the documented {message} error body, and falls back to the status", () => {
    expect(parseCiscoAidResponse(401, { message: "Unauthorized" }, 5)).toMatchObject({
      outcome: "error",
      httpStatus: 401,
      error: "Unauthorized",
    });
    expect(parseCiscoAidResponse(500, { message: "Internal error" }, 5).error).toBe("Internal error");
    expect(parseCiscoAidResponse(500, null, 5).error).toBe("Cisco AI Defense returned HTTP 500");
    expect(parseCiscoAidResponse(502, { message: 5 }, 5).error).toBe("Cisco AI Defense returned HTTP 502");
    // A non-2xx never reads as a verdict, even when the body happens to carry is_safe.
    const r = parseCiscoAidResponse(500, { is_safe: true }, 5);
    expect(r.outcome).toBe("error");
    expect(r.detected).toBeUndefined();
  });
});

describe("scanPromptWithCiscoAid", () => {
  it("returns the parsed verdict from a 200", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ is_safe: false, event_id: "e1", rules: [{ rule_name: "PII" }] }), {
        status: 200,
      })) as typeof fetch;
    expect(await scanPromptWithCiscoAid(input, fetchImpl)).toMatchObject({
      outcome: "block",
      scanId: "e1",
      detected: ["PII"],
      httpStatus: 200,
    });
  });

  it("never throws: an unreachable provider is an error result", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const r = await scanPromptWithCiscoAid(input, fetchImpl);
    expect(r).toMatchObject({ provider: "cisco-ai-defense", outcome: "error" });
    expect(r.error).toMatch(/Could not reach Cisco AI Defense: network down/);
  });

  it("gives up after the timeout and says so", async () => {
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      })) as typeof fetch;
    const r = await scanPromptWithCiscoAid({ ...input, timeoutMs: 30 }, fetchImpl);
    expect(r.outcome).toBe("error");
    expect(r.error).toBe("Cisco AI Defense did not answer within 30 ms");
  });

  it("treats a non-JSON body as an error with the status", async () => {
    const fetchImpl = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as typeof fetch;
    expect(await scanPromptWithCiscoAid(input, fetchImpl)).toMatchObject({
      outcome: "error",
      httpStatus: 502,
      error: "Cisco AI Defense returned HTTP 502",
    });
  });

  it("surfaces a 401 {message} from the wire", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ message: "Invalid API key" }), { status: 401 })) as typeof fetch;
    expect(await scanPromptWithCiscoAid(input, fetchImpl)).toMatchObject({
      outcome: "error",
      httpStatus: 401,
      error: "Invalid API key",
    });
  });

  it("sends the built request, with a timeout signal", async () => {
    let seen: { url: string; init?: RequestInit } | undefined;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seen = { url, init };
      return new Response(JSON.stringify({ is_safe: true }), { status: 200 });
    }) as typeof fetch;
    await scanPromptWithCiscoAid(input, fetchImpl);
    expect(seen?.url).toBe(buildCiscoAidRequest(input).url);
    expect(seen?.init?.body).toBe(buildCiscoAidRequest(input).init.body);
    expect(seen?.init?.signal).toBeInstanceOf(AbortSignal);
  });
});
