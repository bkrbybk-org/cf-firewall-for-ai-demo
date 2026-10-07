// Tests for the Prisma AIRS client.
//
// The fixtures are PANW's real shapes: the request/response fields come from
// their OpenAPI spec, and the two error bodies were captured from the live
// endpoint (which does NOT answer in the spec's documented error shape). The
// case that matters most is the one a lenient parser gets wrong: a 200 with no
// usable `action` must be an error, never an allow — otherwise a malformed or
// partial response would wave every prompt through.
import { describe, expect, it } from "vitest";
import {
  buildPrismaAirsRequest,
  parsePrismaAirsResponse,
  PRISMA_AIRS_REGIONS,
  scanPromptWithPrismaAirs,
} from "./prismaAirs";

const BASE = PRISMA_AIRS_REGIONS[0].url;
const input = { baseUrl: BASE, apiKey: "k-123", profileName: "demo-profile", prompt: "hello", model: "@cf/x", trId: "abc123" };

describe("buildPrismaAirsRequest", () => {
  it("posts to the sync scan path with the key in x-pan-token", () => {
    const { url, init } = buildPrismaAirsRequest(input);
    expect(url).toBe(`${BASE}/v1/scan/sync/request`);
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["x-pan-token"]).toBe("k-123");
  });

  it("sends the required ai_profile and contents, and correlates by tr_id", () => {
    const body = JSON.parse(buildPrismaAirsRequest(input).init.body as string);
    expect(body.ai_profile).toEqual({ profile_name: "demo-profile" });
    expect(body.contents).toEqual([{ prompt: "hello" }]);
    expect(body.tr_id).toBe("abc123");
    expect(body.metadata.ai_model).toBe("@cf/x");
  });

  // The prompt already leaves Cloudflare for a third party; the person behind
  // it does not need to as well.
  it("never sends end-user identity (app_user, user_ip)", () => {
    const body = JSON.parse(buildPrismaAirsRequest(input).init.body as string);
    expect(body.metadata).not.toHaveProperty("app_user");
    expect(body.metadata).not.toHaveProperty("user_ip");
  });

  it("only exposes the four official regional hosts", () => {
    for (const r of PRISMA_AIRS_REGIONS) expect(r.url).toMatch(/^https:\/\/service(-[a-z]{2})?\.api\.aisecurity\.paloaltonetworks\.com$/);
  });
});

describe("parsePrismaAirsResponse", () => {
  // Design J: the reply check sends the prompt too, and `action` covers both — so a
  // prompt detection must never read as something the model said.
  it("a reply check lists the reply's detections, and marks any prompt detection as the prompt's", () => {
    const body = { action: "block", response_detected: { dlp: true, toxic_content: false }, prompt_detected: { injection: true } };
    expect(parsePrismaAirsResponse(200, body, 5, true).detected).toEqual(["dlp", "prompt:injection"]);
    // The prompt check is unchanged: response flags are not its business.
    expect(parsePrismaAirsResponse(200, body, 5).detected).toEqual(["injection"]);
  });

  it("a reply check sends the reply in the same contents item as its prompt", () => {
    const b = JSON.parse(buildPrismaAirsRequest({ ...input, response: "the reply" }).init.body as string);
    expect(b.contents).toEqual([{ prompt: "hello", response: "the reply" }]);
    expect(JSON.parse(buildPrismaAirsRequest(input).init.body as string).contents).toEqual([{ prompt: "hello" }]);
  });

  it("maps an allow verdict", () => {
    const r = parsePrismaAirsResponse(200, { action: "allow", category: "benign", scan_id: "s1", report_id: "r1", prompt_detected: {} }, 42);
    expect(r).toMatchObject({ outcome: "allow", action: "allow", category: "benign", scanId: "s1", reportId: "r1", latencyMs: 42 });
    expect(r.detected).toEqual([]);
  });

  it("maps a block verdict and lists only the detections that fired", () => {
    const r = parsePrismaAirsResponse(
      200,
      { action: "block", category: "malicious", prompt_detected: { injection: true, dlp: true, url_cats: false, toxic_content: false } },
      10,
    );
    expect(r.outcome).toBe("block");
    expect(r.detected).toEqual(["injection", "dlp"]);
  });

  it("takes the outcome from `action` alone, never re-deriving it from category or flags", () => {
    // The operator's AI security profile decided "allow" despite a malicious
    // category — that decision is theirs, and the app must not override it.
    const r = parsePrismaAirsResponse(200, { action: "allow", category: "malicious", prompt_detected: { injection: true } }, 1);
    expect(r.outcome).toBe("allow");
  });

  it("treats a 200 without a usable action as an error, not an allow", () => {
    expect(parsePrismaAirsResponse(200, { category: "benign" }, 1).outcome).toBe("error");
    expect(parsePrismaAirsResponse(200, { action: "maybe" }, 1).outcome).toBe("error");
    expect(parsePrismaAirsResponse(200, null, 1).outcome).toBe("error");
  });

  it("flags a verdict whose detection services timed out or errored as incomplete", () => {
    expect(parsePrismaAirsResponse(200, { action: "allow", timeout: true }, 1).incomplete).toBe(true);
    expect(parsePrismaAirsResponse(200, { action: "allow", error: true }, 1).incomplete).toBe(true);
    expect(parsePrismaAirsResponse(200, { action: "allow", timeout: false, error: false }, 1).incomplete).toBeUndefined();
  });

  it("reads the live endpoint's real error bodies", () => {
    const bad = parsePrismaAirsResponse(403, { error: { message: "Invalid API Key or OAuth Token" } }, 5);
    expect(bad).toMatchObject({ outcome: "error", error: "Invalid API Key or OAuth Token", httpStatus: 403 });
    const none = parsePrismaAirsResponse(401, { error: { message: "Not Authenticated" } }, 5);
    expect(none.error).toBe("Not Authenticated");
  });

  it("also reads the spec's documented error shape, and falls back to the status", () => {
    expect(parsePrismaAirsResponse(429, { status_code: 429, message: "Too Many Requests" }, 1).error).toBe("Too Many Requests");
    expect(parsePrismaAirsResponse(500, null, 1).error).toBe("Prisma AIRS returned HTTP 500");
  });
});

describe("scanPromptWithPrismaAirs", () => {
  it("returns the parsed verdict from a real-shaped response", async () => {
    const fetchImpl = (async () => Response.json({ action: "block", category: "malicious", prompt_detected: { dlp: true } })) as typeof fetch;
    const r = await scanPromptWithPrismaAirs(input, fetchImpl);
    expect(r).toMatchObject({ outcome: "block", detected: ["dlp"] });
  });

  it("never throws: an unreachable provider is an error result", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const r = await scanPromptWithPrismaAirs(input, fetchImpl);
    expect(r.outcome).toBe("error");
    expect(r.error).toMatch(/Could not reach Prisma AIRS: network down/);
  });

  it("gives up after the timeout and says so", async () => {
    // Hangs until the request's abort signal fires, like a provider that never answers.
    const fetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      })) as typeof fetch;
    const r = await scanPromptWithPrismaAirs({ ...input, timeoutMs: 30 }, fetchImpl);
    expect(r.outcome).toBe("error");
    expect(r.error).toBe("Prisma AIRS did not answer within 30 ms");
  });

  it("treats a non-JSON body as an error with the status", async () => {
    const fetchImpl = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as typeof fetch;
    const r = await scanPromptWithPrismaAirs(input, fetchImpl);
    expect(r).toMatchObject({ outcome: "error", httpStatus: 502, error: "Prisma AIRS returned HTTP 502" });
  });
});
