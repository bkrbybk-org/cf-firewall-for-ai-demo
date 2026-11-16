// One rule for every vendor's error text (2026-11-16 review, S3; src/publicError.ts vendorErrorText). Before it,
// Prisma AIRS, CrowdStrike AIDR, Cisco and Lakera copied a vendor's `message` / `detail` out verbatim and uncapped,
// so an error that echoed the request would have carried the user's data into the JSON body, the
// `x-external-guardrails` header and the page. Each parser is fed an echo of a test SSN and email here.
import { describe, expect, it } from "vitest";
import { vendorErrorText } from "./publicError";
import { parsePrismaAirsResponse } from "./prismaAirs";
import { parseAidrResponse } from "./crowdstrikeAidr";
import { parseCiscoAidResponse } from "./ciscoAiDefense";
import { parseLakeraResponse } from "./lakeraGuard";
import { parseCatoResponse } from "./catoGuard";
import { parseDatadogResponse } from "./datadogAiGuard";

// 078-05-1120 is the long-void Woolworth sample SSN, a test value.
const ECHO = "invalid value 'my SSN is 078-05-1120'";
const EMAIL = "unknown field for test.user@example.com";

describe("vendorErrorText", () => {
  it("keeps a plain error, on one line, trimmed", () => {
    expect(vendorErrorText("  Invalid API Key\nor OAuth Token \t")).toBe("Invalid API Key or OAuth Token");
  });

  it("refuses three digits in a row or an @: what an echo of a number or an address looks like", () => {
    expect(vendorErrorText(ECHO)).toBeUndefined();
    expect(vendorErrorText(EMAIL)).toBeUndefined();
    expect(vendorErrorText("card 4111 1111")).toBeUndefined();
    expect(vendorErrorText("code 42")).toBe("code 42"); // two digits are fine
  });

  it("caps at 200 characters with an ellipsis, so a cut text says so", () => {
    const out = vendorErrorText("a".repeat(500))!;
    expect(out.length).toBe(200);
    expect(out.endsWith("…")).toBe(true);
  });

  it("is undefined for anything that is not a non-empty string", () => {
    for (const v of [undefined, null, 5, {}, [], "", "   ", "\u0000\u0007"]) expect(vendorErrorText(v)).toBeUndefined();
  });
});

describe("no vendor parser passes an echoed request on", () => {
  const cases: [string, () => string | undefined, string][] = [
    ["Prisma AIRS", () => parsePrismaAirsResponse(400, { error: { message: ECHO } }, 1).error, "Prisma AIRS returned HTTP 400"],
    ["Prisma AIRS (top-level)", () => parsePrismaAirsResponse(400, { message: EMAIL }, 1).error, "Prisma AIRS returned HTTP 400"],
    ["CrowdStrike AIDR", () => parseAidrResponse(400, { errors: [{ message: ECHO }] }, 1).error, "CrowdStrike AIDR returned HTTP 400"],
    ["CrowdStrike AIDR (summary)", () => parseAidrResponse(400, { summary: EMAIL }, 1).error, "CrowdStrike AIDR returned HTTP 400"],
    ["Cisco", () => parseCiscoAidResponse(400, { message: "Bad request", details: [ECHO] }, 1).error, "Cisco AI Defense returned HTTP 400"],
    ["Lakera", () => parseLakeraResponse(400, { message: ECHO, error: "ErrBadBody" }, 1).error, "Lakera Guard returned HTTP 400"],
    ["Cato", () => parseCatoResponse(401, { detail: ECHO }, 1).error, "Cato AI Security returned HTTP 401"],
  ];
  for (const [name, run, fallback] of cases) {
    it(`${name}: the status line, never the echo`, () => {
      const error = run();
      expect(error).toBe(fallback);
      expect(error).not.toContain("1120");
      expect(error).not.toContain("@");
    });
  }

  it("Datadog: the status line and hint, never the echo", () => {
    const error = parseDatadogResponse(403, { errors: [{ detail: ECHO }] }, 1).error!;
    expect(error.startsWith("Datadog AI Guard returned HTTP 403")).toBe(true);
    expect(error).not.toContain("1120");
  });

  it("a plain vendor error still reaches the operator", () => {
    expect(parsePrismaAirsResponse(403, { error: { message: "Invalid API Key or OAuth Token" } }, 1).error).toBe(
      "Invalid API Key or OAuth Token",
    );
    expect(parseLakeraResponse(401, { message: "Unauthorized", code: 401 }, 1).error).toBe("Unauthorized (401)");
    expect(parseLakeraResponse(401, { message: "Missing token", error: "ErrMissingToken" }, 1).error).toBe(
      "Missing token (ErrMissingToken)",
    );
  });
});
