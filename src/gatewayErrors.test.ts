import { describe, expect, it } from "vitest";
import { explainGatewayError } from "./gatewayErrors";

// The body prod returned on 2026-09-30 with a rejected token (PROGRESS Open bug #1).
const PROD_10000 = '{"code":10000,"message":"Authentication error"}';

describe("explainGatewayError", () => {
  it("turns the real code-10000 body into a message naming the secret, the scopes and the fix", () => {
    const m = explainGatewayError(401, PROD_10000);
    expect(m).toMatch(/^AI Gateway rejected the CF_AIG_TOKEN secret \(HTTP 401, code 10000\)\./);
    expect(m).toContain('"AI Gateway - Read", "AI Gateway - Edit" and "Workers AI - Read"');
    expect(m).toContain("npx wrangler secret put CF_AIG_TOKEN");
  });

  it("finds code 10000 in the v4 envelope too, whatever the status", () => {
    const v4 = '{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}';
    expect(explainGatewayError(403, v4)).toMatch(/rejected the CF_AIG_TOKEN secret \(HTTP 403, code 10000\)/);
  });

  it("treats a bare 401 as auth, but not every 403", () => {
    expect(explainGatewayError(401, "")).toMatch(/rejected the CF_AIG_TOKEN secret \(HTTP 401\)/);
    expect(explainGatewayError(403, '{"errors":[{"code":7003,"message":"No route for the URI"}]}')).toBe(
      '{"errors":[{"code":7003,"message":"No route for the URI"}]}',
    );
  });

  it("never rewrites a Guardrails block, which guardrailsResponse matches by 2016/2017", () => {
    const prompt = '{"errors":[{"code":2016,"message":"Prompt blocked due to security configurations"}]}';
    const resp = '{"errors":[{"code":2017,"message":"Response blocked"}]}';
    expect(explainGatewayError(400, prompt)).toBe(prompt);
    expect(explainGatewayError(401, prompt)).toBe(prompt);
    expect(explainGatewayError(400, resp)).toBe(resp);
  });

  it("passes other errors through, capped, and names the status when there is no body", () => {
    expect(explainGatewayError(500, "")).toBe("AI Gateway returned HTTP 500");
    expect(explainGatewayError(502, "<html>bad gateway</html>")).toBe("<html>bad gateway</html>");
    expect(explainGatewayError(500, "x".repeat(2000)).length).toBe(500);
  });
});
