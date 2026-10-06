// What the chat says when AI Gateway's REST endpoint refuses a request.
//
// Every gateway send goes through REST (handlers.ts, "AI Gateway routing (REST)"),
// so a rejected CF_AIG_TOKEN surfaces on every one of them — and it used to arrive
// in the chat bubble as Cloudflare's bare JSON, {"code":10000,"message":
// "Authentication error"} (seen on prod 2026-09-30, Open bug #1), which says
// nothing about which token, which scopes, or how to fix it. This turns that one
// case into a message an operator can act on.
//
// Two things it must NOT do:
//   - swallow an AI Gateway Guardrails block. Those also arrive as HTTP errors,
//     and guardrailsResponse() recognises them by code 2016 / 2017 in this same
//     text; a body carrying either code passes through untouched, whatever its status.
//   - call something an auth failure on a guess. Only Cloudflare's own
//     authentication code (10000) or an HTTP 401 qualifies — not every 403, which
//     the gateway also uses for other refusals.

const AUTH_CODE = 10000;
const MAX_RAW = 500;

function codesIn(body: string): number[] {
  try {
    const j = JSON.parse(body) as unknown;
    const out: number[] = [];
    const visit = (v: unknown) => {
      if (Array.isArray(v)) v.forEach(visit);
      else if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        if (typeof o.code === "number") out.push(o.code);
        for (const k of ["errors", "error"]) if (k in o) visit(o[k]);
      }
    };
    visit(j);
    return out;
  } catch {
    return [];
  }
}

export const GATEWAY_AUTH_HINT =
  'It needs an API token with "AI Gateway - Read", "AI Gateway - Edit" and "Workers AI - Read" — not a ' +
  'gateway-scoped "AI Gateway Run" token, which this REST endpoint rejects. Replace it with: ' +
  "npx wrangler secret put CF_AIG_TOKEN (and CF_AIG_TOKEN in .env for wrangler dev).";

export function explainGatewayError(status: number, body: string): string {
  if (/\b201[67]\b/.test(body)) return body; // a Guardrails block: leave it for guardrailsResponse
  const codes = codesIn(body);
  if (codes.includes(AUTH_CODE) || status === 401) {
    const code = codes.includes(AUTH_CODE) ? `, code ${AUTH_CODE}` : "";
    return `AI Gateway rejected the CF_AIG_TOKEN secret (HTTP ${status}${code}). ${GATEWAY_AUTH_HINT}`;
  }
  if (!body) return `AI Gateway returned HTTP ${status}`;
  return body.length > MAX_RAW ? body.slice(0, MAX_RAW - 1) + "…" : body;
}
