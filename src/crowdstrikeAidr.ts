// CrowdStrike Falcon AIDR (AI Detection and Response) — AI Guard client.
//
// Every fact here comes from CrowdStrike's own docs and OpenAPI spec
// (aidr-docs.crowdstrike.com/docs/api/aidr, /docs/openapi/aidr_openapi.json)
// and was then checked against the live endpoint — not from memory:
//   - POST {region}/aidr/aiguard/v1/guard_chat_completions, `Authorization:
//     Bearer <collector token>` (the docs' tokens start `pts_`). The spec's own
//     path, `/v1/guard_chat_completions`, is WRONG for these hosts: it is copied
//     from the Pangea-hosted service. Probed 2026-10-03 with a dummy token: the
//     /aidr/aiguard path answers 401 on all three regions, /v1/... answers 404.
//   - Body requires `guard_input` ({messages: [...]}, OpenAI Chat Completions
//     shape); `event_type` "input" selects the input policy.
//   - 200 → Pangea envelope {request_id, status: "Success", summary, result}
//     with `result.blocked` (bool), `result.transformed` (bool — something was
//     redacted), `result.policy`, and `result.detectors.<name>.detected`.
//   - 202 → {status: "Accepted", result: {location, ...}}: the scan went
//     asynchronous. There is no verdict to act on, so it is an ERROR here, never
//     an allow; the operator's fail mode decides.
//   - Errors come in two shapes: the CrowdStrike API gateway's
//     {meta: {trace_id}, errors: [{code, message}]} (seen live: 401 "Unauthorized:
//     Please provide trace-id=…") and the spec's Pangea validation errors
//     {status, summary, result: {errors: [{code, detail}]}}. Both are parsed.
//   - The policy (what is detected, what blocks) is attached to the collector
//     token in the Falcon console, so unlike Prisma AIRS there is no profile to
//     name in the request.

import type { ExternalGuardrailResult } from "./types";

export const AIDR_GUARD_PATH = "/aidr/aiguard/v1/guard_chat_completions";

// The three hosts in the spec's `servers`. As with Prisma AIRS, the Worker only
// ever calls one of these: the token travels in a header, so a typed endpoint
// would let anyone who can reach the config API redirect it.
export const AIDR_REGIONS = [
  { id: "us-1", label: "US-1", url: "https://api.crowdstrike.com" },
  { id: "us-2", label: "US-2", url: "https://api.us-2.crowdstrike.com" },
  { id: "eu-1", label: "EU-1", url: "https://api.eu-1.crowdstrike.com" },
] as const;

// Same budget and reasoning as Prisma AIRS: long enough for a sync scan, short
// enough that a hung provider cannot hold a chat turn hostage.
export const AIDR_TIMEOUT_MS = 5000;

export interface AidrScanInput {
  baseUrl: string;
  token: string;
  prompt: string;
  model?: string;
  spanId?: string; // the Cloudflare ray, so the two consoles can be joined
  timeoutMs?: number;
}

export function buildAidrRequest(input: AidrScanInput): { url: string; init: RequestInit } {
  const body = {
    guard_input: { messages: [{ role: "user", content: input.prompt }] },
    event_type: "input",
    // Only identifying metadata about the APP. Deliberately no `user_id` and no
    // `source_ip`: the prompt already leaves Cloudflare for a third party, and
    // the person behind it does not need to as well.
    app_id: "cf-ai-waf-demo",
    llm_provider: "cloudflare-workers-ai",
    ...(input.model ? { model: input.model } : {}),
    ...(input.spanId ? { span_id: input.spanId } : {}),
  };
  return {
    url: input.baseUrl + AIDR_GUARD_PATH,
    init: {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${input.token}` },
      body: JSON.stringify(body),
    },
  };
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

// A human-readable message from either error shape (see file header).
function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    const gw = Array.isArray(b.errors) ? (b.errors[0] as Record<string, unknown> | undefined) : undefined;
    const fromGateway = str(gw?.message);
    if (fromGateway) return fromGateway;
    const result = b.result as Record<string, unknown> | undefined;
    const pe = Array.isArray(result?.errors) ? (result!.errors as Record<string, unknown>[])[0] : undefined;
    const fromPangea = str(b.summary) ?? (pe ? [str(pe.code), str(pe.detail)].filter(Boolean).join(": ") : undefined);
    if (fromPangea) return fromPangea;
  }
  return `CrowdStrike AIDR returned HTTP ${status}`;
}

// The verdict is `result.blocked` alone — the app never re-derives one from the
// detectors, which would second-guess the operator's AIDR policy. Anything that
// is not a 200 carrying a real boolean there is an error, never an allow.
export function parseAidrResponse(status: number, body: unknown, latencyMs: number): ExternalGuardrailResult {
  const base = { provider: "crowdstrike-aidr" as const, latencyMs, httpStatus: status };
  if (status === 202) {
    return { ...base, outcome: "error", error: "CrowdStrike AIDR answered asynchronously (202) — no verdict in time" };
  }
  if (status < 200 || status >= 300) return { ...base, outcome: "error", error: errorMessage(body, status) };

  const b = (body ?? {}) as Record<string, unknown>;
  const result = (b.result ?? {}) as Record<string, unknown>;
  if (typeof result.blocked !== "boolean") {
    return { ...base, outcome: "error", error: `CrowdStrike AIDR returned no usable verdict (blocked = ${JSON.stringify(result.blocked)})` };
  }
  const detectors = (result.detectors ?? {}) as Record<string, unknown>;
  const detected = Object.keys(detectors).filter(
    (k) => (detectors[k] as { detected?: unknown } | null)?.detected === true,
  );
  const action = result.blocked ? "block" : "allow";
  return {
    ...base,
    outcome: action,
    action,
    detected,
    scanId: str(b.request_id) ?? null,
    reportId: null,
    profileName: null,
    policy: str(result.policy),
    summary: str(b.summary),
    // AIDR may redact the prompt. This app does NOT apply the redaction — the
    // model receives the original prompt — so the UI must say that.
    ...(result.transformed === true ? { transformed: true } : {}),
  };
}

// One synchronous scan. Never throws: network, timeout, bad JSON and non-2xx
// all come back as `outcome: "error"`, so the caller's fail mode decides.
export async function scanPromptWithAidr(input: AidrScanInput, fetchImpl: typeof fetch = fetch): Promise<ExternalGuardrailResult> {
  const { url, init } = buildAidrRequest(input);
  const timeoutMs = input.timeoutMs ?? AIDR_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: errorMessage() falls back to the status
    }
    return parseAidrResponse(res.status, body, Date.now() - started);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `CrowdStrike AIDR did not answer within ${timeoutMs} ms`
        : `Could not reach CrowdStrike AIDR: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "crowdstrike-aidr", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}
