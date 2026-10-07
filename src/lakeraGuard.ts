// Check Point Lakera Guard — Guard API v2 client.
//
// Facts from Lakera's own docs, fetched 2026-10-05 — DOCUMENTED, NOT YET VERIFIED
// against a live payload (PROGRESS.md "Plan: Cisco AI Defense + Check Point Lakera Guard"):
//   - POST {host}/v2/guard, `Authorization: Bearer <API key>`
//     https://docs.lakera.ai/docs/api/guard
//     https://docs.lakera.ai/api-reference/lakera-api/guard/screen-content
//   - Hosts: https://api.lakera.ai (default); the API reference also lists eu., us.
//     and ap-southeast-1. — whether a key works on every host is unverified.
//   - Body: `messages` (OpenAI chat format), `project_id` (selects the project's
//     policy and its Enforce/Detect mode), optional `breakdown` (per-detector
//     results), `payload` (match spans), `metadata` (user/session/IP — none sent).
//   - 200: `flagged` (boolean) is the verdict; `metadata.request_uuid` is the id.
//     **In Detect mode `flagged` is always false** — detections are only logged —
//     and the response's `action` says "detect" vs "enforce".
//   - Errors: 400 / 401 / 429 / 500 with `{error, code, request_id}` per the API
//     reference — but the LIVE 401 (no-key probe, 2026-10-05) is {error: "ErrMissingToken",
//     message, details, request_id}: `error` is a code, `message` the text.
//   - Probed 2026-10-05 with no key: /v2/guard answers 401 on all four hosts, a
//     made-up /v2 path 404 — so the path is real and every listed host is up.
//   - `/v2/guard/results` is a NEW screening with no decision, not a lookup of a
//     past request, so Lakera has no report panel here.
//
// Re-checked 2026-10-08 (API reference + live probes):
//   - Request and response fields unchanged. Breakdown entries also carry `result` (a
//     confidence level, unread) and `message_id` (which message — read in a reply check).
//   - Lakera VALIDATES THE BODY BEFORE THE KEY, and strictly: an unknown field, a wrong
//     type or an unknown role is a 400 with no key at all. Our exact prompt body and our
//     [user, assistant] reply body both got the 401 instead — so both shapes are accepted.
//   - That 400 is text/plain and quotes the offending value ("invalid role: …"), so it is
//     never shown — only the status. A fake key answers ErrInvalidToken, a missing one
//     ErrMissingToken: a dummy-key test proves the key arrived.
//
// Decided with the user (2026-10-05): Detect mode with detectors that fired is
// "allow with alerts" — outcome allow, `detectOnly: true` — never a clean pass and
// never a block.

import type { ExternalGuardrailResult } from "./types";

export const LAKERA_GUARD_PATH = "/v2/guard";

// The only hosts the Worker will ever send the key to — chosen by region, never typed.
export const LAKERA_REGIONS = [
  { id: "global", label: "Global (default)", url: "https://api.lakera.ai" },
  { id: "us", label: "United States", url: "https://us.api.lakera.ai" },
  { id: "eu", label: "Europe", url: "https://eu.api.lakera.ai" },
  { id: "ap-southeast-1", label: "Asia Pacific (Singapore)", url: "https://ap-southeast-1.api.lakera.ai" },
] as const;

export const LAKERA_TIMEOUT_MS = 5000;

export interface LakeraScanInput {
  baseUrl: string;
  apiKey: string;
  projectId: string; // selects the project's policy — and whether it is in Enforce or Detect mode
  prompt: string;
  // The model's reply, for a reply check (design J). Lakera's docs: "the most recent
  // user content is screened as input and the most recent assistant content as output"
  // — so it goes in as the assistant turn. Both are screened; each breakdown entry's
  // `message_id` says which (parseLakeraResponse marks the prompt's). Unverified live.
  response?: string;
  timeoutMs?: number;
}

export function buildLakeraRequest(input: LakeraScanInput): { url: string; init: RequestInit } {
  const body = {
    messages: [
      { role: "user", content: input.prompt },
      ...(input.response != null ? [{ role: "assistant", content: input.response }] : []),
    ],
    project_id: input.projectId,
    // Per-detector results, so the UI can name what fired.
    breakdown: true,
    // Deliberately NO `payload: true`: it returns the matched text spans of the
    // prompt, and this app must not retain prompt content from a third party's
    // reply. Deliberately NO `metadata` either (user / session / IP): the prompt
    // already leaves Cloudflare, the person behind it does not need to as well.
  };
  return {
    url: input.baseUrl + LAKERA_GUARD_PATH,
    init: {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${input.apiKey}` },
      body: JSON.stringify(body),
    },
  };
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

// The API reference documents the error body as {error, code, request_id}; the LIVE
// one differs — probed 2026-10-05 with no key: 401 {"error":"ErrMissingToken",
// "message":"authentication token is missing","details":"","request_id":"…"}. So
// `message` is the human text and `error` is a code; both shapes are read, the
// live one first. 429 is just an error like any other — the operator's fail mode
// decides — but it says so, because "rate limited" tells the operator something a
// bare status does not.
function errorMessage(body: unknown, status: number): string {
  const b = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const message = str(b.message);
  const docCode = typeof b.code === "string" || typeof b.code === "number" ? String(b.code) : undefined;
  const text = message ?? str(b.error);
  const code = message ? (str(b.error) ?? docCode) : docCode;
  const detail = text ? `${text}${code ? ` (${code})` : ""}` : undefined;
  if (status === 429) return `Lakera Guard rate limited (HTTP 429)${detail ? `: ${detail}` : ""}`;
  return detail ?? `Lakera Guard returned HTTP ${status}`;
}

// The verdict is `flagged` alone — the app never re-derives one from the
// breakdown, which would second-guess the operator's Lakera policy. Anything
// that is not a 2xx carrying a real boolean there is an error, never an allow.
export function parseLakeraResponse(
  status: number,
  body: unknown,
  latencyMs: number,
  projectId?: string,
  reply = false,
): ExternalGuardrailResult {
  const base = { provider: "lakera-guard" as const, latencyMs, httpStatus: status };
  if (status < 200 || status >= 300) return { ...base, outcome: "error", error: errorMessage(body, status) };

  const b = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  if (typeof b.flagged !== "boolean") {
    return { ...base, outcome: "error", error: `Lakera Guard returned no usable verdict (flagged = ${JSON.stringify(b.flagged)})` };
  }

  const breakdown = Array.isArray(b.breakdown) ? b.breakdown : [];
  const detected = [
    ...new Set(
      breakdown.flatMap((e) => {
        const entry = e as { detected?: unknown; detector_type?: unknown; message_id?: unknown } | null;
        const type = entry?.detected === true ? str(entry.detector_type) : undefined;
        if (!type) return [];
        // A reply check sends [user prompt, assistant reply], and Lakera screens both.
        // Its API reference gives each breakdown entry a `message_id` (the message's
        // index; documented, not yet seen live), so a detection on message 0 is the
        // PROMPT's and is marked "prompt:" — as Prisma AIRS's is — never shown as
        // something the model said. One with no message_id cannot be attributed and
        // stays unmarked.
        return [reply && entry!.message_id === 0 ? `prompt:${type}` : type];
      }),
    ),
  ];
  const meta = b.metadata && typeof b.metadata === "object" ? (b.metadata as Record<string, unknown>) : {};
  const action = b.flagged ? "block" : "allow";
  return {
    ...base,
    outcome: action,
    action,
    detected,
    scanId: str(meta.request_uuid) ?? null,
    reportId: null,
    profileName: projectId ?? null,
    // In Detect mode Lakera forces `flagged` to false and only logs detections, so
    // a plain "allow" would read as a clean pass. Only an explicit "detect" action
    // with something fired earns the flag — never a missing action, never "enforce"
    // (there `flagged` is already the policy's real answer).
    ...(!b.flagged && b.action === "detect" && detected.length > 0 ? { detectOnly: true } : {}),
  };
}

// One synchronous scan. Never throws: network, timeout, bad JSON and non-2xx
// all come back as `outcome: "error"`, so the caller's fail mode decides.
export async function scanPromptWithLakera(
  input: LakeraScanInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const { url, init } = buildLakeraRequest(input);
  const timeoutMs = input.timeoutMs ?? LAKERA_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: errorMessage() falls back to the status
    }
    return parseLakeraResponse(res.status, body, Date.now() - started, input.projectId, input.response != null);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `Lakera Guard did not answer within ${timeoutMs} ms`
        : `Could not reach Lakera Guard: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "lakera-guard", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}
