// Palo Alto Networks Prisma AIRS — AI Runtime Security "API intercept" client.
//
// Every fact here comes from PANW's own OpenAPI spec
// (github.com/PaloAltoNetworks/pan.dev, openapi-specs/prisma-airs/scan/scan-service_latest.yaml)
// or from calling the real endpoint — not from memory:
//   - POST /v1/scan/sync/request, API key in the `x-pan-token` header.
//   - Body requires `ai_profile` (profile_name or profile_id) and `contents`
//     (a list of {prompt}/{response} items; the last one is scanned).
//   - 200 → ScanResponse: `action` "allow" | "block", `category` "benign" |
//     "malicious", `prompt_detected` booleans, `scan_id`, `report_id`, plus
//     `timeout` / `error` flags when a detection service did not complete.
//   - Errors are NOT the spec's `{status_code, message}`: the live endpoint
//     answers `{"error":{"message":"Invalid API Key or OAuth Token"}}` (403) and
//     `{"error":{"message":"Not Authenticated"}}` (401). Both shapes are parsed.
//   - Sync requests are capped at 2 MB by PANW.

import type { ExternalGuardrailResult } from "./types";

export const PRISMA_AIRS_SCAN_PATH = "/v1/scan/sync/request";

// The four regional hosts PANW publishes in the spec's `servers`. The Worker
// will only ever call one of these: the stored API key is sent in a header, so
// an endpoint the user could type freely would let anyone who can reach the
// config API redirect that key to a host of their choosing.
export const PRISMA_AIRS_REGIONS = [
  { id: "us", label: "United States", url: "https://service.api.aisecurity.paloaltonetworks.com" },
  { id: "eu", label: "Europe (Germany)", url: "https://service-de.api.aisecurity.paloaltonetworks.com" },
  { id: "in", label: "India", url: "https://service-in.api.aisecurity.paloaltonetworks.com" },
  { id: "sg", label: "Singapore", url: "https://service-sg.api.aisecurity.paloaltonetworks.com" },
] as const;

// Long enough for a normal sync scan (measured at 0.3–0.7 s for a rejected key),
// short enough that a hung provider cannot hold a chat turn hostage. What
// happens after a timeout is the operator's fail mode, not this file's call.
export const PRISMA_AIRS_TIMEOUT_MS = 5000;

// prompt_detected keys from the spec, in the order the UI lists them.
export const PRISMA_AIRS_PROMPT_DETECTIONS = [
  "url_cats",
  "dlp",
  "injection",
  "toxic_content",
  "malicious_code",
  "agent",
  "topic_violation",
] as const;

export interface PrismaAirsScanInput {
  baseUrl: string;
  apiKey: string;
  profileName: string;
  prompt: string;
  // The model's reply, for a reply check (design J): sent beside its prompt as one
  // `contents` item — the spec's ScanContent has both, and its result reports
  // `response_detected` apart from `prompt_detected`.
  response?: string;
  model?: string;
  trId?: string; // correlates with the Cloudflare ray, so both consoles can be joined
  timeoutMs?: number;
}

export function buildPrismaAirsRequest(input: PrismaAirsScanInput): { url: string; init: RequestInit } {
  const body = {
    ...(input.trId ? { tr_id: input.trId } : {}),
    ai_profile: { profile_name: input.profileName },
    // Only identifying metadata about the APP. Deliberately no `app_user` and no
    // `user_ip`: the prompt already leaves Cloudflare for a third party, and the
    // person behind it does not need to as well.
    metadata: { app_name: "cf-ai-waf-demo", ...(input.model ? { ai_model: input.model } : {}) },
    contents: [{ prompt: input.prompt, ...(input.response != null ? { response: input.response } : {}) }],
  };
  return {
    url: input.baseUrl + PRISMA_AIRS_SCAN_PATH,
    init: {
      method: "POST",
      headers: { "content-type": "application/json", "x-pan-token": input.apiKey },
      body: JSON.stringify(body),
    },
  };
}

// Pull a human-readable message out of either error shape (see file header).
function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object") {
    const b = body as { error?: unknown; message?: unknown };
    if (b.error && typeof b.error === "object" && typeof (b.error as { message?: unknown }).message === "string") {
      return (b.error as { message: string }).message;
    }
    if (typeof b.message === "string") return b.message;
  }
  return `Prisma AIRS returned HTTP ${status}`;
}

// Turn the provider's HTTP answer into the app's result. `outcome` is decided
// by PANW's `action` alone — the app never re-derives a verdict from
// `category` or the detection flags, which would be second-guessing the
// operator's AI security profile.
export function parsePrismaAirsResponse(
  status: number,
  body: unknown,
  latencyMs: number,
  reply = false,
): ExternalGuardrailResult {
  const base = { provider: "prisma-airs" as const, latencyMs, httpStatus: status };
  if (status < 200 || status >= 300) {
    return { ...base, outcome: "error", error: errorMessage(body, status) };
  }
  const r = (body ?? {}) as Record<string, unknown>;
  const action = r.action;
  if (action !== "allow" && action !== "block") {
    // A 200 without a usable verdict is an error, not an allow: treating it as
    // "allow" would let a malformed response wave every prompt through.
    return { ...base, outcome: "error", error: `Prisma AIRS returned no usable action (got ${JSON.stringify(action)})` };
  }
  const trueKeys = (v: unknown) => {
    const flags = (v && typeof v === "object" ? v : {}) as Record<string, unknown>;
    return Object.keys(flags).filter((k) => flags[k] === true);
  };
  // A reply check sends the prompt too, and `action` covers both. So the reply's own
  // detections come first, and any prompt detection is kept but marked "prompt:" — a
  // reply block caused by the prompt must not read as something the model said.
  const detected = reply
    ? [...trueKeys(r.response_detected), ...trueKeys(r.prompt_detected).map((k) => `prompt:${k}`)]
    : trueKeys(r.prompt_detected);
  return {
    ...base,
    outcome: action,
    action,
    category: typeof r.category === "string" ? r.category : undefined,
    detected,
    scanId: typeof r.scan_id === "string" ? r.scan_id : null,
    reportId: typeof r.report_id === "string" ? r.report_id : null,
    profileName: typeof r.profile_name === "string" ? r.profile_name : null,
    ...(r.timeout === true || r.error === true ? { incomplete: true } : {}),
  };
}

// One synchronous scan. Never throws: every failure — network, timeout, bad
// JSON, non-2xx — comes back as an `outcome: "error"` result, so the caller's
// fail mode is the only thing deciding whether the turn proceeds.
export async function scanPromptWithPrismaAirs(
  input: PrismaAirsScanInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const { url, init } = buildPrismaAirsRequest(input);
  const timeoutMs = input.timeoutMs ?? PRISMA_AIRS_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: errorMessage() falls back to the status
    }
    return parsePrismaAirsResponse(res.status, body, Date.now() - started, input.response != null);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `Prisma AIRS did not answer within ${timeoutMs} ms`
        : `Could not reach Prisma AIRS: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "prisma-airs", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}
