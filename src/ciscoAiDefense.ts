// Cisco AI Defense — runtime Inspection API client (chat inspection).
//
// Facts from Cisco's own DevNet docs, fetched 2026-10-05 — DOCUMENTED, NOT YET
// VERIFIED against a live payload (both earlier vendors' docs were wrong somewhere;
// PROGRESS.md "Plan: Cisco AI Defense + Check Point Lakera Guard"):
//   - POST {region}/api/v1/inspect/chat
//     https://developer.cisco.com/docs/ai-defense-inspection/inspect-conversations/
//   - Regional hosts https://{us,ap,eu}.api.inspect.aidefense.security.cisco.com
//     https://developer.cisco.com/docs/ai-defense-inspection/getting-started/
//   - Auth header `X-Cisco-AI-Defense-API-Key`. The key comes from an AI Defense
//     application connection; the policy rides on that connection, so there is no
//     profile to name in the request.
//   - Body: `messages` [{role, content}] (required), optional `metadata` (user,
//     src_ip, user_agent, … — none sent here except `client_transaction_id`),
//     optional `config`.
//   - 200: `is_safe` (boolean) is the verdict; `classifications[]`, `rules[]`
//     ({rule_name, classification, …}), `severity`, `attack_technique`,
//     `explanation`, `event_id` (documented as generated "if violation occurs"),
//     `client_transaction_id` echoed.
//   - Errors: 401 / 500 with `{message}` per the docs; the LIVE 401 (no-key probe,
//     2026-10-05) is {code: 401, message: "Unauthorized", details: ["…missing api key"]}.
//   - Probed 2026-10-05 with no key: the inspect path answers 401 on all three
//     regions, a made-up path 404 — so the path is real (unlike PANW, whose hosts
//     answer 403 to any path).
//
// Re-checked 2026-10-08 against the same DevNet page and the live hosts:
//   - Path, hosts, header, `messages`, `metadata` and every response field above are
//     unchanged. The page's own schema lists `classification` as required while the
//     property it defines is `classifications` (array) — read as the latter.
//   - `config` (optional) takes `enabled_rules[]` or `integration_profile_id` / `_version` /
//     `_tenant_id` / `integration_type`, and "one of" them must be given IF config is sent.
//     None is sent here: the key's connection carries the policy. Whether a connection
//     key with no config applies its rules is UNVERIFIED — if every answer comes back
//     is_safe with no rules, that is the first thing to check.
//   - `messages[].role` values are not enumerated, so reply checking stays off (replyCheck).
//   - Live, no key → 401 {code, message:"Unauthorized", details:["…missing api key"]}; an
//     obviously fake key → 401 with "…invalid api key" in details, so a dummy-key test
//     proves the key arrived; a made-up path → 404 {code:5, message:"Not Found"}.
//
// Decided with the user (2026-10-05): `severity` never overrides `is_safe`.

import type { ExternalGuardrailResult } from "./types";

export const CISCO_AID_INSPECT_PATH = "/api/v1/inspect/chat";

// The only hosts the Worker will ever send the key to — chosen by region, never typed.
export const CISCO_AID_REGIONS = [
  { id: "us", label: "US (us-west-2)", url: "https://us.api.inspect.aidefense.security.cisco.com" },
  { id: "ap", label: "APAC (ap-northeast-1)", url: "https://ap.api.inspect.aidefense.security.cisco.com" },
  { id: "eu", label: "EU (eu-central-1)", url: "https://eu.api.inspect.aidefense.security.cisco.com" },
] as const;

// Same budget and reasoning as the other providers: long enough for a sync scan,
// short enough that a hung provider cannot hold a chat turn hostage.
export const CISCO_AID_TIMEOUT_MS = 5000;

export interface CiscoAidScanInput {
  baseUrl: string;
  apiKey: string;
  prompt: string;
  transactionId?: string; // the Cloudflare ray, so the two consoles can be joined
  timeoutMs?: number;
}

export function buildCiscoAidRequest(input: CiscoAidScanInput): { url: string; init: RequestInit } {
  const body = {
    messages: [{ role: "user", content: input.prompt }],
    // Only the correlation id. The documented `metadata` also takes user, src_ip,
    // user_agent… — deliberately none of them: the prompt already leaves Cloudflare
    // for a third party, and the person behind it does not need to as well. No
    // `config` either: the policy rides on the key's connection, and sending one
    // here could quietly override what the operator set up in the console.
    ...(input.transactionId ? { metadata: { client_transaction_id: input.transactionId } } : {}),
  };
  return {
    url: input.baseUrl + CISCO_AID_INSPECT_PATH,
    init: {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "X-Cisco-AI-Defense-API-Key": input.apiKey,
      },
      body: JSON.stringify(body),
    },
  };
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

// Unique, in first-seen order, strings only.
function uniqueStrings(values: unknown[]): string[] {
  return [...new Set(values.filter((v): v is string => typeof v === "string" && v !== ""))];
}

// The documented error shape is `{message}` (401 / 500). The live one is richer —
// probed 2026-10-05 with no key: 401 {"code":401,"message":"Unauthorized","details":
// ["failed to validate request: missing api key"]} — and the useful half is in
// `details`, so it is appended. Anything else (an HTML bad-gateway page, an empty
// body) falls back to the status.
function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    const fromBody = str(b.message);
    const detail = Array.isArray(b.details) ? str(b.details[0]) : undefined;
    if (fromBody) return detail ? `${fromBody}: ${detail}` : fromBody;
    if (detail) return detail;
  }
  return `Cisco AI Defense returned HTTP ${status}`;
}

// The verdict is `is_safe` alone. `severity` is reported by Cisco but never
// consulted: the operator's AI Defense policy already decided what is a violation,
// and re-deriving a verdict from a second field would second-guess it (decided
// with the user — HIGH on a safe prompt is still an allow, NONE_SEVERITY on an
// unsafe one is still a block). Anything that is not a 2xx carrying a real boolean
// `is_safe` is an error, never an allow: `"false"`, `0` and `null` are all truthy
// or falsy in ways a lenient parser would read as a verdict.
export function parseCiscoAidResponse(status: number, body: unknown, latencyMs: number): ExternalGuardrailResult {
  const base = { provider: "cisco-ai-defense" as const, latencyMs, httpStatus: status };
  if (status < 200 || status >= 300) return { ...base, outcome: "error", error: errorMessage(body, status) };

  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  if (typeof b.is_safe !== "boolean") {
    return {
      ...base,
      outcome: "error",
      error: `Cisco AI Defense returned no usable verdict (is_safe = ${JSON.stringify(b.is_safe) ?? "undefined"})`,
    };
  }

  // What fired: the named rules first; the bare classifications only when no rule
  // is named. NONE_VIOLATION is Cisco's "nothing found" placeholder, not a finding.
  const rules = Array.isArray(b.rules) ? b.rules : [];
  let detected = uniqueStrings(rules.map((r) => (r as { rule_name?: unknown } | null)?.rule_name));
  if (detected.length === 0 && Array.isArray(b.classifications)) {
    detected = uniqueStrings(b.classifications).filter((c) => c !== "NONE_VIOLATION");
  }

  const action = b.is_safe ? "allow" : "block";
  return {
    ...base,
    outcome: action,
    action,
    detected,
    // Documented as generated only "if violation occurs" — so an allow usually has
    // none, and none is reported as none rather than invented.
    scanId: str(b.event_id) ?? null,
    reportId: null,
    profileName: null,
    summary: str(b.explanation),
  };
}

// One synchronous inspection. Never throws: network, timeout, bad JSON and non-2xx
// all come back as `outcome: "error"`, so the caller's fail mode decides.
export async function scanPromptWithCiscoAid(
  input: CiscoAidScanInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const { url, init } = buildCiscoAidRequest(input);
  const timeoutMs = input.timeoutMs ?? CISCO_AID_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: errorMessage() falls back to the status
    }
    return parseCiscoAidResponse(res.status, body, Date.now() - started);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `Cisco AI Defense did not answer within ${timeoutMs} ms`
        : `Could not reach Cisco AI Defense: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "cisco-ai-defense", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}

