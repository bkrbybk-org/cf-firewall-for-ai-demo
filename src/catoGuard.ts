// Cato Networks AI Security — API Guard client (chat inspection).
//
// Facts from Cato's own console text, fetched 2026-10-06 — DOCUMENTED, NOT YET
// VERIFIED against a live verdict payload (every earlier vendor's docs were wrong
// somewhere; this one has only been checked as far as the probes below):
//   - POST https://api.aisec.catonetworks.com/fw/v1/analyze
//   - `Authorization: Bearer <guard key>`; optional `x-cato-session-id` (groups a
//     conversation — we send the Cloudflare ray when we have one).
//   - Body: `messages` [{role, content}] (OpenAI format).
//   - 200: `required_action.action_type` carries the verdict. ONLY the block value
//     ("block_action") is documented — the sample in the console is a block case, so
//     the allow value is UNKNOWN until a real allow payload has been seen. The body
//     also echoes the raw sensitive data back (`detection_message`, every `content`,
//     `entity.content`, `redacted_chat.*`) — see parseCatoResponse.
//   - LIVE probes, 2026-10-06, real endpoint: no Authorization → HTTP 401
//     {"detail":"Authorization header is required"}; bad key → HTTP 401
//     {"detail":"Invalid API token"}; a made-up path → 404, so the path is real.
//     (A bad key answers differently from a missing one, so a dummy-key test proves
//     the key arrived.)
//
// Decided with the user (2026-10-06): only `block_action` is a block; every other
// answer is an error and the operator's fail mode decides — "an unknown answer is
// never an allow", the rule for every vendor here.
//
// REAL payloads, 2026-10-06 (the user's own Guard, Test connection benign + attack,
// read as shapes — src/responseShape.ts). Where they differ from the console sample,
// the real one wins:
//   - The ALLOW is `required_action: null` — present and null, not absent — next to a
//     full `analysis_result`. Only that exact pair is read as allow.
//   - `policy_drill_down` is keyed by policy UUID, each `{policy_name, detections[]}`;
//     the sample's readable "PII" key does not happen. Names come from `policy_name`.
//   - `invocation_id` (string) is present, so it is the scan id; the sample has none.
//   - `analysis_result.session_entities` exists (unread), `additional_contents` is null.
//   - The fixed injection prompt was ALLOWED: all three of that Guard's policies came
//     back with empty `detections`. A real block has not been seen yet; its shape is
//     still the sample's `required_action.action_type: "block_action"`.

import type { ExternalGuardrailResult } from "./types";

export const CATO_GUARD_PATH = "/fw/v1/analyze";

// The only host the Worker will ever send the key to — chosen by region, never typed.
export const CATO_REGIONS = [{ id: "global", label: "Global", url: "https://api.aisec.catonetworks.com" }] as const;

// Same budget and reasoning as the other providers: long enough for a sync scan,
// short enough that a hung provider cannot hold a chat turn hostage.
export const CATO_TIMEOUT_MS = 5000;

export interface CatoScanInput {
  baseUrl: string;
  apiKey: string;
  prompt: string;
  sessionId?: string; // the Cloudflare ray, so the two consoles can be joined — never invented
  timeoutMs?: number;
}

export function buildCatoRequest(input: CatoScanInput): { url: string; init: RequestInit } {
  // Exactly the prompt, as one user message: no history, no metadata, no user or IP.
  // Every vendor gets the same single prompt so "Controls compared" is like-for-like,
  // and the person behind the prompt does not leave Cloudflare as well.
  const body = { messages: [{ role: "user", content: input.prompt }] };
  return {
    url: input.baseUrl + CATO_GUARD_PATH,
    init: {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: `Bearer ${input.apiKey}`,
        ...(input.sessionId ? { "x-cato-session-id": input.sessionId } : {}),
      },
      body: JSON.stringify(body),
    },
  };
}

const ERROR_CAP = 200;

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

// Error bodies are FastAPI-shaped. The LIVE 401s carry a string `detail` about the
// key — the only string `detail` shown, and only on 401/403: on a 400 nobody has seen,
// a string `detail` could be a validation message quoting the prompt. A 422 carries an
// array of {loc, msg, type, input}: only the first `msg` is read, NEVER `input` — it
// echoes the request, i.e. the prompt. Anything else (an HTML bad gateway page, an
// empty body) falls back to the status.
function errorMessage(body: unknown, status: number): string {
  if (status === 429) return "Cato AI Security rate limited the request (HTTP 429)";
  if (isObject(body)) {
    const d = body.detail;
    let text: unknown;
    if (typeof d === "string" && (status === 401 || status === 403)) text = d;
    else if (Array.isArray(d) && isObject(d[0])) text = d[0].msg;
    if (typeof text === "string" && text.trim()) return text.trim().slice(0, ERROR_CAP);
  }
  return `Cato AI Security returned HTTP ${status}`;
}

// A name that may be shown to the operator. Anything that does not look like a short
// identifier could be free text — and Cato's free text can be the user's own data.
// Three digits in a row are refused too: the charset alone would pass "078-05-1120",
// and a detector's name never needs a number that long.
const SAFE_LABEL = /^[A-Za-z0-9_ .\-/]{1,60}$/;
const DIGIT_RUN = /\d{3}/;
const SAFE_ACTION = /^[a-z_]{1,40}$/;

function label(v: unknown): string | undefined {
  return typeof v === "string" && SAFE_LABEL.test(v) && !DIGIT_RUN.test(v) ? v : undefined;
}

// An operator-named policy (`policy_drill_down.<uuid>.policy_name`). It is console
// configuration, not prompt data, so it may hold digits and punctuation — but it is
// still capped, and control characters refuse it.
function policyName(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t && t.length <= 80 && !/[\u0000-\u001f\u007f]/.test(t) ? t : undefined;
}

// Cato's id for this analysis, for its console. Shape-checked like any id we show.
function invocationId(v: unknown): string | null {
  return typeof v === "string" && /^[A-Za-z0-9_.:-]{1,100}$/.test(v) ? v : null;
}

// Why the verdict is unusable, in words an operator can act on. The unknown value is
// named only when it is a short lowercase token; otherwise it is not echoed at all.
function unrecognisedVerdict(actionType: unknown, requiredActionPresent: boolean): string {
  const lead =
    "Cato AI Security's verdict was not recognised (seen live: required_action null = allow, anonymize_action = allow + redaction; documented: block_action)";
  if (!requiredActionPresent) return `${lead}: required_action was missing or not an object`;
  if (typeof actionType !== "string") return `${lead}: required_action.action_type was missing or not a string`;
  if (SAFE_ACTION.test(actionType)) return `${lead}: action_type was "${actionType}"`;
  return `${lead}: action_type was not a recognised token`;
}

// PRIVACY: Cato echoes the raw sensitive data back — `detection_message`,
// `detections[].message`, every `content`, `entity.content`, `redacted_chat.*`,
// `name`, offsets, scores. This parser is an ALLOWLIST: it copies none of those
// into the result, so nothing downstream (the prompt log, the UI, the Controls
// strip) can end up holding the very value the guardrail was meant to catch.
// What it does read: names of what fired (each fired policy's operator-set
// `policy_name`, entity `type`s — each shape-checked), the policy that required the
// action, Cato's `invocation_id`, and whether the newest message was redacted (never
// the redacted text itself).
//
// The verdict, from the real payloads above:
//   - `required_action: null` with an `analysis_result` object → allow. If a policy
//     still reported detections, it is allow WITH ALERTS (`detectOnly`): Cato saw
//     something and its policy asked for no action — never a clean pass (the rule
//     Lakera's Detect mode follows, decided with the user).
//   - `required_action.action_type === "block_action"` → block (documented; no real
//     block seen yet).
//   - Anything else — required_action missing, another action_type, null without an
//     analysis — is an error, never an allow: an unfamiliar answer is not a pass.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function firedNames(analysis: Record<string, unknown>): string[] {
  const names: string[] = [];
  const add = (n: string | undefined) => {
    if (n !== undefined && !names.includes(n)) names.push(n);
  };
  // Policy sections that actually fired — by their name, never their UUID key — then
  // entity types from each detection and from the newest message's entities.
  const drill = isObject(analysis.policy_drill_down) ? analysis.policy_drill_down : {};
  for (const [section, v] of Object.entries(drill)) {
    if (!isObject(v) || !Array.isArray(v.detections) || v.detections.length === 0) continue;
    add(policyName(v.policy_name) ?? (UUID.test(section) ? undefined : label(section)));
    for (const d of v.detections) {
      if (isObject(d) && isObject(d.entity)) add(label(d.entity.type));
    }
  }
  if (Array.isArray(analysis.last_message_entities)) {
    for (const e of analysis.last_message_entities) if (isObject(e)) add(label(e.type));
  }
  return names;
}

export function parseCatoResponse(status: number, body: unknown, latencyMs: number): ExternalGuardrailResult {
  const base = { provider: "cato-ai-security" as const, latencyMs, httpStatus: status };
  if (status < 200 || status >= 300) return { ...base, outcome: "error", error: errorMessage(body, status) };

  if (!isObject(body)) {
    return { ...base, outcome: "error", error: "Cato AI Security returned no usable verdict (body was not a JSON object)" };
  }
  const required = body.required_action;
  const analysis = isObject(body.analysis_result) ? body.analysis_result : null;
  const ids = { scanId: invocationId(body.invocation_id), reportId: null, profileName: null };

  // Cato redacted something in the newest message. This app does NOT apply it (the UI
  // says "redaction available, not applied"), and the redacted text is never read.
  const chat = isObject(body.redacted_chat) ? body.redacted_chat : {};
  const newest = isObject(chat.redacted_new_message) ? chat.redacted_new_message : {};
  const transformed = Array.isArray(newest.entities) && newest.entities.length > 0;

  if (required === null && analysis) {
    const detected = firedNames(analysis);
    return {
      ...base,
      outcome: "allow",
      action: "allow",
      detected,
      ...ids,
      ...(detected.length > 0 ? { detectOnly: true } : {}),
      ...(transformed ? { transformed: true } : {}),
    };
  }
  if (required === null) {
    return { ...base, outcome: "error", error: "Cato AI Security returned no action and no analysis_result — not a verdict" };
  }
  const policy =
    isObject(required) && typeof required.policy_name === "string" ? required.policy_name.trim().slice(0, ERROR_CAP) : "";

  // SEEN LIVE (2026-10-06, a Thai OTP-redirect prompt carrying two phone numbers, in
  // chat): `action_type: "anonymize_action"` — Cato's policy asks for the PII to be
  // anonymized and the prompt to go on. Undocumented. Read the way AIDR's redaction is
  // (decided with the user: redaction is shown, not applied): an ALLOW, flagged
  // `transformed`, so the card says the redaction was not applied and the model would
  // receive the original prompt — amber, never a clean pass, and never a block Cato
  // did not ask for. The flag rides on the action itself, not on whether the redacted
  // message happens to list entities.
  if (isObject(required) && required.action_type === "anonymize_action") {
    return {
      ...base,
      outcome: "allow",
      action: "allow",
      detected: analysis ? firedNames(analysis) : [],
      ...ids,
      ...(policy ? { policy } : {}),
      transformed: true,
    };
  }
  if (!isObject(required) || required.action_type !== "block_action") {
    return {
      ...base,
      outcome: "error",
      error: unrecognisedVerdict(isObject(required) ? required.action_type : undefined, isObject(required)),
    };
  }

  return {
    ...base,
    outcome: "block",
    action: "block",
    detected: analysis ? firedNames(analysis) : [],
    ...ids,
    ...(policy ? { policy } : {}),
    ...(transformed ? { transformed: true } : {}),
  };
}

// One synchronous analysis. Never throws: network, timeout, bad JSON and non-2xx
// all come back as `outcome: "error"`, so the caller's fail mode decides.
export async function scanPromptWithCato(
  input: CatoScanInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const { url, init } = buildCatoRequest(input);
  const timeoutMs = input.timeoutMs ?? CATO_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: parseCatoResponse() falls back to the status / "no usable verdict"
    }
    return parseCatoResponse(res.status, body, Date.now() - started);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `Cato AI Security did not answer within ${timeoutMs} ms`
        : `Could not reach Cato AI Security: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "cato-ai-security", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}
