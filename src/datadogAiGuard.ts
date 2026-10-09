// Datadog AI Guard — HTTP API client (evaluate).
//
// Sources, strongest first (PROGRESS.md "Research: Datadog AI Guard", 2026-10-09). The docs are the
// thinnest of them, so the shipping client wins where they differ:
//   1. Datadog's own Ruby tracer, DataDog/dd-trace-rb lib/datadog/ai_guard/* (http_client.rb,
//      evaluation/{request,response,outcome}.rb): the path, both key headers, the body, and that
//      `action`, `reason`, `tags`, `tag_probs` and `is_blocking_enabled` are REQUIRED in a response
//      (`sds_findings` and `redaction_replacements` default to []). It blocks only when
//      `is_blocking_enabled && (DENY || ABORT)`.
//   2. Recorded calls in DataDog/system-tests (utils/build/docker/vcr/cassettes/aiguard/): every 200 has
//      `data.id` (a UUID), `type: "evaluations"` and `is_blocking_enabled`; `sds_findings[]` carry
//      `rule_display_name`, `rule_tag`, `category` and a `location` naming the message
//      (`messages[2].content`). One recording is a real DENY with `is_blocking_enabled: false`.
//   3. docs.datadoghq.com/security/ai_guard/setup/http_api/ and …/setup/: POST /api/v2/ai-guard/evaluate,
//      `DD-API-KEY` + `DD-APPLICATION-KEY` (the application key needs the `ai_guard_evaluate` scope),
//      "AI Guard evaluates the last message in the sequence", ALLOW / DENY ("should be blocked") /
//      ABORT ("terminate the entire agent workflow"), `reason` is "only provided for auditing and logging,
//      and should not be passed back to the LLM or the end user". "By default, AI Guard … does not block
//      requests": blocking is a policy per organisation, environment or service. AI Guard is in Preview
//      (Datadog enables it per org) and not available on the ddog-gov sites. "HTTP API requests do not
//      send traces to Datadog": these evaluations do not appear in the Datadog UI.
//   Live, 2026-10-09: all six public hosts answer POST /api/v2/ai-guard/evaluate with 401 and a made-up
//   /api/v2/ai-guard path with 404 {"errors":["Not found"]}, so the path is real on each. No keys, a fake
//   API key alone, or keys of the wrong shape → 401 {"errors":["Unauthorized"]}. A fake application key of
//   the real shape (40 hex), with or without an API key → 403 {"errors":["Forbidden"]}. So a 403 proves a
//   well-formed application key ARRIVED, and nothing about the API key; real keys without the
//   `ai_guard_evaluate` scope, or an org without the AI Guard Preview, presumably answer 403 too (unseen).
//
// DOCUMENTED, NOT YET VERIFIED by a payload from the user's own org: `verified: false` until then.
//
// Proposed 2026-10-09 and taken when the user asked for the integration (it follows the user's 2026-10-05
// Lakera Detect-mode decision):
//   - DENY or ABORT with `is_blocking_enabled: false` (Datadog's monitor-only default) is ALLOW WITH
//     ALERTS — outcome allow, `detectOnly` — never a clean pass and never a block Datadog did not enforce.
//   - Sensitive data found on an ALLOW is never a clean pass either (`detectOnly`); a redaction Datadog
//     offered is "redaction not applied" (`transformed`), as for AIDR — this app never applies one.

import type { ExternalGuardrailResult } from "./types";

export const DATADOG_AI_GUARD_PATH = "/api/v2/ai-guard/evaluate";

// The only hosts the Worker will ever send the keys to — one per Datadog site, chosen by region, never
// typed. dd-trace-rb prefixes "app." when the site has one dot, which gives these six.
export const DATADOG_REGIONS = [
  { id: "us1", label: "US1 (datadoghq.com)", url: "https://app.datadoghq.com" },
  { id: "us3", label: "US3 (us3.datadoghq.com)", url: "https://us3.datadoghq.com" },
  { id: "us5", label: "US5 (us5.datadoghq.com)", url: "https://us5.datadoghq.com" },
  { id: "eu1", label: "EU1 (datadoghq.eu)", url: "https://app.datadoghq.eu" },
  { id: "ap1", label: "AP1 (ap1.datadoghq.com)", url: "https://ap1.datadoghq.com" },
  { id: "ap2", label: "AP2 (ap2.datadoghq.com)", url: "https://ap2.datadoghq.com" },
] as const;

// Same budget and reasoning as the other providers.
export const DATADOG_TIMEOUT_MS = 5000;

// Sent as `meta.service`, so the operator can give this demo its own AI Guard service policy (blocking,
// sensitivity, sensitive data scanning) instead of the organisation default. A fixed name, not user data.
export const DATADOG_SERVICE = "cf-ai-waf-demo";

export interface DatadogScanInput {
  baseUrl: string;
  apiKey: string;
  appKey: string;
  prompt: string;
  // The model's reply, for a reply check (design J). AI Guard evaluates the LAST message, so the reply
  // goes last, as the assistant turn, with the prompt before it as context.
  response?: string;
  timeoutMs?: number;
}

export function buildDatadogRequest(input: DatadogScanInput): { url: string; init: RequestInit } {
  // Exactly the prompt (and the reply, for a reply check): no system prompt, no history, no user or IP —
  // every vendor gets the same input so "Controls compared" is like-for-like.
  const body = {
    data: {
      attributes: {
        messages: [
          { role: "user", content: input.prompt },
          ...(input.response != null ? [{ role: "assistant", content: input.response }] : []),
        ],
        meta: { service: DATADOG_SERVICE },
      },
    },
  };
  return {
    url: input.baseUrl + DATADOG_AI_GUARD_PATH,
    init: {
      method: "POST",
      headers: { "content-type": "application/json", "dd-api-key": input.apiKey, "dd-application-key": input.appKey },
      body: JSON.stringify(body),
    },
  };
}

const ERROR_CAP = 200;

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

// Error bodies are `{"errors": [...]}` — strings in the live 401/404 and in dd-trace-rb, which joins
// them; JSON:API `{title, detail}` objects are read too. The text is shown only on 401/403, where it is
// about the keys or the org (no AI Guard Preview, a missing `ai_guard_evaluate` scope). On anything else
// an error nobody has seen could be a validation message quoting the prompt, so only the status shows.
function errorMessage(body: unknown, status: number): string {
  if (status === 429) return "Datadog AI Guard rate limited the request (HTTP 429)";
  if (status === 404) return "Datadog AI Guard returned HTTP 404 — is AI Guard enabled for this organisation on this site?";
  // Both live errors are one generic word, so each says what it can mean.
  const hint =
    status === 401
      ? " — check the API key and the Datadog site"
      : status === 403
        ? " — check the application key, its ai_guard_evaluate scope, and that AI Guard is enabled for the organisation"
        : "";
  if ((status === 401 || status === 403) && isObject(body) && Array.isArray(body.errors)) {
    const text = body.errors
      .map((e) => (typeof e === "string" ? e : isObject(e) ? (e.detail ?? e.title) : undefined))
      .filter((t): t is string => typeof t === "string" && t.trim() !== "")
      .join(", ")
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .trim();
    if (text) return `Datadog AI Guard: ${text.slice(0, ERROR_CAP)} (HTTP ${status})${hint}`;
  }
  return `Datadog AI Guard returned HTTP ${status}${hint}`;
}

// A name that may be shown to the operator: an attack category (`jailbreak`) or a scanner rule's tag
// (`us_ssn`). Anything else could be free text. Three digits in a row are refused too, as for Cato: a
// tag never needs a number that long, and a custom rule's tag must not be able to carry the data.
const SAFE_TAG = /^[A-Za-z][A-Za-z0-9_.:-]{0,59}$/;
const DIGIT_RUN = /\d{3}/;

function tag(v: unknown): string | undefined {
  return typeof v === "string" && SAFE_TAG.test(v) && !DIGIT_RUN.test(v) ? v : undefined;
}

// Datadog's id for this evaluation (`data.id`, a UUID in every recording). Shape-checked like any id shown.
function evaluationId(v: unknown): string | null {
  return typeof v === "string" && /^[A-Za-z0-9_.:-]{1,100}$/.test(v) ? v : null;
}

const ACTIONS = ["ALLOW", "DENY", "ABORT"] as const;

// PRIVACY: the parser is an ALLOWLIST. It never copies `reason` (free text that Datadog itself says must
// not reach the user), `redaction_replacements` (the user's own text, redacted), `tag_probs`, a finding's
// `rule_display_name` or its `location` — only names: attack `tags` and each finding's `rule_tag`, each
// shape-checked, the evaluation id, and whether a redaction was offered (never the redaction).
//
// The verdict:
//   - ALLOW → allow. Sensitive data findings make it allow with alerts; a redaction offered, also
//     "redaction not applied".
//   - DENY / ABORT with `is_blocking_enabled: false` → allow with alerts: Datadog's policy only monitors.
//   - DENY / ABORT otherwise → block. A MISSING `is_blocking_enabled` is read as a block too: the docs'
//     own examples omit the field and say DENY "should be blocked", and the safer reading of an
//     incomplete answer is the stricter one. Only an explicit `false` downgrades it.
//   - Anything else (no attributes, an unknown action) is an error, never an allow.
export function parseDatadogResponse(status: number, body: unknown, latencyMs: number, reply = false): ExternalGuardrailResult {
  const base = { provider: "datadog-ai-guard" as const, latencyMs, httpStatus: status };
  if (status < 200 || status >= 300) return { ...base, outcome: "error", error: errorMessage(body, status) };

  const data = isObject(body) && isObject(body.data) ? body.data : null;
  const attrs = data && isObject(data.attributes) ? data.attributes : null;
  if (!attrs) {
    return { ...base, outcome: "error", error: "Datadog AI Guard returned no usable verdict (no data.attributes object)" };
  }
  const action = attrs.action;
  if (typeof action !== "string" || !(ACTIONS as readonly string[]).includes(action)) {
    const named = typeof action === "string" && /^[A-Z_]{1,20}$/.test(action) ? `"${action}"` : "missing or not a known value";
    return {
      ...base,
      outcome: "error",
      error: `Datadog AI Guard's verdict was not recognised (documented: ALLOW, DENY, ABORT): action was ${named}`,
    };
  }

  const detected: string[] = [];
  const add = (n: string | undefined) => {
    if (n !== undefined && !detected.includes(n)) detected.push(n);
  };
  if (Array.isArray(attrs.tags)) for (const t of attrs.tags) add(tag(t));
  const findings = Array.isArray(attrs.sds_findings) ? attrs.sds_findings.filter(isObject) : [];
  for (const f of findings) {
    const name = tag(f.rule_tag);
    if (!name) continue;
    // A reply check sends [prompt, reply]. Sensitive data scanning may report a finding in either; its
    // `location.path` names the message. One in messages[0] is the PROMPT's and is marked "prompt:", as
    // Prisma AIRS's and Lakera's are — never shown as something the model said. Only the path's prefix is
    // read, never its offsets.
    const path = isObject(f.location) && typeof f.location.path === "string" ? f.location.path : "";
    add(reply && path.startsWith("messages[0]") ? `prompt:${name}` : name);
  }
  const redactionOffered = Array.isArray(attrs.redaction_replacements) && attrs.redaction_replacements.length > 0;
  const ids = { scanId: evaluationId(data!.id), reportId: null, profileName: null };

  if (action === "ALLOW") {
    return {
      ...base,
      outcome: "allow",
      action: "allow",
      detected,
      ...ids,
      ...(findings.length > 0 ? { detectOnly: true } : {}),
      ...(redactionOffered ? { transformed: true } : {}),
    };
  }
  // DENY or ABORT. `category` keeps which one, so an ABORT ("terminate the workflow") is not flattened
  // into a DENY on the card.
  const category = action.toLowerCase();
  if (attrs.is_blocking_enabled === false) {
    return {
      ...base,
      outcome: "allow",
      action: "allow",
      category,
      detected,
      ...ids,
      detectOnly: true,
      ...(redactionOffered ? { transformed: true } : {}),
    };
  }
  return { ...base, outcome: "block", action: "block", category, detected, ...ids };
}

// One synchronous evaluation. Never throws: network, timeout, bad JSON and non-2xx all come back as
// `outcome: "error"`, so the caller's fail mode decides.
export async function scanPromptWithDatadog(
  input: DatadogScanInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const { url, init } = buildDatadogRequest(input);
  const timeoutMs = input.timeoutMs ?? DATADOG_TIMEOUT_MS;
  const started = Date.now();
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null; // non-JSON body: parseDatadogResponse() falls back to the status / "no usable verdict"
    }
    return parseDatadogResponse(res.status, body, Date.now() - started, input.response != null);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    const message =
      name === "TimeoutError" || name === "AbortError"
        ? `Datadog AI Guard did not answer within ${timeoutMs} ms`
        : `Could not reach Datadog AI Guard: ${err instanceof Error ? err.message : String(err)}`;
    return { provider: "datadog-ai-guard", outcome: "error", error: message, latencyMs: Date.now() - started };
  }
}
