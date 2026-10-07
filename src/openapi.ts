// OpenAPI 3.1 description of the Worker's HTTP API, served at GET /api/openapi.json
// Swagger UI at /api-docs/ renders its 3.0 rendering (src/openapi30.ts,
// /api/openapi-3.0.json) — the form API Shield accepts.
//
// HAND-WRITTEN on purpose, and kept honest by two guards rather than by hope:
//   - src/openapi.test.ts parses it with a real OpenAPI validator and fails if the
//     route table in src/index.ts and `paths` below ever disagree, so an endpoint
//     cannot be added or removed without this file noticing.
//   - The schemas were validated against live payloads (local `wrangler dev` and
//     prod through Access), including a check for keys the payload carries that
//     the schema does not declare — the drift a validator alone would let through.
//
// What the schemas do NOT prove: they describe the shapes the handlers produce
// today, not a contract the handlers are tested against. There is no handler-level
// contract test (it would need D1 and Workers AI mocks). Treat a mismatch as a bug
// in whichever side is wrong, and fix it at that point.
//
// Conventions worth knowing before reading the paths:
//   - A missing secret or D1 binding is reported as HTTP 200 with
//     `{ "configured": false }`, never as an error status, so a demo missing one
//     token degrades one feature instead of breaking a page. Only real failures
//     (bad input, an upstream error) use 4xx/5xx.
//   - The edge AI Security scan runs BEFORE the Worker. A prompt it blocks never
//     reaches this code: the 403 on /api/chat is written by the WAF custom rule,
//     not by the Worker, and its body is whatever the operator configured.

type Json = Record<string, unknown>;

const ref = (name: string): Json => ({ $ref: `#/components/schemas/${name}` });
const param = (name: string): Json => ({ $ref: `#/components/parameters/${name}` });
const json = (description: string, schema: Json, example?: unknown): Json => ({
  description,
  content: { "application/json": example === undefined ? { schema } : { schema, example } },
});
const error = (description: string): Json => json(description, ref("Error"));

const str = (description?: string): Json => (description ? { type: "string", description } : { type: "string" });
const int = (description?: string): Json => (description ? { type: "integer", description } : { type: "integer" });
const num = (description?: string): Json => (description ? { type: "number", description } : { type: "number" });
const bool = (description?: string): Json => (description ? { type: "boolean", description } : { type: "boolean" });
const nullable = (type: string, description?: string): Json =>
  description ? { type: [type, "null"], description } : { type: [type, "null"] };
const arr = (items: Json): Json => ({ type: "array", items });
const obj = (properties: Record<string, Json>, required: string[] = [], description?: string): Json => ({
  type: "object",
  ...(description ? { description } : {}),
  properties,
  ...(required.length ? { required } : {}),
});
// SQLite has no boolean, so D1-backed rows carry flags as 0/1 integers.
const flag = (description: string): Json => ({ type: "integer", enum: [0, 1], description });

// Every "configured: false" response — a missing token or binding, not a failure.
const notConfigured = (extra: Record<string, Json> = {}): Json =>
  obj({ configured: { const: false }, ...extra }, ["configured"]);

export const openapi = {
  openapi: "3.1.0",
  info: {
    title: "Cloudflare AI Security demo API",
    version: "1.0.0",
    description: [
      "The HTTP API behind the **Cloudflare AI Security for Apps + AI Gateway** demo (`cf-ai-waf-demo`).",
      "",
      "**Access.** Production sits behind Cloudflare Access. In a browser you are already signed in, so *Try it out* just works. From a script, send a service token: `CF-Access-Client-Id` and `CF-Access-Client-Secret` (use *Authorize* above).",
      "",
      "**What is real.** *Try it out* sends real requests. `POST /api/chat` calls a live model (Workers AI, billable) and is scanned by the real edge WAF, so a prompt containing PII or an injection will come back **403 from the WAF, not from this Worker** — that is the demo. `DELETE /api/prompt-log` and `DELETE /api/redteam-runs` really delete.",
      "",
      "**`configured: false`.** A missing secret or D1 binding returns HTTP 200 with `{\"configured\": false}` rather than an error, so one missing token degrades one feature. Only genuine failures use 4xx/5xx.",
      "",
      "**The prompt log is a feature flag** (`PROMPT_LOG_ENABLED`, off by default). While it is off, `/api/prompt-log` and `/api/prompt-analytics` answer `{\"configured\": false, \"disabled\": true}`.",
    ].join("\n"),
  },
  // Relative, so Swagger UI's Try it out targets whichever origin served this
  // document — the same file works on prod and on `wrangler dev`.
  servers: [{ url: "/" }],
  tags: [
    { name: "Chat", description: "The one inference endpoint: direct Workers AI or AI Gateway, JSON or SSE." },
    { name: "Edge analytics", description: "What the Cloudflare edge did — read from the zone's GraphQL Analytics." },
    { name: "Prompt log", description: "PII-redacted prompts in D1. Off by default (`PROMPT_LOG_ENABLED`)." },
    { name: "Red team", description: "Persisted red-team runs. No UI calls these yet." },
    { name: "External guardrails", description: "Forward each prompt to third-party guardrails (Palo Alto Networks Prisma AIRS, CrowdStrike Falcon AIDR) before the model runs, as a sequential or parallel pipeline." },
    { name: "Meta", description: "Configuration the client reads to build its controls." },
  ],
  security: [{ AccessClientId: [], AccessClientSecret: [] }, {}],
  paths: {
    "/api/openapi.json": {
      get: {
        tags: ["Meta"],
        operationId: "getOpenApi",
        summary: "This document",
        description: "The OpenAPI 3.1 source document. Swagger UI at `/api-docs/` renders the 3.0 rendering, `/api/openapi-3.0.json`.",
        responses: { "200": { description: "OpenAPI 3.1 document.", content: { "application/json": { schema: { type: "object" } } } } },
      },
    },
    "/api/openapi-3.0.json": {
      get: {
        tags: ["Meta"],
        operationId: "getOpenApi30",
        summary: "This document as OpenAPI 3.0 (for API Shield)",
        description:
          "The same API, down-converted to OpenAPI 3.0.3 for Cloudflare API Shield Schema Validation, which rejects 3.1-only semantics (numeric `exclusiveMinimum`, `type` arrays, `const`) and relative server URLs. `servers` is the origin that served the request. Upload this file, not `/api/openapi.json`.",
        responses: { "200": { description: "OpenAPI 3.0.3 document.", content: { "application/json": { schema: { type: "object" } } } } },
      },
    },
    "/api/models": {
      get: {
        tags: ["Meta"],
        operationId: "getModels",
        summary: "Model menu, gateways, limits and feature flags",
        description:
          "Everything the client needs to draw its controls. The model list is the server-side allowlist (`MODEL_REGISTRY`); the front end is never the source of truth. `promptLog.enabled` requires **both** the `PROMPT_LOG_ENABLED` var and a bound D1.",
        responses: { "200": json("Configuration.", ref("ModelsResponse")) },
      },
    },
    "/api/chat": {
      post: {
        tags: ["Chat"],
        operationId: "postChat",
        summary: "Send a prompt (direct Workers AI or AI Gateway)",
        description: [
          "The **top-level `prompt`** is what the edge AI Security scan inspects, so it always carries the latest user message; earlier turns ride in `history`.",
          "",
          "**Two routes.** Default is the Workers AI binding. `gateway: true` calls AI Gateway's OpenAI-compatible REST endpoint and needs the `CF_AIG_TOKEN` secret (otherwise **501**). The edge verdict is identical on both — the scan happens before the Worker runs.",
          "",
          "**Streaming.** `stream: true` returns `text/event-stream` (see the schema for the frame shapes). On the gateway route a final `data: {\"gateway\": …}` frame carries cache status and log id.",
          "",
          "**Blocked prompts.** A WAF block is a **403 written by the zone's rule**, not by this Worker; the body is operator-configured (Custom JSON). A Guardrails block, by contrast, is a **200** with `guardrailsBlocked: true`.",
          "",
          "**Prompt log.** The turn is written to the D1 prompt log only when `PROMPT_LOG_ENABLED` is on *and* `excludeFromLog` is not `true`.",
          "",
          "**External guardrails.** Enabled providers (`/api/external-guardrails`) run as a pipeline after the edge scan and before the model, on both routes — sequentially in the configured order, or in parallel. A block — or a provider error under fail-closed — is a **200** with `externalGuardrailBlocked: true`, never a 403 (403 means the edge WAF). Every response after the check carries the `GuardrailPipelineResult` in the `x-external-guardrails` header (URI-encoded JSON), because a streamed reply has no JSON body to put it in.",
          "",
          "**Guardrail-only mode.** When the pipeline's `guardrailOnly` is on, a prompt that passes every check is answered with a **200** `{guardrailOnly: true}` and **no model is called** — no reply, tokens or cost, and no AI Gateway Guardrails (they run inside the model call).",
        ].join("\n"),
        requestBody: {
          required: true,
          content: { "application/json": { schema: ref("ChatRequest") } },
        },
        responses: {
          "200": {
            description: "The reply — JSON, or an SSE stream when `stream: true`.",
            headers: {
              "x-external-guardrails": {
                description: "Present when the pipeline ran (a guardrail is enabled, or guardrail-only is on): the `GuardrailPipelineResult` for this prompt, as URI-encoded JSON.",
                schema: { type: "string" },
              },
            },
            content: {
              "application/json": {
                schema: { oneOf: [ref("ChatReply"), ref("GuardrailsBlocked"), ref("ExternalGuardrailBlocked"), ref("GuardrailOnlyResult")] },
              },
              "text/event-stream": {
                schema: {
                  type: "string",
                  description:
                    "Server-sent events. Each frame is `data: <json>`. Frames are the model's own chunks — Workers AI shape (`response`) or OpenAI shape (`choices[0].delta.content`) depending on route and model — followed by `data: [DONE]`. The gateway route appends one more frame, `data: {\"gateway\":{\"gatewayId\":…,\"cached\":…,\"logId\":…,\"guarded\":…,\"latencyMs\":…}}`.",
                },
              },
            },
          },
          "400": error("Invalid body, or an invalid `dynamicRoute` name."),
          "403": json(
            "Blocked by the zone's WAF custom rule (AI Security for Apps) **before the Worker ran**. Shape is whatever the operator configured; this is the deployed zone's Custom JSON.",
            ref("WafBlock"),
          ),
          "405": error("Not a POST."),
          "501": error("Gateway route requested but `CF_ACCOUNT_ID` / `CF_AIG_TOKEN` is not set."),
          "502": error("Workers AI call failed."),
          default: json(
            "Gateway route: any other upstream AI Gateway status is passed through (for example 401 with Cloudflare error code 10000 when `CF_AIG_TOKEN` is rejected).",
            ref("Error"),
          ),
        },
      },
    },
    "/api/verdict": {
      get: {
        tags: ["Edge analytics"],
        operationId: "getVerdict",
        summary: "What the edge did to one request",
        description:
          "Looks the request up by its `cf-ray` in the zone's GraphQL Analytics (`firewallEventsAdaptive` + `httpRequestsAdaptive`). **Ingestion lags ~1–2 minutes**, so a fresh ray returns `found: false` — retry rather than concluding nothing happened. `tooOld: true` is different: the request predates the retention window and waiting cannot help.",
        parameters: [
          {
            name: "ray",
            in: "query",
            required: true,
            description: "The `cf-ray` response header value. A trailing `-COLO` suffix is accepted and ignored.",
            schema: { type: "string", pattern: "^[0-9a-fA-F]{16}(-[A-Za-z]{3})?$" },
            example: "a1adfe7e4d618961",
          },
          {
            name: "ts",
            in: "query",
            required: false,
            description:
              "Epoch **milliseconds** of the request itself. Anchors the lookup window to `[ts ± 5 min]` instead of `now`. Malformed values are ignored, not rejected.",
            schema: { type: "integer" },
          },
        ],
        responses: {
          "200": json("The verdict, or `configured: false`.", ref("VerdictResponse")),
          "400": error("`ray` is not a 16-hex-digit ray id."),
          "502": json("The GraphQL lookup failed.", ref("VerdictResponse")),
        },
      },
    },
    "/api/zone-rules": {
      get: {
        tags: ["Edge analytics"],
        operationId: "getZoneRules",
        summary: "The zone's WAF custom rules",
        description:
          "Read live from the Rulesets API, classified as AI Security rules by whether the *expression* references `cf.llm.*`. Needs `Zone → WAF → Read` on `CF_ANALYTICS_TOKEN`; without it `source` is `fallback` with no rules and the client uses its static mirror — it never presents the mirror as live data.",
        responses: { "200": json("Rules, or the fallback marker.", ref("ZoneRulesResponse")) },
      },
    },
    "/api/neurons": {
      get: {
        tags: ["Edge analytics"],
        operationId: "getNeurons",
        summary: "Workers AI Neuron usage today",
        description: "Account-wide usage since 00:00 UTC against the free daily allocation.",
        responses: {
          "200": json("Usage, or `configured: false`.", { oneOf: [ref("NeuronsResponse"), notConfigured()] }),
          "502": error("The analytics query failed."),
        },
      },
    },
    "/api/analytics": {
      get: {
        tags: ["Edge analytics"],
        operationId: "getAnalytics",
        summary: "Aggregated zone security events and AI scores",
        description:
          "Pulls the latest **500 rows per dataset**, so when `truncated` is true every total is a **floor** (\"500+\"), not an exact count. `prev` (the preceding same-length window, for trend deltas) is omitted when that window was itself truncated — a delta between two capped windows would read precise while meaning nothing. Bucket width is server-chosen: 5 min at 1 h, hourly to 48 h, daily beyond.",
        parameters: [param("Hours24")],
        responses: {
          "200": json("Summary, or `configured: false`.", { oneOf: [ref("AnalyticsResponse"), notConfigured()] }),
          "502": error("The GraphQL query failed."),
        },
      },
    },
    "/api/gateway-analytics": {
      get: {
        tags: ["Edge analytics"],
        operationId: "getGatewayAnalytics",
        summary: "Aggregated AI Gateway logs",
        description:
          "AI Gateway has no GraphQL dataset, so this pages the logs REST API (50 rows/page, up to 500) and sums Worker-side. **Account-scoped**: the logs include any other app using the same gateway. `truncated` means the totals are a floor.",
        parameters: [
          {
            name: "gatewayId",
            in: "query",
            required: false,
            description: "A gateway on the account. An unknown or malformed id falls back to the default gateway rather than erroring.",
            schema: { type: "string", pattern: "^[a-zA-Z0-9_-]{1,64}$" },
          },
          param("Hours24"),
        ],
        responses: {
          "200": json("Summary, or `configured: false`.", { oneOf: [ref("GatewayAnalyticsResponse"), notConfigured()] }),
          "502": error("The logs query failed."),
        },
      },
    },
    "/api/prompt-log": {
      get: {
        tags: ["Prompt log"],
        operationId: "getPromptLog",
        summary: "One page of PII-redacted prompts",
        description:
          "Filtering, sorting, search and paging all resolve **in SQL**, so a page is a true window onto the whole table. Only prompts that **reached the Worker** are here — edge-blocked requests never invoke it. Detections are not stored; join a row's `ray` to `/api/verdict`.",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 200, default: 25 } },
          { name: "offset", in: "query", schema: { type: "integer", minimum: 0, default: 0 } },
          { name: "route", in: "query", schema: { type: "string", enum: ["direct", "gateway"] } },
          {
            name: "outcome",
            in: "query",
            description: "Comma-separated subset of `reply`, `guardrails`, `external`, `skipped`, `error`. Unknown values are ignored.",
            schema: { type: "string" },
            example: "guardrails,error",
          },
          { name: "q", in: "query", description: "Substring search over prompt, reply, model and ray. `%` and `_` are matched literally.", schema: { type: "string" } },
          {
            name: "sort",
            in: "query",
            description: "Whitelisted column; anything else falls back to `ts`. `latency` sorts by Worker-observed latency.",
            schema: { type: "string", enum: ["ts", "outcome", "route", "model", "tokens", "redactions", "latency"], default: "ts" },
          },
          { name: "dir", in: "query", schema: { type: "string", enum: ["asc", "desc"], default: "desc" } },
          param("HoursAllTime"),
          param("Since"),
          param("Until"),
        ],
        responses: {
          "200": json("A page of rows, or the disabled / not-configured marker.", ref("PromptLogResponse")),
          "502": error("The D1 query failed."),
        },
      },
      delete: {
        tags: ["Prompt log"],
        operationId: "clearPromptLog",
        summary: "Delete every row in the prompt log",
        description: "**Destructive and unscoped** — there is no filter; it empties the table.",
        responses: {
          "200": json("Cleared, or the disabled / not-configured marker.", {
            oneOf: [obj({ configured: { const: true }, cleared: { const: true } }, ["configured", "cleared"]), notConfigured({ disabled: bool() })],
          }),
          "502": error("The delete failed."),
        },
      },
    },
    "/api/prompt-analytics": {
      get: {
        tags: ["Prompt log"],
        operationId: "getPromptAnalytics",
        summary: "SQL rollups over the prompt log",
        description:
          "Every rollup is a `GROUP BY` inside D1, so it stays correct however large the table gets. **Latency is Worker-observed only**: it starts just before the model call, so it excludes the edge AI Security scan, and requests the WAF blocked have no row at all — it cannot say what AI Security costs. It is grouped by `streamed` because the column means *total generation time* for non-streamed rows but *time to first byte* for streamed ones; the two must never be averaged. Rows written before migration `0002` have no latency, which `latencyCoverage` reports.",
        parameters: [param("HoursAllTime"), param("Since"), param("Until")],
        responses: {
          "200": json("Rollups, or the disabled / not-configured marker.", ref("PromptAnalyticsResponse")),
          "502": error("The D1 query failed."),
        },
      },
    },
    "/api/external-guardrails": {
      get: {
        tags: ["External guardrails"],
        operationId: "getExternalGuardrails",
        summary: "Every provider's configuration (API keys redacted)",
        description:
          "**The API key is write-only**: it is never returned, only `apiKeySet` and `apiKeyLast4`. `pipeline` is how enabled providers run. `configured: false` with a `setupHint` means the encryption secret (`GUARDRAIL_SECRET_KEY`), the D1 binding or a migration is missing.",
        responses: {
          "200": json("Configuration.", ref("ExternalGuardrailsState")),
          "502": json("D1 read failed.", ref("ExternalGuardrailsState")),
        },
      },
      put: {
        tags: ["External guardrails"],
        operationId: "updateExternalGuardrail",
        summary: "Update one provider",
        description: [
          "Omitted fields are unchanged. Any number of providers may be enabled; `PUT /api/external-guardrails/pipeline` decides how they run. Enabling is refused until the provider's key is saved (Prisma AIRS: API key; CrowdStrike AIDR: collector token), plus an AI security profile name for a provider that requires one (`requiresProfile` — Prisma AIRS), and for a provider that is not supported yet.",
          "",
          "The endpoint is chosen by `region` from the provider's official hosts only. There is no free-text URL: the stored key travels in a request header, so a typed endpoint would let anyone who can reach this API redirect it.",
          "",
          "`apiKey` is encrypted (AES-256-GCM) before it is stored; an empty string keeps the existing key. `clearApiKey: true` deletes it and disables the provider.",
        ].join("\n"),
        requestBody: { required: true, content: { "application/json": { schema: ref("ExternalGuardrailUpdate") } } },
        responses: {
          "200": json("The new state.", ref("ExternalGuardrailsState")),
          "400": json("Rejected — invalid field, unsupported provider, enabling without a key/profile, or not set up.", obj({ configured: bool(), error: str(), setupHint: str() }, ["error"])),
          "403": json("Not a guardrail admin (`access.mode` is `admin`) — the body says why.", obj({ configured: bool(), error: str(), access: ref("GuardrailAccess") }, ["error"])),
          "405": error("Not GET or PUT."),
          "502": json("D1 write failed.", obj({ configured: bool(), error: str() }, ["error"])),
        },
      },
    },
    "/api/external-guardrails/pipeline": {
      put: {
        tags: ["External guardrails"],
        operationId: "updateGuardrailPipeline",
        summary: "Set how enabled guardrails run",
        description: [
          "Omitted fields are unchanged. The edge WAF always runs first (before the Worker) and AI Gateway Guardrails run inside the model call, so only the external guardrails between them can be ordered.",
          "",
          "- `sequential`: in `order`; the first guardrail that stops the turn ends it and the rest do not run.",
          "- `parallel`: all at once; the model runs only if every one lets it through. The Worker waits for all of them (each capped by its own timeout).",
          "- `guardrailOnly`: never call the model — for testing the checks without model cost. Applies to chat and red-team runs alike.",
          "",
          "`order` must list every provider exactly once; anything else is rejected rather than repaired.",
        ].join("\n"),
        requestBody: { required: true, content: { "application/json": { schema: ref("GuardrailPipelineUpdate") } } },
        responses: {
          "200": json("The new state.", ref("ExternalGuardrailsState")),
          "400": json("Rejected — invalid field or not set up.", obj({ configured: bool(), error: str(), setupHint: str() }, ["error"])),
          "403": json("Not a guardrail admin — the body says why.", obj({ configured: bool(), error: str(), access: ref("GuardrailAccess") }, ["error"])),
          "405": error("Not a PUT."),
          "502": json("D1 write failed.", obj({ configured: bool(), error: str() }, ["error"])),
        },
      },
    },
    "/api/external-guardrails/report": {
      get: {
        tags: ["External guardrails"],
        operationId: "getExternalGuardrailReport",
        summary: "Prisma AIRS's own per-detection report for one scan",
        description: [
          "Fetches `GET /v1/scan/reports` from the **saved** region's official Prisma AIRS host with the **saved** key — the request never supplies a key or host. Use the `reportId` from an `ExternalGuardrailResult`.",
          "",
          "**Allowlisted, not passed through.** A PANW report can echo the prompt (DLP / toxic / injection snippets, masked text, URLs, code blocks, the grounding explanation). Only detector names, verdicts, actions, categories and counts are returned — never prompt content.",
          "",
          "`verdict` (what a detector concluded) and `action` (what the AI security profile does) are separate facts: a malicious verdict with action `allow` means the profile only alerts.",
          "",
          "CrowdStrike AIDR has no per-request report API, so this is Prisma AIRS only.",
        ].join("\n"),
        parameters: [
          { name: "provider", in: "query", required: true, schema: { type: "string", enum: ["prisma-airs"] } },
          { name: "reportId", in: "query", required: true, schema: { type: "string", pattern: "^[A-Za-z0-9-]{1,80}$" }, example: "R126fe3c6-7a24-4d02-8e26-70966b14d573" },
        ],
        responses: {
          "200": json(
            "The report, or `pending: true` when PANW has no report under this id yet (retry — this is neither an error nor \"nothing detected\").",
            { oneOf: [obj({ ok: { const: true }, report: ref("GuardrailReport") }, ["ok", "report"]), obj({ ok: { const: false }, pending: { const: true }, error: str() }, ["ok", "pending", "error"])] },
          ),
          "400": json("Not set up, no key saved, a provider other than prisma-airs, or a malformed reportId.", obj({ ok: { const: false }, error: str() }, ["ok", "error"])),
          "405": error("Not a GET."),
          "502": json("Prisma AIRS could not be reached or answered with an error.", obj({ ok: { const: false }, error: str(), httpStatus: int() }, ["ok", "error"])),
        },
      },
    },
    "/api/external-guardrails/test": {
      post: {
        tags: ["External guardrails"],
        operationId: "testExternalGuardrail",
        summary: "Scan a fixed prompt (benign or a known injection) with the saved configuration",
        description:
          "Uses the **saved** key, region and profile — it never accepts a key in the request, so it cannot be used to probe the provider with arbitrary credentials. Works whether or not the provider is enabled. `ok: false` means the provider could not be consulted (e.g. `Invalid API Key or OAuth Token`); it is not a verdict.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: obj(
                {
                  provider: ref("ExternalGuardrailProvider"),
                  sample: { type: "string", enum: ["benign", "attack", "pii"], description: "Which FIXED prompt to scan (`pii` carries the example SSN from Cato's API docs); anything else is `benign`. No prompt text is accepted." },
                },
                ["provider"],
              ),
            },
          },
        },
        responses: {
          "200": json(
            "The provider's answer.",
            obj(
              {
                ok: bool(),
                result: ref("ExternalGuardrailResult"),
                sample: { type: "string", enum: ["benign", "attack", "pii"] },
                verified: bool("This provider's parser has been checked against a real payload."),
                responseShape: {
                  type: ["object", "null"],
                  description: "The vendor response's field names, types and booleans — never a string's or number's value (src/responseShape.ts), except a string verdict field the provider names (Cato's `required_action.action_type`), shown as `string = <value>` only when the value is a bare lowercase token. Evidence for verifying an unverified parser.",
                },
              },
              ["ok", "result"],
            ),
          ),
          "400": error("Not set up, no key (or required profile) saved, or an unknown provider."),
          "403": json("Not a guardrail admin — a test sends the stored key to the vendor, so it is a write-level action.", obj({ configured: bool(), error: str(), access: ref("GuardrailAccess") }, ["error"])),
          "405": error("Not a POST."),
          "502": error("D1 read failed."),
        },
      },
    },
    "/api/redteam-runs": {
      get: {
        tags: ["Red team"],
        operationId: "getRedTeamRuns",
        summary: "List saved runs, or fetch one with its results",
        description:
          "Without `id`: the 50 most recently saved runs (ordered by server-assigned `id`, never the client-supplied `ts`), **metadata only** (a run can carry 500 result rows, so the list never pulls them). With `id`: that run plus its results.",
        parameters: [{ name: "id", in: "query", required: false, description: "A run id. Omit for the list.", schema: { type: "integer", minimum: 1 } }],
        responses: {
          "200": json("The list, one run, or `configured: false`.", ref("RedTeamRunsResponse")),
          "400": error("`id` is not a positive integer."),
          "404": json("No such run.", obj({ configured: { const: true }, run: { type: "null" }, results: arr({}) }, ["configured", "run", "results"])),
          "502": error("The D1 query failed."),
        },
      },
      post: {
        tags: ["Red team"],
        operationId: "saveRedTeamRun",
        summary: "Save a finished, client-scored run",
        description: [
          "Scoring happens in the browser, so the client POSTs a finished run. **This endpoint treats its input as hostile**: at most 500 results, every `state` checked against a whitelist, strings length-capped, score totals clamped (`reached + stopped` never above `scored`), only the 50 most recently saved runs kept (by `id`, not the client's `ts`), and each prompt passed through the same PII redaction as the prompt log and truncated to a 200-character preview. A result with an invalid shape is dropped; the request fails only when none survive.",
          "",
          "Send the **full prompt text**: the server redacts it. Never send a pre-redacted preview.",
        ].join("\n"),
        requestBody: { required: true, content: { "application/json": { schema: ref("RedTeamRunSaveRequest") } } },
        responses: {
          "201": json("Saved.", obj({ configured: { const: true }, id: int("The new run's id."), pruned: int("Older runs deleted to stay within 50.") }, ["configured", "id", "pruned"])),
          "200": json("`configured: false` — D1 is not bound or the migration has not run.", notConfigured()),
          "400": error("Not valid JSON, or the run failed validation."),
          "502": error("The D1 write failed."),
        },
      },
      delete: {
        tags: ["Red team"],
        operationId: "deleteRedTeamRun",
        summary: "Delete one saved run and its results",
        parameters: [{ name: "id", in: "query", required: true, schema: { type: "integer", minimum: 1 } }],
        responses: {
          "200": json("Deleted, or `configured: false`.", {
            oneOf: [obj({ configured: { const: true }, deleted: bool("False when no such run existed.") }, ["configured", "deleted"]), notConfigured()],
          }),
          "400": error("`id` is not a positive integer."),
          "502": error("The delete failed."),
        },
      },
    },
  },
  components: {
    securitySchemes: {
      AccessClientId: { type: "apiKey", in: "header", name: "CF-Access-Client-Id", description: "Cloudflare Access service token — client id. Not needed in a signed-in browser." },
      AccessClientSecret: { type: "apiKey", in: "header", name: "CF-Access-Client-Secret", description: "Cloudflare Access service token — client secret." },
    },
    parameters: {
      Hours24: {
        name: "hours",
        in: "query",
        description: "Window width in hours, ending now. Clamped to 1–168.",
        schema: { type: "integer", minimum: 1, maximum: 168, default: 24 },
      },
      HoursAllTime: {
        name: "hours",
        in: "query",
        description: "Window width in hours, ending now. **0 or absent = all time.** Clamped to 168. Ignored when `since` or `until` is given.",
        schema: { type: "integer", minimum: 0, maximum: 168, default: 0 },
      },
      Since: { name: "since", in: "query", description: "Window start, epoch **milliseconds**. Wins over `hours`.", schema: { type: "integer" } },
      Until: { name: "until", in: "query", description: "Window end, epoch **milliseconds**. Wins over `hours`.", schema: { type: "integer" } },
    },
    schemas: {
      Error: obj({ error: str("Human-readable message. Not a stable code.") }, ["error"]),

      // ── chat ────────────────────────────────────────────────────────────
      ChatTurn: obj({ role: { type: "string", enum: ["user", "assistant"] }, content: str() }, ["role", "content"]),
      ChatRequest: obj(
        {
          prompt: {
            type: "string",
            minLength: 1,
            maxLength: 8000,
            description:
              "The latest user message. **This is what the edge scan inspects.** Required and non-blank. Over 8000 characters is a 400 — never cut short, since the edge scanned the full body.",
          },
          model: str("An id from `/api/models`. Anything off the allowlist silently falls back to the default model."),
          systemPrompt: { type: "string", maxLength: 2000, description: "Trimmed and truncated to 2000 characters. Blank = the server default." },
          history: {
            type: "array",
            items: ref("ChatTurn"),
            description: "Prior turns, re-validated server-side: only `user`/`assistant`, newest kept, capped at 10 turns and 8000 characters.",
          },
          stream: bool("`true` → an SSE response instead of JSON."),
          gateway: bool("`true` → route through AI Gateway. Needs `CF_AIG_TOKEN`."),
          gatewayId: { type: "string", pattern: "^[a-zA-Z0-9_-]{1,64}$", description: "Gateway route only. An id not on the account falls back to the default gateway." },
          dynamicRoute: {
            type: "string",
            description:
              "Gateway route only. A Dynamic Route configured in the gateway dashboard — `demo-routes` or the dashboard's `dynamic/demo-routes`. **The route chooses the model**, so `model` is ignored. Letters, digits, `_` and `-` only (400 otherwise).",
          },
          routeMetadata: {
            type: "object",
            additionalProperties: true,
            description: "Gateway route only. Tags for AI Gateway logs and a route's Conditional nodes. At most 5 entries are kept; values are coerced to strings (sent as `cf-aig-metadata`).",
          },
          skipCache: bool("Gateway route only — `cf-aig-skip-cache`."),
          cacheTtl: { type: "integer", exclusiveMinimum: 0, description: "Gateway route only. Seconds — `cf-aig-cache-ttl`." },
          cacheKey: { type: "string", maxLength: 128, description: "Gateway route only — `cf-aig-cache-key`." },
          collectLog: bool("Gateway route only — `cf-aig-collect-log`. Unrelated to the D1 prompt log."),
          requestTimeoutMs: { type: "integer", exclusiveMinimum: 0, description: "Gateway route only — `cf-aig-request-timeout`." },
          maxAttempts: { type: "integer", minimum: 1, maximum: 5, description: "Gateway route only. Clamped to 1–5 — `cf-aig-max-attempts`." },
          retryDelayMs: { type: "integer", minimum: 0, maximum: 5000, description: "Gateway route only. Clamped to 0–5000 — `cf-aig-retry-delay`." },
          backoff: { type: "string", enum: ["constant", "linear", "exponential"], description: "Gateway route only — `cf-aig-backoff`. Any other value is ignored." },
          excludeFromLog: bool("`true` → do not write this turn to the D1 prompt log. Both routes. Has no effect while `PROMPT_LOG_ENABLED` is off, when nothing is written anyway."),
          includeRaw: bool("`true` → each `externalGuardrails.results[]` entry carries `raw`, the vendor's response body as it came back (capped at 32,000 characters). JSON responses only — never in the `x-external-guardrails` header, so a streamed reply has none — and never stored. It can quote the prompt and anything the vendor detected."),
        },
        ["prompt"],
      ),
      ChatReply: obj(
        {
          reply: str(),
          model: str("The model that actually ran. On a Dynamic Route this is the route's choice, not the requested model."),
          ray: nullable("string", "The request's `cf-ray` id — the join key to `/api/verdict`. Null when the request carried none (local `wrangler dev`)."),
          usage: obj(
            {
              prompt_tokens: int(),
              completion_tokens: int(),
              total_tokens: int(),
              estimated: bool("True when the model reported no usage and the Worker estimated (~4 characters/token)."),
            },
            ["prompt_tokens", "completion_tokens", "total_tokens", "estimated"],
          ),
          cost: nullable("number", "Estimated USD from Workers AI unit pricing. 0 for a cache hit; null for a model with no price entry."),
          gateway: ref("GatewayMeta"),
          dynamicRoute: str("Echoed when the reply came from a Dynamic Route."),
          externalGuardrails: ref("GuardrailPipelineResult"),
        },
        ["reply", "model", "ray", "usage", "cost"],
      ),
      GatewayMeta: obj(
        {
          gatewayId: str(),
          cached: nullable("boolean", "Null when the gateway reported no cache status."),
          latencyMs: int("Worker-observed round trip to the gateway."),
          logId: nullable("string"),
          guarded: bool("The gateway has Guardrails enabled."),
        },
        ["gatewayId", "guarded"],
        "Present on the gateway route only.",
      ),
      GuardrailsBlocked: obj(
        {
          guardrailsBlocked: { const: true },
          direction: { type: "string", enum: ["prompt", "response"], description: "Guardrails error 2016 (prompt) or 2017 (response)." },
          model: str(),
          gateway: obj({ gatewayId: str(), guarded: bool() }, ["gatewayId", "guarded"]),
          detail: str("The upstream error text."),
        },
        ["guardrailsBlocked", "direction", "model", "gateway", "detail"],
        "An AI Gateway Guardrails block. Note the HTTP status is **200**, unlike a WAF block.",
      ),
      WafBlock: {
        type: "object",
        description:
          "Body written by the zone's WAF custom rule, so this is **operator-configured, not a fixed contract**. Shown is the deployed zone's Custom JSON; a rule left on Cloudflare's default returns an HTML page instead.",
        properties: {
          error: { type: "string", examples: ["request_blocked"] },
          reason_code: { type: "string", examples: ["LLM_PII_BLOCKED"] },
          message: str(),
          detail: str(),
          support_hint: str(),
        },
        additionalProperties: true,
      },

      // ── external guardrails ─────────────────────────────────────────────
      ExternalGuardrailProvider: {
        type: "string",
        enum: ["prisma-airs", "crowdstrike-aidr", "cisco-ai-defense", "lakera-guard", "cato-ai-security"],
        description: "`cisco-ai-defense`, `lakera-guard` and `cato-ai-security` are configurable but `verified: false` until their parser has been checked against a real payload.",
      },
      ExternalGuardrailResult: obj(
        {
          provider: ref("ExternalGuardrailProvider"),
          outcome: {
            type: "string",
            enum: ["allow", "block", "error"],
            description: "What the Worker did. `error` = the provider could not be consulted — **never a verdict**; `failedOpen` says whether the turn then ran unscanned.",
          },
          failedOpen: bool("`outcome` error under fail-open: the model ran without a scan."),
          action: { type: "string", enum: ["allow", "block"], description: "The provider's own verdict, when it gave one." },
          category: str("Prisma AIRS: `benign` or `malicious`. Absent for CrowdStrike AIDR."),
          detected: arr({
            type: "string",
            description:
              "Prisma AIRS: `injection`, `dlp`, `toxic_content`, `url_cats`, `malicious_code`, `agent`, `topic_violation`. CrowdStrike AIDR: detector names such as `malicious_prompt`, `confidential_and_pii_entity`, `secret_and_key_entity`, `topic`.",
          }),
          scanId: nullable("string", "Prisma AIRS `scan_id` (look it up in Strata Cloud Manager) or CrowdStrike AIDR `request_id`."),
          reportId: nullable("string"),
          profileName: nullable("string"),
          latencyMs: int("Worker-observed round trip to the provider."),
          error: str(),
          httpStatus: int("The provider's HTTP status, when it answered."),
          incomplete: bool("A verdict was returned but at least one detection service timed out or errored."),
          policy: str("CrowdStrike AIDR: the policy its collector token evaluated."),
          summary: str("CrowdStrike AIDR: its own one-line summary of the result."),
          transformed: bool("CrowdStrike AIDR redacted part of the prompt. **This app does not apply the redaction** — the model receives the original prompt."),
          detectOnly: bool("Lakera Guard in Detect mode: detectors fired, but the project only logs them, so the outcome is `allow`. Allow with alerts — not a clean pass."),
          raw: obj(
            {
              status: { type: "integer", description: "The vendor's HTTP status." },
              body: { description: "The response body: parsed JSON when `json`, otherwise the text." },
              json: bool(),
              truncated: bool("The body exceeded 32,000 characters and was cut (it is then text)."),
            },
            ["status", "body", "json", "truncated"],
            "Only when the chat request set `includeRaw`. The vendor's response as it came back — never the request, which carries the key.",
          ),
        },
        ["provider", "outcome", "latencyMs"],
      ),
      SeriesReadCoverage: {
        type: "string",
        enum: ["partial", "none"],
        description:
          "Present only when the row cap was hit (rows are read newest first). `none` = the bucket is older than the oldest row read: **not read — its zeros mean unknown, not zero**. `partial` = the bucket holding the oldest row read: its counts are a floor. Absent = fully read.",
      },
      GuardrailReportDetection: obj(
        {
          service: str("PANW's `detection_service`, e.g. `dlp`, `urlf`, `prompt injection`."),
          dataType: nullable("string", "`prompt`, `response` or `tool_event`."),
          verdict: nullable("string", "What the detector concluded: `malicious` or `benign`."),
          action: nullable("string", "What the AI security profile does about it: `block` or `allow`."),
          details: arr({ type: "string", description: "Allowlisted facts — profile and pattern names with match counts, categories, risk levels. Never prompt content." }),
        },
        ["service", "dataType", "verdict", "action", "details"],
      ),
      GuardrailReport: obj(
        {
          provider: { type: "string", enum: ["prisma-airs"] },
          reportId: str(),
          scanId: nullable("string"),
          transactionId: nullable("string", "PANW's own `transaction_id` (e.g. `pan_…`). **Not** the `tr_id` this app sends — measured on prod, PANW does not echo it here."),
          source: nullable("string", "e.g. `AI-Runtime-API`."),
          detections: arr(ref("GuardrailReportDetection")),
        },
        ["provider", "reportId", "scanId", "transactionId", "source", "detections"],
      ),
      GuardrailPipelineMode: { type: "string", enum: ["sequential", "parallel"] },
      GuardrailPipelineConfig: obj(
        {
          mode: ref("GuardrailPipelineMode"),
          guardrailOnly: bool("Never call the model (chat and red-team runs)."),
          order: arr(ref("ExternalGuardrailProvider")),
        },
        ["mode", "guardrailOnly", "order"],
      ),
      GuardrailPipelineUpdate: obj(
        {
          mode: ref("GuardrailPipelineMode"),
          guardrailOnly: bool(),
          order: { ...arr(ref("ExternalGuardrailProvider")), description: "Every provider exactly once." },
        },
      ),
      GuardrailPipelineResult: obj(
        {
          mode: ref("GuardrailPipelineMode"),
          guardrailOnly: bool(),
          results: arr(ref("ExternalGuardrailResult")),
          notRun: arr(obj({ provider: ref("ExternalGuardrailProvider"), reason: str() }, ["provider", "reason"])),
          stoppedBy: { anyOf: [ref("ExternalGuardrailProvider"), { type: "null" }], description: "The guardrail whose result stopped the turn, or null." },
          latencyMs: int("Wall clock for the whole pipeline."),
        },
        ["mode", "guardrailOnly", "results", "notRun", "stoppedBy", "latencyMs"],
        "What the pipeline did for one prompt. `results` is in run order (sequential) or configured order (parallel); `notRun` lists enabled guardrails skipped because an earlier one stopped the turn.",
      ),
      ExternalGuardrailBlocked: obj(
        {
          externalGuardrailBlocked: { const: true },
          externalGuardrails: ref("GuardrailPipelineResult"),
          model: str(),
          ray: nullable("string"),
        },
        ["externalGuardrailBlocked", "externalGuardrails", "model", "ray"],
        "The turn was stopped by an external guardrail: its verdict was `block`, or it could not be consulted and its fail mode is `block`. The deciding result is the one whose `provider` equals `externalGuardrails.stoppedBy`; tell the two cases apart by its `outcome`. HTTP status is **200**.",
      ),
      GuardrailOnlyResult: obj(
        {
          guardrailOnly: { const: true },
          externalGuardrails: ref("GuardrailPipelineResult"),
          model: str("The model that WOULD have run."),
          ray: nullable("string"),
        },
        ["guardrailOnly", "externalGuardrails", "model", "ray"],
        "Guardrail-only mode: the prompt passed the edge and every enabled external guardrail, and the model was deliberately not called. No reply, usage or cost. HTTP status is **200**.",
      ),
      ExternalGuardrailConfig: obj(
        {
          provider: ref("ExternalGuardrailProvider"),
          label: str(),
          supported: bool("False → listed for context, cannot be configured yet."),
          verified: bool("False → built from the vendor's docs and not yet checked against a real response (Cisco AI Defense, Lakera Guard, Cato AI Security until verified)."),
          enabled: bool(),
          region: str(),
          endpoint: str("Full scan URL derived from `region` (read-only)."),
          regions: arr(obj({ id: str(), label: str(), url: str() }, ["id", "label", "url"])),
          profileName: str("Prisma AIRS AI security profile name (required by its API)."),
          requiresProfile: bool("True for Prisma AIRS (AI security profile) and Lakera Guard (project ID); false where the policy rides on the key (CrowdStrike AIDR, Cisco AI Defense)."),
          profileLabel: str("What `profileName` is called for this provider: `AI security profile name` or `Project ID`; empty when `requiresProfile` is false."),
          keyLabel: str("What the secret is called for this provider: `API key` or `Collector token`."),
          vendor: str("Whose official hosts the key is sent to."),
          failMode: { type: "string", enum: ["block", "allow"], description: "What happens when the provider errors or times out." },
          apiKeySet: bool(),
          apiKeyLast4: nullable("string", "The only part of the key ever returned."),
          updatedAt: nullable("integer", "Epoch ms."),
        },
        ["provider", "label", "supported", "enabled", "region", "endpoint", "regions", "profileName", "requiresProfile", "profileLabel", "keyLabel", "vendor", "failMode", "apiKeySet", "apiKeyLast4", "updatedAt"],
      ),
      ExternalGuardrailsState: obj(
        {
          configured: bool("False → `setupHint` says what is missing."),
          providers: arr(ref("ExternalGuardrailConfig")),
          pipeline: ref("GuardrailPipelineConfig"),
          setupHint: str(),
          error: str(),
          access: ref("GuardrailAccess"),
        },
        ["configured", "providers", "pipeline"],
      ),
      GuardrailAccess: obj(
        {
          canEdit: bool("Whether THIS caller may change the settings (PUT, pipeline PUT, test POST)."),
          mode: {
            type: "string",
            enum: ["open", "admin"],
            description:
              "`open`: no `GUARDRAIL_ADMIN_EMAILS` secret is set, so anything Access lets in may write. `admin`: only the listed emails, verified from Access's signed JWT; service tokens can read, never write.",
          },
          who: { type: ["string", "null"], description: "The verified email, or `service token <client id>`; null when unknown." },
          reason: str("Why `canEdit` is false."),
        },
        ["canEdit", "mode", "who"],
      ),
      ExternalGuardrailUpdate: obj(
        {
          provider: ref("ExternalGuardrailProvider"),
          enabled: bool("Any number may be enabled; the pipeline decides how they run."),
          region: str("One of the provider's `regions[].id`."),
          profileName: { type: "string", maxLength: 200 },
          failMode: { type: "string", enum: ["block", "allow"] },
          apiKey: { type: "string", maxLength: 4096, description: "Replaces the stored key. Empty keeps it. Never echoed back." },
          clearApiKey: bool("Delete the stored key (also disables the provider)."),
        },
        ["provider"],
      ),

      // ── models / meta ───────────────────────────────────────────────────
      Model: obj({ id: str(), label: str(), priceIn: num("USD per million input tokens."), priceOut: num("USD per million output tokens.") }, ["id", "label", "priceIn", "priceOut"]),
      GatewayOption: obj({ id: str(), label: str(), guarded: bool("Guardrails are enabled on this gateway.") }, ["id", "label", "guarded"]),
      ModelsResponse: obj(
        {
          default: str("Default model id."),
          models: arr(ref("Model")),
          defaultSystemPrompt: str(),
          maxSystemPromptLen: int(),
          gateways: arr(ref("GatewayOption")),
          defaultGateway: str("Absent when no gateway is configured."),
          limits: obj({ maxAttempts: int(), retryDelayMs: int() }, ["maxAttempts", "retryDelayMs"], "Caps the Worker clamps the numeric gateway settings to."),
          promptLog: obj(
            {
              enabled: bool("Prompt-log feature flag AND a bound D1."),
              maxAgeDays: int("Retention: rows older than this are deleted (90)."),
              maxRows: int("Retention: only this many newest rows are kept (1000)."),
            },
            ["enabled", "maxAgeDays", "maxRows"],
          ),
        },
        ["default", "models", "defaultSystemPrompt", "maxSystemPromptLen", "gateways", "limits", "promptLog"],
      ),

      // ── edge analytics ──────────────────────────────────────────────────
      VerdictResponse: obj(
        {
          configured: bool("False when `CF_ANALYTICS_TOKEN` / `CF_ZONE_ID` is missing; nothing else is set then."),
          ray: str(),
          found: bool("False until the request has been ingested (~1–2 min), or when `tooOld`."),
          tooOld: bool("The request predates the analytics retention window — waiting cannot help."),
          retentionDays: int(),
          httpStatus: nullable("integer"),
          securityAction: nullable("string", "First-class WAF action, e.g. `block`, `log`."),
          securitySource: nullable("string"),
          ai: {
            oneOf: [
              obj(
                {
                  injectionScore: nullable("integer", "1–99, **low = likely attack**; 100 means not scored."),
                  piiCategories: arr(str()),
                  unsafeTopicCategories: arr(str()),
                  customTopicCategories: arr(obj({ label: str(), score: int() }, ["label", "score"])),
                  customTopicScoreMin: nullable("integer", "Custom-topic scores invert the same way: lower = stronger match."),
                },
                ["injectionScore", "piiCategories", "unsafeTopicCategories", "customTopicCategories", "customTopicScoreMin"],
              ),
              { type: "null" },
            ],
          },
          rules: arr(obj({ ruleId: str(), action: str(), description: str(), source: str() }, ["ruleId", "action", "description", "source"])),
          cfLlmLabeled: bool("The endpoint carries the `cf-llm` managed label in Web Assets."),
          scored: bool("AI Security actually scored the prompt."),
          error: str(),
        },
        ["configured", "ray"],
      ),
      ZoneRulesResponse: obj(
        {
          configured: bool(),
          source: { type: "string", enum: ["live", "fallback"], description: "`fallback` = the lookup was unavailable and the client uses its static mirror." },
          rules: arr(
            obj(
              {
                id: str(),
                name: str("The rule's dashboard description — what firewall events report."),
                action: str(),
                expression: str(),
                enabled: bool(),
                llm: bool("The expression references `cf.llm.*` — an AI Security rule."),
              },
              ["id", "name", "action", "expression", "enabled", "llm"],
            ),
          ),
          error: str("Why the live lookup failed, when `source` is `fallback`."),
        },
        ["configured", "source", "rules"],
      ),
      NeuronsResponse: obj(
        {
          configured: { const: true },
          totalNeurons: num(),
          requestCount: int(),
          freeLimit: int(),
          overageUsdPer1k: num(),
          pctUsed: num(),
          resetsAt: { type: "string", format: "date-time" },
        },
        ["configured", "totalNeurons", "requestCount", "freeLimit", "overageUsdPer1k", "pctUsed", "resetsAt"],
      ),
      SeriesBucket: { type: "string", enum: ["5m", "hour", "day"], description: "Chosen server-side from the window: 5 min at 1 h, hourly to 48 h, daily beyond." },
      AnalyticsResponse: obj(
        {
          configured: { const: true },
          rangeHours: int(),
          since: { type: "string", format: "date-time" },
          until: { type: "string", format: "date-time" },
          totalEvents: int("A **floor** when `truncated`."),
          truncated: bool("A dataset returned exactly the 500-row cap."),
          prev: obj(
            { totalEvents: int(), blocked: int(), logged: int(), piiRequests: int() },
            ["totalEvents", "blocked", "logged", "piiRequests"],
            "The preceding same-length window. Omitted when that window was itself truncated.",
          ),
          actions: { type: "object", additionalProperties: { type: "integer" }, description: "Raw WAF action → count." },
          topRules: arr(obj({ name: str(), action: str(), count: int() }, ["name", "action", "count"])),
          series: arr(obj({ t: { type: "string", format: "date-time" }, block: int(), log: int(), other: int(), read: ref("SeriesReadCoverage") }, ["t", "block", "log", "other"])),
          bucket: ref("SeriesBucket"),
          aiScored: int("Requests AI Security actually scored."),
          scoreBuckets: arr(obj({ label: str(), count: int() }, ["label", "count"])),
          piiRequests: int(),
          unsafeTopics: arr(obj({ code: str("S1–S14."), count: int() }, ["code", "count"])),
          piiCategories: arr(obj({ name: str(), count: int() }, ["name", "count"])),
          customTopics: arr(obj({ label: str(), count: int(), avgStrength: num("Mean of (100 − score); higher = stronger match.") }, ["label", "count", "avgStrength"])),
          scannedRequests: int("`/api/chat` rows seen in the window."),
          labeledRequests: int("…of those, rows carrying the `cf-llm` label."),
        },
        ["configured", "rangeHours", "since", "until", "totalEvents", "actions", "topRules", "series", "bucket", "aiScored", "scoreBuckets", "piiRequests", "unsafeTopics", "piiCategories", "customTopics", "scannedRequests", "labeledRequests"],
      ),
      GatewayAnalyticsResponse: obj(
        {
          configured: { const: true },
          gatewayId: str(),
          guarded: bool(),
          rangeHours: int(),
          since: { type: "string", format: "date-time" },
          until: { type: "string", format: "date-time" },
          requests: int(),
          cachedRequests: int(),
          totalCost: num(),
          tokensIn: int(),
          tokensOut: int(),
          avgMs: num(),
          p50Ms: num(),
          p95Ms: num(),
          errors: int("Requests with `success === false`."),
          statusCodes: arr(obj({ code: int(), count: int() }, ["code", "count"])),
          byModel: arr(obj({ model: str(), count: int(), tokensIn: int(), tokensOut: int(), cost: num() }, ["model", "count", "tokensIn", "tokensOut", "cost"])),
          series: arr(obj({ t: { type: "string", format: "date-time" }, hit: int(), miss: int(), error: int(), read: ref("SeriesReadCoverage") }, ["t", "hit", "miss", "error"])),
          bucket: ref("SeriesBucket"),
          truncated: bool("Hit the row cap — totals are a floor."),
        },
        ["configured", "gatewayId", "guarded", "rangeHours", "since", "until", "requests", "cachedRequests", "totalCost", "tokensIn", "tokensOut", "avgMs", "p50Ms", "p95Ms", "errors", "statusCodes", "byModel", "series", "bucket", "truncated"],
      ),

      // ── prompt log ──────────────────────────────────────────────────────
      PromptLogRow: obj(
        {
          ray: str("The join key to `/api/verdict`."),
          ts: int("Epoch ms."),
          route: { type: "string", enum: ["direct", "gateway"] },
          model: str(),
          gatewayId: nullable("string", "Null on the direct route."),
          guarded: flag("Gateway has Guardrails."),
          outcome: { type: "string", enum: ["reply", "guardrails", "external", "skipped", "error"], description: "`external` = an external guardrail blocked the turn; `skipped` = guardrail-only mode let it through and no model was called. In both, no model ran, so `latencyMs` is null." },
          prompt: str("PII-redacted at write time."),
          reply: nullable("string", "PII-redacted. Null for a blocked turn, or a streamed turn whose stream has not finished (or was never captured)."),
          redactions: int("PII spans masked across prompt + reply."),
          promptTokens: nullable("integer"),
          completionTokens: nullable("integer"),
          latencyMs: nullable("integer", "Worker-observed only. **Meaning depends on `streamed`**: total generation time when 0, time to first byte when 1. Null on rows written before migration `0002`."),
          streamed: flag("1 = `latencyMs` is time-to-first-byte."),
        },
        ["ray", "ts", "route", "model", "gatewayId", "guarded", "outcome", "prompt", "reply", "redactions", "promptTokens", "completionTokens", "latencyMs", "streamed"],
      ),
      PromptLogResponse: {
        oneOf: [
          obj(
            {
              configured: { const: true },
              rows: arr(ref("PromptLogRow")),
              filtered: int("Rows matching the filters — drives the page count."),
              total: int("Rows in the whole table, regardless of filters."),
              limit: int(),
              offset: int(),
              retention: ref("PromptLogRetention"),
            },
            ["configured", "rows", "filtered", "total", "limit", "offset", "retention"],
          ),
          notConfigured({ disabled: bool("The operator turned the feature off (`PROMPT_LOG_ENABLED`) — as opposed to D1 simply not being bound.") }),
        ],
      },
      PromptLogRetention: obj(
        {
          maxAgeDays: int("Rows older than this are deleted (90)."),
          maxRows: int("At most this many newest rows are kept (1000)."),
          rows: int("Rows held now, across all time."),
          oldestTs: nullable("integer", "Epoch ms of the oldest row held, or null when empty."),
          windowPartial: bool(
            "The requested window reaches past what the log keeps — older than `maxAgeDays` (or all time), or before `oldestTs` while the row cap is full. Every count in that window is then **at least**, not a total.",
          ),
        },
        ["maxAgeDays", "maxRows", "rows", "oldestTs", "windowPartial"],
        "Retention is applied when a prompt is written (same D1 batch as the insert), not on a timer, so a row past the limits can survive until the next write.",
      ),
      PromptAnalyticsResponse: {
        oneOf: [
          obj(
            {
              configured: { const: true },
              total: int(),
              withPii: int("Prompts where redaction fired at least once."),
              redactions: int(),
              promptTokens: int(),
              completionTokens: int(),
              byOutcome: arr(obj({ outcome: str(), count: int() }, ["outcome", "count"])),
              byRoute: arr(obj({ route: str(), count: int() }, ["route", "count"])),
              byModel: arr(obj({ model: str(), count: int(), promptTokens: int(), completionTokens: int() }, ["model", "count", "promptTokens", "completionTokens"])),
              repeated: arr(obj({ prompt: str(), count: int(), redactions: int() }, ["prompt", "count", "redactions"])),
              series: arr(obj({ t: { type: "string", format: "date-time" }, reply: int(), guardrails: int(), external: int(), skipped: int(), error: int() }, ["t", "reply", "guardrails", "external", "skipped", "error"])),
              bucket: ref("SeriesBucket"),
              firstTs: nullable("integer"),
              lastTs: nullable("integer"),
              latency: arr(
                obj(
                  {
                    route: str(),
                    guarded: flag("Gateway has Guardrails."),
                    streamed: flag("Never aggregated across this: 1 = time-to-first-byte, 0 = total generation time."),
                    n: int(),
                    p50: nullable("integer"),
                    p95: nullable("integer"),
                    max: nullable("integer"),
                  },
                  ["route", "guarded", "streamed", "n", "p50", "p95", "max"],
                ),
              ),
              latencyCoverage: obj({ withLatency: int(), total: int() }, ["withLatency", "total"], "How many rows in the window have a latency at all — old rows never will."),
              retention: ref("PromptLogRetention"),
            },
            ["configured", "total", "withPii", "redactions", "promptTokens", "completionTokens", "byOutcome", "byRoute", "byModel", "repeated", "series", "bucket", "firstTs", "lastTs", "latency", "latencyCoverage", "retention"],
          ),
          notConfigured({ disabled: bool() }),
        ],
      },

      // ── red team ────────────────────────────────────────────────────────
      RtResultState: {
        type: "string",
        enum: ["block", "challenge", "log", "allow", "denied", "guardrails", "external", "pending", "error"],
        description:
          "`allow` and `log` mean the request **reached the model**; `block` and `challenge` mean the edge stopped it. `denied`, `guardrails` (AI Gateway Guardrails), `external` (an external guardrail such as Prisma AIRS), `pending` and `error` are not edge verdicts and are excluded from the scored denominator.",
      },
      RedTeamRunRow: obj(
        {
          id: int(),
          ts: int("Epoch ms — client-supplied."),
          label: nullable("string"),
          route: { type: "string", enum: ["direct", "gateway"] },
          gatewayId: nullable("string"),
          guarded: flag("Gateway has Guardrails."),
          model: nullable("string"),
          dynamicRoute: nullable("string", "The Dynamic Route the run went through, or null. A route chooses the model, so runs that differ here are not comparable."),
          corpusName: str(),
          corpusSize: int(),
          corpusFingerprint: str("Hash over the sorted attack keys. `diffRuns` refuses to compare runs whose fingerprints differ."),
          delayMs: int(),
          total: int(),
          scored: int("reached + stopped — the denominator."),
          reached: int("log + allow."),
          stopped: int("block + challenge."),
          denied: int(),
          guardrails: int(),
          external: int("Blocked by an external guardrail (Prisma AIRS)."),
          skipped: int("Of `reached`: got past every check in guardrail-only mode, so no model answered."),
          pending: int(),
          error: int(),
          reachedPct: int("reached / scored, 0 when nothing was scored — which means *nothing was measured*, not a perfect block rate."),
        },
        ["id", "ts", "label", "route", "gatewayId", "guarded", "model", "dynamicRoute", "corpusName", "corpusSize", "corpusFingerprint", "delayMs", "total", "scored", "reached", "stopped", "denied", "guardrails", "external", "skipped", "pending", "error", "reachedPct"],
      ),
      RedTeamResultRow: obj(
        {
          attackKey: str("Stable join key across runs: the id for the built-in corpus, a hash of the prompt for a custom one."),
          attackId: str("This run's own display id only."),
          category: str(),
          severity: nullable("string", "Scan-only; null for a custom CSV attack."),
          state: ref("RtResultState"),
          ray: nullable("string"),
          ts: nullable("integer"),
          promptPreview: nullable("string", "Redacted and truncated to ~200 characters — never the raw prompt."),
          vendors: {
            anyOf: [ref("RedTeamVendorVerdicts"), { type: "null" }],
            description: "Each external guardrail's verdict on this prompt. Null when the response carried no pipeline (the edge refused it) or the run was saved before migration 0007 — *not recorded*, never a miss.",
          },
          expected: { anyOf: [{ type: "string", enum: ["allow"] }, { type: "null" }], description: "`allow` = a harmless row, scored only for false blocks. Never counted in the run's totals or by `diffRuns`." },
          topic: nullable("string", "The benchmark topic: scan category, or the CSV goal (redacted, ≤120 chars)."),
          lang: nullable("string", "Writing-system label from the full prompt, e.g. `Thai`, `Latin script`, `Thai + Latin script`."),
        },
        ["attackKey", "attackId", "category", "severity", "state", "ray", "ts", "promptPreview", "vendors", "expected", "topic", "lang"],
      ),
      RedTeamVendorVerdicts: obj(
        {
          mode: { type: "string", enum: ["parallel", "sequential"] },
          verdicts: arr(
            obj(
              {
                provider: ref("ExternalGuardrailProvider"),
                verdict: { type: "string", enum: ["block", "allow", "alerts", "error", "notRun"], description: "`alerts` = Detect mode flagged but let it through; `error` is not a verdict; `notRun` = an earlier guardrail stopped it (sequential)." },
                latencyMs: { type: "integer", minimum: 0, maximum: 60000, description: "That guardrail's own call as the Worker timed it (Cloudflare → vendor and back). Optional; an out-of-range value is dropped on its own, never the verdict." },
              },
              ["provider", "verdict"],
            ),
          ),
          latencyMs: { type: "integer", minimum: 0, maximum: 60000, description: "The whole guardrail stage for this prompt: the slowest call in parallel mode, the sum in sequential." },
        },
        ["mode", "verdicts"],
        "Provider ids and verdict words only — never a vendor's text. The server stores it all-or-nothing: one unknown provider or verdict drops the whole value.",
      ),
      RedTeamRunsResponse: {
        oneOf: [
          obj({ configured: { const: true }, runs: arr(ref("RedTeamRunRow")) }, ["configured", "runs"]),
          obj({ configured: { const: true }, run: ref("RedTeamRunRow"), results: arr(ref("RedTeamResultRow")) }, ["configured", "run", "results"]),
          notConfigured(),
        ],
      },
      RedTeamRunSaveRequest: obj(
        {
          ts: int("Epoch ms. Defaults to now. **Known limitation:** it also orders the retention prune, so a far-future value is never pruned."),
          label: { type: "string", maxLength: 200 },
          route: { type: "string", enum: ["direct", "gateway"] },
          gatewayId: { type: "string", maxLength: 300 },
          guarded: bool(),
          model: { type: "string", maxLength: 300 },
          dynamicRoute: { type: "string", maxLength: 300, description: "Ignored unless `route` is `gateway`." },
          corpusName: { type: "string", minLength: 1, maxLength: 300 },
          corpusSize: { type: "integer", minimum: 0, maximum: 500, description: "The corpus the run was fired at — may exceed `results.length` for a stopped run." },
          corpusFingerprint: { type: "string", minLength: 1, maxLength: 300 },
          delayMs: { type: "integer", minimum: 0, maximum: 60000 },
          total: int(),
          scored: int(),
          reached: int(),
          stopped: int(),
          denied: int(),
          guardrails: int(),
          external: int(),
          skipped: int("Of `reached`, how many were not sent to the model (guardrail-only). Clamped to `reached`."),
          pending: int(),
          error: int(),
          reachedPct: { type: "integer", minimum: 0, maximum: 100 },
          results: {
            type: "array",
            minItems: 1,
            maxItems: 500,
            items: obj(
              {
                attackKey: { type: "string", minLength: 1, maxLength: 300 },
                attackId: { type: "string", minLength: 1, maxLength: 300 },
                category: { type: "string", minLength: 1, maxLength: 300 },
                severity: { type: "string", maxLength: 20 },
                state: ref("RtResultState"),
                ray: { type: "string", maxLength: 64 },
                ts: int(),
                prompt: { type: "string", description: "The **full** prompt. The server redacts it and stores at most a 200-character preview." },
                vendors: { anyOf: [ref("RedTeamVendorVerdicts"), { type: "null" }] },
                expected: { anyOf: [{ type: "string", enum: ["allow"] }, { type: "null" }], description: "Mark a harmless row. Its result is stored but must not be counted in the totals above." },
                topic: { type: "string", description: "Redacted server-side, stored to 120 characters." },
                lang: { type: "string", maxLength: 60, pattern: "^[A-Za-z][A-Za-z ()+]*$", description: "A languageOf() label; anything else is stored as null." },
              },
              ["attackKey", "attackId", "category", "state"],
            ),
          },
        },
        ["route", "corpusName", "corpusFingerprint", "results"],
        "The totals (`total`…`reachedPct`) are trusted-and-clamped rather than recomputed: scoring stays client-side.",
      ),
    },
  },
} as const;

export type OpenApiDocument = typeof openapi;
