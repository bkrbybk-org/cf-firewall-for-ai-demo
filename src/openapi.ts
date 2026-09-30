// OpenAPI 3.1 description of the Worker's HTTP API, served at GET /api/openapi.json
// and rendered by Swagger UI at /api-docs/.
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
    { name: "Meta", description: "Configuration the client reads to build its controls." },
  ],
  security: [{ AccessClientId: [], AccessClientSecret: [] }, {}],
  paths: {
    "/api/openapi.json": {
      get: {
        tags: ["Meta"],
        operationId: "getOpenApi",
        summary: "This document",
        description: "The OpenAPI 3.1 description Swagger UI renders at `/api-docs/`.",
        responses: { "200": { description: "OpenAPI 3.1 document.", content: { "application/json": { schema: { type: "object" } } } } },
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
        ].join("\n"),
        requestBody: {
          required: true,
          content: { "application/json": { schema: ref("ChatRequest") } },
        },
        responses: {
          "200": {
            description: "The reply — JSON, or an SSE stream when `stream: true`.",
            content: {
              "application/json": {
                schema: { oneOf: [ref("ChatReply"), ref("GuardrailsBlocked")] },
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
            description: "Comma-separated subset of `reply`, `guardrails`, `error`.",
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
    "/api/redteam-runs": {
      get: {
        tags: ["Red team"],
        operationId: "getRedTeamRuns",
        summary: "List saved runs, or fetch one with its results",
        description:
          "Without `id`: the newest 50 runs, **metadata only** (a run can carry 500 result rows, so the list never pulls them). With `id`: that run plus its results.",
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
          "Scoring happens in the browser, so the client POSTs a finished run. **This endpoint treats its input as hostile**: at most 500 results, every `state` checked against a whitelist, strings length-capped, score totals clamped, only the newest 50 runs kept, and each prompt passed through the same PII redaction as the prompt log and truncated to a 200-character preview. A result with an invalid shape is dropped; the request fails only when none survive.",
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
          prompt: { type: "string", minLength: 1, description: "The latest user message. **This is what the edge scan inspects.** Required and non-blank." },
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
          promptLog: obj({ enabled: bool() }, ["enabled"], "Prompt-log feature flag AND a bound D1."),
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
          series: arr(obj({ t: { type: "string", format: "date-time" }, block: int(), log: int(), other: int() }, ["t", "block", "log", "other"])),
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
          series: arr(obj({ t: { type: "string", format: "date-time" }, hit: int(), miss: int(), error: int() }, ["t", "hit", "miss", "error"])),
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
          outcome: { type: "string", enum: ["reply", "guardrails", "error"] },
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
            },
            ["configured", "rows", "filtered", "total", "limit", "offset"],
          ),
          notConfigured({ disabled: bool("The operator turned the feature off (`PROMPT_LOG_ENABLED`) — as opposed to D1 simply not being bound.") }),
        ],
      },
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
              series: arr(obj({ t: { type: "string", format: "date-time" }, reply: int(), guardrails: int(), error: int() }, ["t", "reply", "guardrails", "error"])),
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
            },
            ["configured", "total", "withPii", "redactions", "promptTokens", "completionTokens", "byOutcome", "byRoute", "byModel", "repeated", "series", "bucket", "firstTs", "lastTs", "latency", "latencyCoverage"],
          ),
          notConfigured({ disabled: bool() }),
        ],
      },

      // ── red team ────────────────────────────────────────────────────────
      RtResultState: {
        type: "string",
        enum: ["block", "challenge", "log", "allow", "denied", "guardrails", "pending", "error"],
        description:
          "`allow` and `log` mean the request **reached the model**; `block` and `challenge` mean the edge stopped it. `denied`, `guardrails`, `pending` and `error` are not edge verdicts and are excluded from the scored denominator.",
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
          dynamicRoute: nullable("string", "The Dynamic Route the run went through. **Known gap: recorded on save but not returned by GET today** — treat it as absent."),
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
          pending: int(),
          error: int(),
          reachedPct: int("reached / scored, 0 when nothing was scored — which means *nothing was measured*, not a perfect block rate."),
        },
        ["id", "ts", "label", "route", "gatewayId", "guarded", "model", "corpusName", "corpusSize", "corpusFingerprint", "delayMs", "total", "scored", "reached", "stopped", "denied", "guardrails", "pending", "error", "reachedPct"],
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
        },
        ["attackKey", "attackId", "category", "severity", "state", "ray", "ts", "promptPreview"],
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
