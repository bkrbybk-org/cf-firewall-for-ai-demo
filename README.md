# Cloudflare AI Security for Apps — Customer Demo

Chat app that demos **AI Security for Apps** (formerly *Firewall for AI*): real LLM traffic flows through a Cloudflare zone, the edge inspects each prompt, and WAF custom rules block PII, prompt injection, and unsafe topics **before they reach the model**.

```
Browser chat UI ──POST /api/chat {"prompt","model"} ──▶ Cloudflare edge
   ▲  (🧠 model picker)                                  │ 1. AI Security scans body (cf-llm endpoint)
   │                                                     │ 2. WAF rules block → 403 custom JSON
   └── reply (via <model>) / red "blocked" card ◀─ Worker ◀─┘ 3. Allowed → Worker → Workers AI (selected model)
```

- **Worker**: serves the static chat UI + `POST /api/chat` + `GET /api/models` (Workers AI binding, no API keys).
- **Account**: NFR - TH - NTT (`daf82c7c231958777ed36e9c0b6d347a`) — set in `wrangler.jsonc`.
- **URL**: the proxied custom domain in `wrangler.jsonc` `routes` (currently `cf-ai-waf-demo.nttlab.org`). `workers.dev` is disabled (`workers_dev: false`) because the AI detections only fire on a proxied zone hostname.

## Project layout

**Frontend = React + Vite + Tailwind (v4) + lucide icons**, built to `dist/` and served by the Worker as static assets (SPA). **Backend = the Worker** (`src/`, esbuild-bundled by wrangler), unchanged API.

```
src/                       Worker (TypeScript) — API + serves dist/
  index.ts                 fetch entry + route dispatch
  types.ts                 Env + shared interfaces
  models.ts                MODEL_REGISTRY (id+label+pricing), single source of truth
  config.ts                pricing/limit constants, upload limits, demo defaults
  cloudflare.ts            gqlFetch() + queryVerdict() + queryNeuronUsage()
  handlers.ts              one handler per endpoint + extractReply() + handleExtract() (toMarkdown);
                           handleChat unifies direct + AI Gateway routing
web/                       React app (Vite root)
  index.html               SPA entry + pre-paint theme script
  src/
    main.tsx               React root + router ( /, /analytics, /compliance; /gateway → / )
    index.css              Tailwind + CSS-var design tokens (light/dark)
    lib/
      data.ts              *** EDIT THIS for demo content: CATEGORIES,
                           PRESET_SYSTEM_PROMPTS, DEMO_SCRIPT, UNSAFE_TOPICS ***
      compliance.ts        *** EDIT THIS for the compliance page: MATRIX,
                           FRAMEWORKS (NIST/ISO/OWASP/ATLAS mappings) ***
      api.ts               typed fetch wrappers (incl. SSE stream parsing)
      types.ts             API response types
      format.ts            fmtTime/fmtCost/topicLabel
      icons.ts             category iconKey → lucide icon
      verdict.ts           shared verdict classify/poll (Verdict chip + autopilot)
      sampleFiles.ts        on-the-fly PDF/image sample builders (no binary assets)
    hooks/                 useTheme, useNeurons, useChat (session + send pipeline)
    components/            Header, ThemeToggle, NeuronChip, SystemPromptPanel,
                           AttackLibrary (searchable), Chat, Verdict, DemoMode,
                           FileAttach (visual prompt injection upload)
    pages/                 FirewallPage (chat + route selector), AnalyticsPage, CompliancePage
dist/                      Vite build output (gitignored) → wrangler assets
```

### Scripts / dev

```sh
npm install
npm run build      # tsc -b web + vite build → dist/
npm run deploy     # build, then wrangler deploy
npm run check      # worker typecheck

# Local dev (two terminals): Vite HMR proxies /api → wrangler dev
npm run dev:worker # wrangler dev  (port 8787, serves API + built dist)
npm run dev:web    # vite          (HMR; proxies /api/* to :8787)
```

Requires **Node ≥ 22** (`nvm use 24`) for wrangler.

To change what the demo shows (attack prompts, personas), edit **`web/src/lib/data.ts`** — nothing else — then `npm run build` (or run `npm run dev:web` for live reload).

## AI Gateway routing (Route selector on the Firewall page)

AI Gateway is **merged into the Firewall page** — there is no separate `/gateway` page (old links redirect to `/`). Above the composer, a **Workers AI ↔ AI Gateway toggle** picks the route; when AI Gateway is selected, a **Gateway dropdown** picks *which* configured gateway to use. One endpoint, `POST /api/chat`, powers both routes:

- **Workers AI** — `env.AI.run(model, inputs)`. Streaming + multi-turn, per-reply verdict.
- **AI Gateway** — `env.AI.run(model, inputs, { gateway: { id, skipCache, cacheTtl } })`. Adds a cache HIT/MISS badge, latency, gateway **log id** — *and still shows the verdict.*

**Which gateway** — `GET /api/models` returns a `gateways: [{ id, label, guarded }]` list. When `CF_ANALYTICS_TOKEN` (with the **AI Gateway Read** permission) and `CF_ACCOUNT_ID` are set, this is fetched **live from the account** via `GET /accounts/{id}/ai-gateway/gateways` (`listAiGateways()` in `src/cloudflare.ts`) — every gateway in the account appears in the dropdown, with the two demo gateways floated to the top. If the token lacks the permission or the call fails, it falls back to the two wrangler-var gateways (`resolveGateways()` handles both). The chosen `gatewayId` is sent to the Worker, sanity-checked to the gateway-id charset (invalid → default gateway), and the `guarded` flag — which drives the purple **GUARDRAILS** badge and Guardrails-block handling — is set for the gateway named in `CF_AI_GATEWAY_GUARDED_ID` (the list API does not report per-gateway Guardrails state, so this can't be auto-detected).

**Why the verdict works on both routes** — this is the whole point of merging at the endpoint. The edge WAF scans the inbound request to the `cf-llm`-labeled `/api/chat` path *before* the Worker runs, so it's identical regardless of whether the Worker then routes the inference through AI Gateway. The old standalone gateway page (a different `/api/gateway/chat` path) had **no** verdict; now every gateway-routed prompt gets the `cf.llm.*` edge verdict too.

- Cache status is authoritative from `env.AI.gateway(id).getLog(env.AI.aiGatewayLogId).cached` (best-effort — `null`/"cache: ?" if the log lags). Non-streaming gives the cleanest HIT/MISS badge; for streaming the Worker appends a trailing `data: {"gateway": …}` SSE event (log id + latency; cache status may be `null` mid-stream).
- **Caching + full features tradeoff**: a cache HIT needs an *identical request body*, so streaming and prior conversation turns weaken it. For a clean HIT: clear the conversation and send the same prompt twice. A note in the UI says so when the gateway route is active.
- Gateway name = `CF_AI_GATEWAY_ID` var (`"default"` auto-creates on first request). System prompts flow through unchanged; a different system prompt gets its own cache entry (the cache key is the full request body).

### Guardrails (gateway-layer moderation)

Picking the **Guardrails** gateway from the dropdown routes through a gateway with **AI Gateway Guardrails** enabled — Llama-Guard moderation of prompts and responses at the gateway layer. On a block the binding throws error **2016** (prompt) / **2017** (response); the Worker maps it to `{ guardrailsBlocked, direction }` and the UI shows a purple **“Blocked by AI Gateway Guardrails”** card — and the edge WAF verdict still appears below it, so you can see both control layers act on one prompt. WAF `cf.llm.*` rules act at the zone edge *before* the Worker; Guardrails act at the gateway *inside* the model call.

**One-time setup**: dashboard → AI → AI Gateway → create the guarded gateway → Guardrails → enable for prompts + responses and pick categories to block. The default gateway keeps Guardrails **off** so the caching demo stays unmoderated. Until the guarded gateway exists, the toggle returns error 2001 (“configure AI Gateway”).

## Model selection

The chat UI has a model picker (🧠 Model). The list is served by `GET /api/models` from a server-side allowlist in [`src/index.ts`](src/index.ts) (`ALLOWED_MODELS`), so the front end is never the source of truth. `POST /api/chat` accepts an optional `"model"` field; anything not on the allowlist falls back to the default. Each reply is tagged with the model that produced it.

Default: `@cf/meta/llama-3.3-70b-instruct-fp8-fast`. Also offered: Llama 4 Scout 17B, Llama 3.1 8B, Mistral Small 3.1 24B, GPT-OSS 120B, Qwen3 30B, Gemma 4 26B, DeepSeek R1 Distill 32B. Edit `ALLOWED_MODELS` to change the menu — see the full account list with:

```sh
npx wrangler ai models   # or: dashboard → AI → Workers AI → Models (task: Text Generation)
```

Model choice does not affect the edge detections — `cf.llm.*` scanning happens on the request body before the Worker calls any model.

## Compliance mapping page (`/compliance`)

Customer-facing page showing how these two products support six AI risk frameworks: **NIST AI RMF**, **ISO/IEC 42001**, **OWASP LLM Top 10 (2025)**, **MITRE ATLAS**, and two Thai frameworks — the **Bank of Thailand AI risk management policy (2025)** and the **NCSA AI Security Guidelines (2025)**. Layout is a coverage matrix (capability × framework) on top, then framework tabs with one detail card per control.

Coverage is **graded, not inflated** — every control carries one of four honest levels:

| Level | Meaning |
|---|---|
| Full | Cloudflare detects and enforces it at the edge, and records it |
| Partial | Detected and enforceable, but the policy decision stays with the customer |
| Supporting | Supplies evidence/telemetry only; the control itself is organizational |
| Out of scope | Not addressed by these products (kept on the page deliberately) |

Design decisions worth preserving if you edit it:

- **All ten OWASP items are listed, including the four Cloudflare does not address** (LLM04 poisoning, LLM06 excessive agency, LLM08 vector/embedding, and the partial ones). Customers know the list is ten — omitting four reads as evasive, and naming the gaps is more credible than a page of green ticks.
- **ISO/IEC 42001 is a paid standard**, so the page cites **top-level Annex A groups only** (`A.2`–`A.10`) and describes them in Cloudflare's own words. It never reproduces ISO control text. NIST AI RMF, OWASP and MITRE ATLAS are public and are cited by their real identifiers.
- The **Bank of Thailand** and **NCSA** documents are Thai-language; the page paraphrases their structure (BOT: Part 1/2 §n; NCSA: lifecycle phases 0–6 + §n) and reproduces no Thai text. The BOT tab carries a "confirm against the official document for a regulated engagement" note. BOT's Part 2 §3.1 maps especially cleanly — it splits the cyber control into *prompt filtering* + *response filtering*, exactly Firewall for AI + Gateway Guardrails.
- A banner states plainly that Cloudflare supplies *technical controls* and that full compliance is an organizational program, not a product.
- Each control card cross-links to the live demo that exercises it, so a claim can be proven in the same session.

All content lives in **`web/src/lib/compliance.ts`** (`MATRIX` + `FRAMEWORKS`) — edit that one file, then rebuild. No mappings are hardcoded in the page component.

## Visual prompt injection — file upload (Firewall page)

Tests hidden instructions carried inside an image or PDF rather than typed directly. This is deliberately a **two-stage** flow, because Firewall for AI only scans the `prompt` text field of `/api/chat` — it never sees file bytes:

1. **Extract** — `POST /api/extract` (multipart, ≤1 MB, PDF/PNG/JPEG/WebP/GIF/BMP/SVG) converts the file to text via `env.AI.toMarkdown()`. This endpoint is **not** the `cf-llm`-labeled endpoint and is never scanned — the extraction card in the UI says so explicitly.
2. **Load into prompt → Send** — the user reviews the extracted text and, if they choose, loads it into the chat input and sends it through the normal, scanned `/api/chat` path. Only at that point does Firewall for AI score it.

The two file types behave very differently, and the UI is honest about the gap instead of implying uniform coverage:

- **PDF** — `toMarkdown()` extracts the document's text layer directly, regardless of how it's painted. Text hidden via `1 1 1 rg` (white-on-white) or an invisible render mode comes back byte-for-byte. Verified against the real API: a hand-built sample PDF with one visible line and one white-on-white line returns **both** in the extracted text.
- **Image** — `toMarkdown()`'s image path is object-detection + **captioning** (via a vision model), not OCR. A genuinely invisible overlay (0% opacity, exact background color) won't surface at all. Verified against the real API: a sample image with a faint, low-contrast instruction in one corner produced a caption that *noticed* “a line of extremely faint, low-contrast text… along the very bottom edge” but did **not** transcribe its content — the model saw that something was hidden, not what it said.

Both sample files (`web/src/lib/sampleFiles.ts`) are generated on the fly in the browser — a hand-written minimal PDF (raw PDF syntax, no library) and a canvas-drawn PNG — so no binary assets live in the repo and the technique stays inspectable as plain code. Extraction cards render inline in the chat transcript (`kind: "extraction"` in `hooks/useChat.ts`) but are not chat turns: no prompt was sent, nothing was scanned, and they're excluded from session export's turn pairing.

## Session export (Firewall page)

The **Export** button (next to Clear conversation, once the chat has at least one turn) downloads the current session as:

- **JSON** — full structured data: every turn's prompt, reply, model, tokens, cost, and edge verdict (matched rules, injection score, PII/unsafe/custom-topic categories). Meant for re-analysis or archiving.
- **Markdown** — the same data as a readable report, meant for pasting into a doc or handing to a customer.

Verdicts are **re-fetched fresh at export time** (`buildSessionExport()` in `web/src/lib/export.ts`) via a single `GET /api/verdict` lookup per turn — not the multi-minute poll the live UI uses. If analytics haven't ingested yet, that turn's verdict is marked unavailable rather than blocking the export.

## Multi-turn conversations & streaming (Firewall page)

- **Multi-turn**: the chat sends prior turns as `history: [{role, content}…]` alongside the top-level `prompt` (kept as-is so AI Security's body scanning is unchanged). The Worker re-validates roles and caps history at 10 turns / 8,000 chars (`sanitizeHistory`). Only completed user→assistant *pairs* are sent — a blocked prompt is deliberately **not** resent in history, or every later turn would be blocked too. The UI shows “N turns of context” and a **Clear conversation** button. The Attack Library has a **Multi-turn Jailbreak (Crescendo)** category with prompts designed to be sent in sequence — a good talking point: each request is scanned individually, while context accumulates model-side.
- **Streaming**: the **stream replies** toggle (default on) makes `POST /api/chat` pass through the model's SSE stream (`stream: true` → `text/event-stream`); the UI renders tokens live with a cursor. Blocked requests are unaffected — the WAF acts before the Worker, so the response is a 403 HTML/JSON body, detected by content-type and routed to the normal blocked card. Token usage comes from the stream's final `usage` event when the model emits one, otherwise it's estimated (`~`); cost is computed client-side from the per-model prices included in `GET /api/models`.
- The gateway page intentionally stays single-turn & non-streaming — history would make every request unique and defeat the cache demo.

## Demo autopilot (▶ Run demo)

One click in the Firewall page header runs a scripted attack tour (`DEMO_SCRIPT` in `web/src/lib/data.ts`): baseline → injection → PII → unsafe topic (block) → unsafe topic (log-only) → custom topic. Each step is sent through the real chat pipeline; the autopilot clears the conversation first, waits for the **edge verdict** per step (blocked 403s count immediately), compares the outcome against the step's `expect` (block / log / allow), and ends with a scorecard (“N/N verified steps behaved exactly as configured”). Stop button aborts between steps. On localhost there are no edge verdicts, so steps show “verdict pending” — run it on the production hostname for live scoring.

## Analytics page (`/analytics`)

Zone security dashboard fed by `GET /api/analytics?hours=1|24|168`: the Worker pulls the latest raw rows from `firewallEventsAdaptive` (rule, action) and `httpRequestsAdaptive` filtered to `/api/chat` (AI scores, PII), aggregates server-side (`queryAnalytics` in `src/cloudflare.ts`), and returns one payload: action totals, top fired rules, an hourly/daily stacked series (block/log/other), an injection-score histogram, and a PII-request count. Hand-rolled SVG/flex bars (no chart library), light+dark, auto-refresh every 60s with a fetch timestamp, range picker 1h/24h/7d. Needs the same `CF_ANALYTICS_TOKEN` secret as the verdict feature; localhost shows real zone data too (the query is zone-wide, not per-request).

### System prompt (left panel)

The left sidebar shows the **active system prompt** (name + preview), a dropdown of predefined personas, and a collapsible editor for a fully custom one:

| Preset | Purpose |
|---|---|
| Default — Cloudflare demo assistant | server's real default (from `GET /api/models`'s `defaultSystemPrompt`) |
| Customer support agent | empathetic, on-topic SaaS support persona |
| Cloudflare product expert | precise, product-name-citing answers |
| Strict / locked-down assistant | refuses everything except one topic — good for showing injection attempts failing against a tightly scoped prompt |
| Pirate persona (fun demo) | lighthearted persona swap, obviously changes tone |
| Custom… | opens the textarea; auto-selected the moment you edit away from any preset's exact text |

Picking a preset immediately updates the textarea and the active-prompt preview; editing the textarea directly updates the preview live and flips the dropdown to "Custom…" once the text no longer matches a preset verbatim. "Reset to default" restores preset #1. `PRESET_SYSTEM_PROMPTS` in `public/index.html` is the place to add/edit personas — only the first entry's text comes from the server (`defaultSystemPrompt`), the rest are client-side.

`POST /api/chat` accepts an optional `"systemPrompt"`; empty/whitespace-only falls back to the default, anything longer than `maxSystemPromptLen` (2000 chars) is truncated server-side.

Useful for demoing prompt-injection resilience against a *stricter* system prompt, or for showing the detections are unaffected by system-prompt changes (they run on the raw request body, before any of this).

### Per-reply metadata

Each assistant reply is tagged with `via <model> · ray <cf-ray> · <n> tok (in / out) · ~$<cost>`. `POST /api/chat` returns:

```jsonc
{
  "reply": "…", "model": "@cf/…",
  "ray": "a1adfe7e4d618961-BKK",              // Cloudflare ray id — search it in Security → Events
  "usage": { "prompt_tokens": 68, "completion_tokens": 24, "total_tokens": 92, "estimated": false },
  "cost": 0.000074                             // USD estimate = tokens × per-model unit price
}
```

- **ray id** ties a chat turn to its edge event, so you can look the exact request up in Security → Events / Analytics during the demo.
- **tokens** come from the model's own `usage`; if a model omits it, the Worker estimates (~4 chars/token) and the count is prefixed `~`.
- **cost** is estimated from Workers AI [unit pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/) (`PRICING` map in `src/index.ts`), so it is marked `~`. Billing is in Neurons at $0.011 / 1,000.
- Note: gpt-oss models return OpenAI chat-completion shape (`choices[0].message.content`); the Worker's `extractReply()` handles that, the standard `{ response }`, and reasoning models (Gemma 4, DeepSeek R1) that put text in `message.reasoning` with `content: null`. `<think>…</think>` chain-of-thought is stripped so only the final answer shows; `max_tokens` is 2048 (`MAX_REPLY_TOKENS`) so reasoning models don't truncate mid-think.

## Live edge verdict (per-prompt log)

Each turn also shows a `🔎 edge verdict` line: **which WAF rule matched, its action (block / log / challenge / allow), and the Firewall-for-AI scores** for that exact request. The browser polls `GET /api/verdict?ray=<cf-ray>`, which the Worker answers by querying the GraphQL Analytics API (`firewallEventsAdaptive` for the rule + action, `httpRequestsAdaptive` for `firewallForAiInjectionScore` / `firewallForAiPiiCategories` / `firewallForAiUnsafeTopicCategories`).

This is the piece that makes **log-only** rules visible: a logged request still returns 200 to the user, but the verdict line reveals the rule fired and what it detected — the "detect first, then enforce" story. Blocks already show instantly via the 403 card; the verdict enriches them with the rule name and score.

### Enable it (one secret)

`CF_ZONE_ID` is already set in `wrangler.jsonc`. Add a scoped API token as a secret:

1. Create a token at <https://dash.cloudflare.com/profile/api-tokens> → **Zone · Analytics · Read** on `nttlab.org` (Account Analytics Read also works).
2. ```sh
   npx wrangler secret put CF_ANALYTICS_TOKEN   # paste the token
   npx wrangler deploy
   ```

Without the token, `/api/verdict` returns `{ "configured": false }` and the UI shows a "live edge log disabled" hint — everything else keeps working.

### Notes

- **ray id is always shown** — on the blocked card immediately (no polling needed), and again as the first field of the verdict line.
- **PII and unsafe-topic categories always show**, even when empty (`PII: none`), once the request is scored — no more silent omission.
- **Ingestion order quirk**: for blocked/logged requests, the matched-rule row (`firewallEventsAdaptive`) can land ~5s *before* the row carrying the AI scores (`httpRequestsAdaptive`). The poller specifically waits for the AI-score row before rendering, so scores don't get silently dropped; if it never arrives within ~100s it falls back to showing the rule with an explicit "AI scores: pending" note instead of hiding them.
- **Near-real-time, not instant.** GraphQL analytics ingest ~15–90s behind; the UI polls every 5s for up to ~100s, then says "no edge event yet".
- Until the zone is onboarded, the verdict reads **`action: allowed — no matching rule · AI scan: not scored (endpoint not labeled cf-llm — AI Security not scanning)`**. This is expected: `securityAction` comes back as the raw enum `unknown` (no security layer acted), `firewallForAiInjectionScore` is `100` (= not scored), and `webAssetsLabelsManaged` is empty (endpoint not registered/labeled). The Worker maps these to the readable line via `scored`/`cfLlmLabeled` flags in `queryVerdict()`; the UI's `renderVerdict()` translates the raw `unknown` action into "allowed — no matching rule".
- Once onboarded, `securityAction` becomes `block`/`log`/`managed_challenge`, `firewallEventsAdaptive` returns the matched rule, and `injection_score` becomes a real 1–99.
- `/api/verdict` only accepts a ray id and only returns rows for this zone's recent traffic; the analytics token stays server-side (never sent to the browser).

### Reading the verdict line

Every field that's an identifier/score/category is rendered in **monospace** so it's easy to eyeball and copy: ray id, rule name, `injection_score`, PII category names, unsafe-topic codes, and custom-topic labels. Unsafe-topic codes show their meaning inline, e.g. `S7 (Privacy)`, from the full S1–S14 taxonomy baked into the UI (`UNSAFE_TOPICS` in `public/index.html`) — see the [reference table](#unsafe-topic-taxonomy-s1s14) below. Custom topics (if configured on your ruleset) show as `label (score N)` — lower score = more relevant.

`firewallEventsAdaptive` (the matched rule) and `httpRequestsAdaptive` (the AI scores) ingest **independently and in no fixed order** — either can lag the other by anywhere from a few seconds up to the ~130s poll budget. The UI waits for both when a rule is expected; if the poll budget runs out before the rule row appears, it says `rule: not yet visible (still ingesting)` rather than silently omitting it — check Security → Events directly if that happens.

Each prompt/response also gets a small **timestamp** (`HH:MM:SS`, local time) under its bubble/card.

### Unsafe-topic taxonomy (S1–S14)

| Code | Category | Code | Category |
|---|---|---|---|
| S1 | Violent crimes | S8 | Intellectual property |
| S2 | Non-violent crimes | S9 | Indiscriminate weapons |
| S3 | Sex-related crimes | S10 | Hate |
| S4 | Child sexual exploitation | S11 | Suicide and self-harm |
| S5 | Defamation | S12 | Sexual content |
| S6 | Specialized advice | S13 | Elections |
| S7 | Privacy | S14 | Code interpreter abuse |

Source: [AI Security for Apps — unsafe topics](https://developers.cloudflare.com/waf/detections/ai-security-for-apps/unsafe-topics/).

### Raw block response viewer

Every blocked-request card has a **▸ View raw response** toggle showing exactly what the browser received — pretty-printed JSON if the WAF rule returns a custom JSON body, or the raw HTML otherwise.

⚠️ **Current live state**: the deployed rules return Cloudflare's **default HTML "Attention Required" block page**, not a custom JSON body. The chat UI's "reason" text on the blocked card is therefore a generic fallback, not something read from the response — the real detail (rule, action, scores, categories) comes from the **edge verdict line below it**, which is accurate regardless of the block page format. To get a structured JSON block body instead, edit each WAF rule's response: set "With response type" → **Custom JSON** (see the rule table above) and the raw-response viewer will pretty-print it instead of showing HTML.

## Workers AI Neuron monitor

The header shows a live **⚡ Neurons** chip: total Neurons consumed by the account today (resets 00:00 UTC) against the free daily allocation, from `GET /api/neurons` (queries the account-level `aiInferenceAdaptiveGroups` GraphQL dataset). Refreshes on load, after every chat turn, and every 60s.

- **Free allocation**: 10,000 Neurons/day (from [Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/), 2026-07). Beyond that: **$0.011 / 1,000 Neurons** on Workers Paid, or requests fail on Workers Free.
- Chip turns **amber** at ≥80% of the daily allocation, **red** at ≥100%.
- Needs `CF_ACCOUNT_ID` (already set in `wrangler.jsonc`) **and** the `CF_ANALYTICS_TOKEN` secret to also carry **"Account Analytics: Read"** (separate from the "Zone Analytics: Read" scope `/api/verdict` needs — add both scopes to the same token). Without it, `/api/neurons` returns `{"configured":true,"error":"not authorized for that account"}` and the chip shows "Neuron monitor error"; without `CF_ACCOUNT_ID` it shows "not configured".

> **`CF_ANALYTICS_TOKEN` scopes recap** — this one token now backs three features: **Zone Analytics: Read** (`/api/verdict`, `/api/analytics`), **Account Analytics: Read** (`/api/neurons`), and **AI Gateway Read** (the account-wide gateway dropdown via `/api/models`). Any scope it's missing degrades only its own feature — the gateway list falls back to the two wrangler-var gateways, so the page still works.

## Deploy

```sh
npm install
npx wrangler deploy   # requires Node >= 22 (nvm use 24)
```

`wrangler.jsonc` already pins the custom domain, so deploy creates/updates the proxied DNS record and cert for `ai-demo.nttlab.org` automatically:

```jsonc
"workers_dev": false,
"routes": [{ "pattern": "ai-demo.nttlab.org", "custom_domain": true }]
```

> ⚠️ AI Security for Apps is a *zone* feature — detections only fire on this proxied `nttlab.org` hostname on an **Enterprise zone with the AI Security add-on**, never on `workers.dev`.

## One-time zone setup (dashboard)

On the Enterprise zone that hosts the demo hostname:

1. **Enable the feature** — Security → Settings → turn on **AI Security for Apps**.
2. **Label the endpoint** — Security → Web Assets (Endpoint Management):
   - Ensure `POST ai-demo.nttlab.org/api/chat` exists (add manually or wait for API discovery after sending a few requests).
   - Apply the managed label **`cf-llm`** to it. Detection only runs on labeled endpoints with `application/json` bodies.
3. **Create 3 custom rules** — Security → WAF → Custom rules. For each: action **Block**, "With response type" = **Custom JSON**, status 403, body as below.

   | Rule | Expression | Custom JSON response body |
   |---|---|---|
   | AI demo — block PII | `(http.request.uri.path eq "/api/chat" and cf.llm.prompt.pii_detected)` | `{"blocked": true, "detection": "pii", "reason": "Personally identifiable information found in the prompt"}` |
   | AI demo — block injection | `(http.request.uri.path eq "/api/chat" and cf.llm.prompt.detected and cf.llm.prompt.injection_score lt 20)` | `{"blocked": true, "detection": "injection", "reason": "Prompt injection likelihood score below threshold"}` |
   | AI demo — block unsafe topics | `(http.request.uri.path eq "/api/chat" and cf.llm.prompt.unsafe_topic_detected)` | `{"blocked": true, "detection": "unsafe_topic", "reason": "Prompt matches an unsafe topic category"}` |

   Notes:
   - `injection_score` is 1–99 and **low = likely attack**; `100` = not scored. Tune the `lt 20` threshold live during the demo if you like.
   - Custom JSON responses are static — the chat UI shows the reason from this JSON; detected *categories* (e.g. `CREDIT_CARD`, `S2`) are visible in Security → Events.
   - The UI understands `{"blocked": true, "detection": "pii|injection|unsafe_topic", "reason": "..."}` and renders a red 🛡️ card.

## Attack Library (right panel) — framework mapping

The UI groups the demo prompts by threat category, each tagged with its **OWASP LLM Top 10 (2025)** and **MITRE ATLAS** references and the Cloudflare field that catches it:

| Category | OWASP LLM Top 10 (2025) | MITRE ATLAS | Cloudflare field |
|---|---|---|---|
| Baseline — safe traffic | — | — | (none flagged) |
| Prompt Injection / Jailbreak | LLM01:2025 Prompt Injection | AML.T0051 LLM Prompt Injection | `cf.llm.prompt.injection_score` |
| System Prompt Leakage | LLM07:2025 System Prompt Leakage | AML.T0056 LLM Meta Prompt Extraction | `cf.llm.prompt.injection_score` |
| Sensitive Info Disclosure (PII) | LLM02:2025 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | `cf.llm.prompt.pii_detected` → `pii_categories` |
| Unsafe / Harmful Topics | LLM01:2025 (Jailbreak variant) | AML.T0054 LLM Jailbreak | `cf.llm.prompt.unsafe_topic_categories` (S1–S13) |

References: [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) · [MITRE ATLAS AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) · [ATLAS matrix](https://atlas.mitre.org/matrices/ATLAS)

## Demo script

| Step | Category (right panel) | Expected |
|---|---|---|
| 1 | ✅ Baseline → "Legit product question" | LLM answers. Security Analytics shows request with `cf-llm` label, prompt detected, no flags. |
| 2 | 🪪 PII → "Credit card + email" | 403 → red card "PII detected". Security Events shows `pii_categories: CREDIT_CARD, EMAIL_ADDRESS`. |
| 3 | 💉 Prompt Injection → "Ignore instructions" | 403 → red card "Prompt injection". Events shows low `injection_score`. |
| 4 | 🕵️ System Prompt Leakage → "Dump the system prompt" | 403 → red card. Ties to OWASP LLM07 / ATLAS AML.T0056. |
| 5 | ☠️ Unsafe Topics → "Non-violent crime (S2)" | 403 → red card "Unsafe topic". Events shows S-category (S2 = non-violent crimes). |
| 6 | Flip a rule's action Block → Log, resend | Prompt now reaches the LLM but is still flagged in Analytics → "detect first, then enforce" story. |

Full unsafe-topic taxonomy (S1–S13) and custom topics: <https://developers.cloudflare.com/waf/detections/ai-security-for-apps/unsafe-topics/>

## Verify after setup

```sh
# Clean → 200 + reply
curl -s https://ai-demo.nttlab.org/api/chat -H 'content-type: application/json' \
  -d '{"prompt":"hello"}'

# PII → 403 + block JSON
curl -s https://ai-demo.nttlab.org/api/chat -H 'content-type: application/json' \
  -d '{"prompt":"my credit card is 4111 1111 1111 1111"}'
```

## Requirements recap

- Enterprise plan + **AI Security for Apps add-on** on the zone (LLM endpoint *discovery* works on all plans; the `cf.llm.*` rule fields do not).
- Endpoint saved in Web Assets and labeled `cf-llm`.
- Requests must be `application/json` (the UI always sends this).
