# Progress — Cloudflare AI Security demo

_Last updated: 2026-07-31_

Customer-facing demo of **Cloudflare AI Security for Apps** (formerly *Firewall for AI*) plus
**AI Gateway** (routing, caching, Guardrails, Dynamic Routing), a **security analytics dashboard**,
and a **compliance mapping page**. Live at **https://cf-ai-waf-demo.nttlab.org** (account
**NFR - TH - NTT** `daf82c7c…`, zone `nttlab.org`).

Prod is behind **Cloudflare Access**. Functional testing this session was done on `wrangler dev`
(real Workers AI + real zone GraphQL + real AI Gateway REST API), seeding local D1 with `wrangler
d1 execute … --local` and faking a `cf-ray` header via curl where the edge-verdict / prompt-log
join needed one (local dev never sets a real one). Node ≥ 22 (`nvm use 24`).

---

## Architecture decisions

- **Single Cloudflare Worker** serves both the API and the built React SPA. No separate origin.
  - API routes: `/api/models`, `/api/chat` (unified — direct or AI Gateway routing), `/api/verdict`
    (anchored + retention-aware, see below), `/api/neurons`, `/api/analytics` (zone),
    `/api/gateway-analytics` (account, per gateway), `/api/prompt-log` (GET list / DELETE clear —
    D1), `/api/prompt-analytics` (D1 rollups). Everything else → static assets (SPA fallback).
- **Prompt log store = D1** (`DB` binding, db `cf-ai-waf-demo-log`, `migrations/0001_prompt_log.sql`).
  `handleChat` writes one PII-**redacted** row per prompt that reaches the Worker, via
  `ctx.waitUntil` so it never blocks the reply; redaction is an independent regex pass in
  `src/redact.ts`. **Opt-out per request**: a "log prompt" toggle sends `excludeFromLog: true`,
  which short-circuits the write before it happens — independent of AI Gateway's own request log.
  Optional — unbinding `DB` degrades the tab to a setup hint.
- **Detection happens at the edge, not in app code.** AI Security scans the request body *before*
  the Worker runs; WAF custom rules block/log. The app generates traffic + reads back what the edge
  did via GraphQL Analytics. Fires only on the proxied zone hostname + `cf-llm`-labeled `/api/chat`.
- **AI Gateway route is now always REST, not the binding.** Originally direct = `env.AI.run(...)`,
  gateway = `env.AI.run(..., { gateway })` — one binding call either way. That changed: the gateway
  route now calls the OpenAI-compatible REST endpoint
  (`POST /accounts/{id}/ai/v1/chat/completions` with `cf-aig-gateway-id`) unconditionally, the same
  path Dynamic Routing always needed. Reason: the binding's `gateway` option only ever exposed 3 of
  the 9 documented per-request `cf-aig-*` settings (id/skipCache/cacheTtl/cacheKey/metadata/
  collectLog) — REST is the only way to reach `cache-key`, `collect-log`, `request-timeout`,
  `max-attempts`, `retry-delay`, and `backoff`. **Consequence accepted knowingly**: every AI Gateway
  request now needs `CF_AIG_TOKEN` — previously only Dynamic Routing did. Direct Workers AI is
  unaffected (still the plain binding, no token). See Open bugs #1 — this token's permissions are
  currently unverified in prod, which would make the *entire* gateway route return 501/10000.
  Because the edge WAF scans the inbound request before the Worker picks a route, **the verdict
  still applies to both routes** either way.
- **Every AI Gateway per-request REST setting is exposed and validated client-side.**
  `GatewaySettingsPanel` (left column, gateway route only) covers all 9 `cf-aig-*` headers plus
  metadata. Numeric fields (`maxAttempts` ≤ 5, `retryDelayMs` ≤ 5000, `cacheTtl`/`requestTimeoutMs`
  > 0) show a live red error while out of range and silently clamp on blur; the Worker clamps the
  same values again server-side as a second guard, since a client can always be bypassed.
- **LLM backend = Workers AI** (native `AI` binding for the direct route). Model allowlist in
  `src/models.ts` (7 models incl. `llama-guard-3-8b`; default = **Gemma 4 26B**,
  `MODEL_REGISTRY[0]`). `MAX_REPLY_TOKENS = 2048`. Prices served to the client for cost estimates.
- **Multi-turn keeps the top-level `prompt` field** (latest user message) so AI Security's body
  scan is unchanged; prior turns ride in `history[]`, server-revalidated (10 turns / 8k chars), and
  only completed user→assistant pairs are sent (blocked prompts never re-enter history).
- **Streaming = SSE passthrough.** `stream:true` → Worker returns the model's `text/event-stream`;
  client parses `data:` lines, including reading the real model id off OpenAI-shape chunks (`j.model`)
  for the gateway/dynamic-route path, since the route — not the dropdown — picks the model there.
  For a streaming gateway call the Worker appends a trailing `data:{gateway:…}` event (cache status
  read straight off the `cf-aig-cache-status` response header now, not an async `getLog()` lookup —
  the REST response already carries it). Blocked requests come back as 403 HTML/JSON regardless —
  content-type decides the parse path.
- **Edge-verdict lookup is anchored to the request's own timestamp, not "now".** The original query
  window was hardcoded to `[now−15min, now+1min]` — fine for a prompt just sent, but it silently
  returned nothing for any older row, because the ray's own time and "the moment someone clicked
  the row" are different things. `queryVerdict()` now takes an optional `atMs`; when given, the
  window becomes `[atMs±5min]` instead. `/api/verdict?ray=&ts=` — prompt-log rows pass their stored
  `ts`, live chat sends nothing and keeps the old behaviour. A second, genuinely distinct problem:
  Cloudflare's analytics retention is real and finite (queried live via the GraphQL settings node's
  `notOlderThan`, cached per isolate, conservative 30-day fallback if that query fails) — a row past
  it is correctly reported `tooOld`, distinct from "not ingested yet" (which is worth retrying).
- **Historical verdict lookups are one-shot + cached, not polled.** The 60s-delay-then-5s-poll cycle
  in `pollVerdict()` exists because a just-sent prompt's analytics genuinely haven't ingested yet.
  A prompt-log row from an hour ago has no such excuse — `<Verdict ts={row.ts}>` branches on age
  (>2 min → `fetchVerdictOnce`, one request, no wait) and a module-level `Map<ray, result>` cache
  means expanding the same row twice, or many rows, never re-fetches a settled ray.
- **A block is only attributed to the WAF when the response says so.** A 403 with a structured JSON
  body (`data.blocked`) is a genuine WAF/AI-Security block and is labelled as such. A bare 403/HTML
  is not — it proves the edge refused the request, not who refused it (Cloudflare Access and rate
  limiting both look identical from here). `verdictOutcome()` now cross-checks the rules against the
  edge's own `httpStatus`: a non-2xx with only log-only (or no) matching rules resolves to a new
  `"denied"` outcome — pill **STOPPED**, not BLOCKED — so the UI never credits a control that took no
  action. This was not theoretical: it caught a live production incident (see Open bugs).
- **AI Gateways are listed live from the account.** `/api/models` calls the AI Gateway REST API
  (`GET /accounts/{id}/ai-gateway/gateways`, needs `CF_ANALYTICS_TOKEN` with **AI Gateway Read**)
  and returns every gateway. Falls back to the two wrangler-var gateways if the token lacks the
  permission. Wrangler vars: `CF_AI_GATEWAY_ID = cf-ai-sec-demo-gw-no-guardrail` (default),
  `CF_AI_GATEWAY_GUARDED_ID = cf-ai-sec-demo-gw` (marked as the guarded one). Guardrails blocks
  surface as REST HTTP errors matched by text (2016 prompt / 2017 response) → `{guardrailsBlocked,
  direction}`.
- **Analytics aggregates in the Worker**: latest 500 raw rows per dataset (`firewallEventsAdaptive`
  + `httpRequestsAdaptive` filtered to `/api/chat`), tallied server-side into one payload.
- **Prompt log time filtering and D1 rollups share one window model.** `parseTimeWindow()` in
  `handlers.ts` reads an explicit `since`/`until` (epoch ms — the custom date/time picker) when
  present, else a rolling `hours` (0/absent = all time — the 1h/24h/7d/all preset buttons). Both
  `/api/prompt-log` and `/api/prompt-analytics` use it, so the table and its rollup tiles/chart
  above always describe the same range.
- **Sorting and text-search on the prompt log are client-side; route/outcome/time filters are
  server-side.** The former only reorder or narrow the page already fetched (200-row cap), so a
  round trip would add latency for nothing; the latter change which rows are fetched at all.
- **One send pipeline** (`useChat` hook) drives both manual chat and the demo autopilot; shared
  verdict poller/cache in `web/src/lib/verdict.ts` powers the Verdict chip, the prompt log's
  one-shot lookups, and autopilot scoring. Chat session state lives in a **module-level store**
  (`lib/sessionStore.ts`) so it survives tab switches and is cleared by a full refresh.
- **Toggle switches use a shared `Switch` component**, not raw checkboxes — a Tailwind Plus-style
  pill-with-sliding-thumb pattern reimplemented from scratch (that block's source is paywalled),
  dependency-free (no Headless UI).
- Server-side allowlists for model + system prompt. Frontend: React 18 + Vite 6 + Tailwind v4 +
  lucide, light/dark via `data-theme`.

### Pages / layout

- **`/` — Firewall / chat** (nav-tab label is currently "AI Guardrails Demo"): System Prompt +
  (gateway route only) **AI Gateway settings** on the left · Chat center · Attack Library right.
  Chat toolbar: model picker, Workers AI ↔ AI Gateway toggle, stream/multi-turn/**log prompt**
  switches, and — on the gateway route — a Gateway dropdown and Dynamic Routing **Route** field.
  The chat pane is centered (`max-w-3xl`) with a ChatGPT-style right-edge **prompt navigator**
  (hover the tick rail → jump to any earlier prompt) anchored to the pane's true right edge, not the
  narrowed column's edge. **Responsive**: below the `lg` breakpoint the three panes can no longer
  all fit one viewport (sidebar + library are `shrink-0` with far more content than the screen), so
  the whole column scrolls instead of the chat pane collapsing to zero height — a real layout bug
  fixed this session (see Open bugs history / Implemented). `/gateway` redirects here.
- **`/analytics`**: three tabs (edge / AI Gateway / prompt log). Edge and gateway tabs share a
  1h/24h/7d range picker; **prompt log has its own independent range** (1h/24h/7d/**all**/**custom**
  date-time picker), defaulting to **1h**, since it's reviewed differently (recent activity vs. "the
  whole demo session"). Prompt log is a **sortable table** (click any column header; defaults to
  Time, newest first) with a client-side text filter (prompt/reply/model/ray) and a **multi-select**
  outcome filter (toggle any combination of replied/guardrails-blocked/error, not just one at a
  time). 60s auto-refresh on all three tabs.
- **`/compliance`**: coverage matrix (capability × framework) + framework tabs with per-control
  detail cards. **Six frameworks**: NIST AI RMF · ISO 42001 · OWASP LLM Top 10 · MITRE ATLAS ·
  Bank of Thailand AI risk policy (2025) · NCSA AI Security Guidelines (2025).

---

## Repository layout

```
src/                Worker (TypeScript)
  index.ts          route dispatch
  types.ts          Env + request/response interfaces
  models.ts         MODEL_REGISTRY (id+label+pricing) — single source of truth
  config.ts         reply/history limits, pricing, gateway + dynamic-route constants, verdict
                    window/retention helpers (verdictWindow, isBeyondRetention)
  cloudflare.ts     gqlFetch, queryVerdict (anchored), queryVerdictRetention (cached
                    notOlderThan), queryNeuronUsage, queryAnalytics, listAiGateways
  handlers.ts       one handler per endpoint; handleChat unifies direct (binding) + AI Gateway
                    (REST, incl. Dynamic Routing) routing; runGatewayRest, appendRestGatewayEvent,
                    parseTimeWindow (shared by prompt-log + prompt-analytics), extractReply/
                    stripThink, sanitizeHistory, logPrompt, gateway registry helpers
  redact.ts         PII redaction for the prompt log (regex pass, not FW-for-AI driven)
web/src/
  lib/              data.ts (demo content), compliance.ts (MATRIX + FRAMEWORKS), api.ts (fetch
                    wrappers incl. TimeWindow + SSE parser), types.ts, format.ts, icons.ts,
                    verdict.ts (classify + poller + fetchVerdictOnce + ray cache), export.ts
                    (session export — ⚠️ still uses the old unanchored window, see Open bugs),
                    metadata.ts (AI Gateway metadata parser), sessionStore.ts
  hooks/            useTheme, useNeurons, useChat (session + send pipeline, RequestConfig snapshot
                    per turn for the verdict trace's request-chips row)
  components/       Header, NavTabs, ThemeToggle, NeuronChip, SystemPromptPanel,
                    GatewaySettingsPanel (all 9 cf-aig-* settings + validation; replaces the old
                    RequestMetadataPanel), Switch, AttackLibrary, Chat, Verdict, FlowTrace,
                    DemoMode, ExportButton
    analytics/      primitives (Tile/Card/BarList), EventSeries (line+area chart + series defs),
                    EdgeTab, GatewayTab, PromptLogTab (sortable table + filters)
  pages/            FirewallPage (chat + route/gateway controls), AnalyticsPage (shell: state,
                    loaders, tab strip, filters incl. prompt-log time window + outcome multiselect),
                    CompliancePage
```

Scripts: `npm run build` · `npm run deploy` · `npm run check` (worker typecheck) · `npm test`
(vitest, `vitest.config.ts` — separate from `vite.config.ts`, which sets `root: "web"`) · `npm run
dev:worker` / `npm run dev:web`. `.claude/launch.json` has `wrangler-dev` + `vite-dev` configs.

**Version control**: branch `main`, **6 commits** (`ed669b6` … `a4f78d2`), all from before this
session. ⚠️ **Everything in this doc past that point — the AI Gateway REST migration, the verdict
window/retention fix, the WAF-attribution fix, the prompt log rewrite, the layout fixes — is
uncommitted.** `git status` shows modifications across ~20 files plus several new ones
(`GatewaySettingsPanel.tsx`, `Switch.tsx`, `verdict-window.test.ts`, `verdict.test.ts`) and one net
removal (`RequestMetadataPanel.tsx`, superseded). This is a large, working diff — commit it in
reviewable chunks rather than one giant commit; see Next tasks.

**Tests** — `npm test`, **49 across 5 files** (was 32/3 before this session). Each exists because a
real bug shipped, and each was mutation-verified (reintroduce the bug → red):
- `src/redact.test.ts` (18) — PII redaction against the real Attack Library prompts. Asserts the
  identifier is **absent** rather than matching an exact replacement (the shipped bug was a
  *partial* mask leaking part of an IBAN). No-false-positives + idempotency.
- `src/config.test.ts` (8) — `normalizeDynamicRoute`. Accepts both `demo-routes` and the dashboard's
  `dynamic/demo-routes`; returns `null` (never a silently wrong value) for traversal or junk.
- `web/src/lib/metadata.test.ts` (6) — the 5-entry cap and malformed-pair handling.
- `src/verdict-window.test.ts` (9) — **new this session**. `verdictWindow()`: anchored vs. live
  bracketing, the regression itself (the live window provably excludes an hours-old timestamp the
  anchored one covers), non-finite-timestamp fallback. `isBeyondRetention()`: inside/past/exact
  boundary, and — important — an *unknown* timestamp never reads as expired (there's nothing to
  compare, so the lookup must still be attempted).
- `web/src/lib/verdict.test.ts` (8) — **new this session**, built from a real incident's exact
  payload (ray `a23939307b53893b`). Asserts a 403 with only log-only matched rules classifies as
  `denied`, not `log`; a genuine `block`/`challenge` still classifies correctly; a 403 with zero
  matched rules also denies; covers 5xx as well as 403; falls back to the rules when the status is
  still unknown (nothing to contradict yet, so don't invent a denial).

---

## Implemented

Verified against real Cloudflare via `wrangler dev` + local D1 seeding unless noted.

**This session's headline change: AI Gateway per-request REST settings, exposed and correct.**
- The gateway route moved off the `env.AI.run(..., {gateway})` binding onto the same REST call
  Dynamic Routing already used, specifically to reach the 6 `cf-aig-*` settings the binding never
  exposed. `GatewaySettingsPanel` (left column, renders only on the gateway route — nothing to
  configure on direct) covers all 9: skip-cache, cache-ttl, cache-key, collect-log, request-timeout,
  max-attempts (≤5), retry-delay (≤5000ms), backoff (constant/linear/exponential), metadata.
- **Validated both sides.** Numeric fields show a live red error while typing out of range and
  silently clamp on blur (verified: typing `8` into max-attempts shows "max 5" live, blurring
  corrects it to `5`); the Worker clamps the same values again, since a client-side guard alone
  never stops a direct API call.
- **Verified the actual model, not just the label, for streamed Dynamic Route replies.** OpenAI-shape
  SSE chunks carry the real `model` field (e.g. the specific leaf a policy graph routed to); the
  client previously ignored it and always showed whatever was in the model dropdown. Fixed in
  `api.ts`'s SSE parser + `useChat.ts`.
- **Consequence surfaced, not hidden**: `CF_AIG_TOKEN` is now load-bearing for the *entire* AI
  Gateway route, not just Dynamic Routing. Diagnosed and fixed our own stale docs/error text, which
  told people to create the token with a permission ("AI Gateway Run") that doesn't exist — the
  real requirement is `AI Gateway - Read`, `AI Gateway - Edit`, `Workers AI - Read` on a normal
  account API token, not the gateway-scoped "Run" token from Authenticated Gateway (which this REST
  call rejects with a bare `{"code":10000,"message":"Authentication error"}`). **Status in prod is
  unverified** — see Open bugs #1.

**Edge-verdict lookup: fixed a real "can we ever fail to see detections" bug, then made it fast.**
- Root cause found via a direct question about log retention: the query window was
  `[now−15min, now+1min]` — anchored to *when you look*, not to the request. Any prompt-log row
  older than ~15 minutes was **guaranteed** to come back empty, and the UI blamed "ingestion delay"
  — actively misleading, since Cloudflare's real retention (confirmed live: 31 days on this zone,
  via the GraphQL settings node's `notOlderThan`) had nothing to do with it.
- **Proven with a real ray** (`a2338b3e69c78949`, sent ~5.5h earlier): unanchored → `found: false`;
  anchored to its own timestamp → full verdict recovered (injection score 99, unsafe topic S6, 2
  matched WAF rules). Same ray, same data, only the query window changed.
- A genuine "too old" state now exists and is reported honestly (`tooOld`, "older than the 31-day
  edge analytics window") instead of the misleading ingestion-delay text.
- **Historical rows no longer pay the 60s live-ingestion wait.** Measured: an hours-old prompt-log
  row now resolves in **4ms** (one request) versus 60,000ms before. A per-ray cache means
  collapsing/re-expanding the same row, or browsing many rows, does zero extra network calls.
- Live chat is provably unaffected: a row timestamped `now` still polls (verified — the age check is
  derived from `ts`, not a separate mode flag), and DemoMode's scoring timings are untouched.

**A live incident caught and fixed: false WAF/AI-Security attribution on non-WAF blocks.**
- User reported a chat turn shown as "Blocked by Cloudflare WAF — Blocked by Cloudflare AI Security
  for Apps" while the verdict card *simultaneously* said "LOGGED — Reached the model" with a Worker
  node claiming "request allowed" and a Workers AI node claiming "model generated the reply" — three
  contradictory claims on one screen, all wrong.
- Root cause, confirmed with the real edge data for that ray: `httpStatus: 403`, but the only two
  matched rules were **log-only**, and mitigation was **"Not mitigated"**. The 403 came from a layer
  above the WAF — in this case traced by the user to a **Cloudflare Access** misconfiguration (a
  `Bypass` policy meant to exempt `/api/chat` for a red-team service was scoped to the whole
  application, and `Bypass` is separately documented as unreliable behind a Worker — Cloudflare's
  own recommendation is `Service Auth` instead). The app had no way to know that, but it also had no
  business asserting WAF/AI-Security involvement it couldn't back up.
- Fix: `verdictOutcome()` now cross-checks the rules against the edge's own status; a non-2xx with
  no *blocking* rule match is a new `denied` outcome (pill **STOPPED**, not BLOCKED), and the block
  card only attributes to a specific detector when the response body actually says so (`data.blocked`
  from a Custom-JSON WAF rule) — a bare 403/HTML now reads "the edge returned 403 without a
  structured reason" instead of guessing. Verified both directions live: a mocked bare-403 shows no
  WAF/AI-Security claim; a mocked Custom-JSON block still attributes correctly.
- **Recommended Access remediation given, not yet applied** (dashboard change, out of app scope):
  split into two Access apps — a path-scoped `/api/chat` app with `Service Auth` + a service token
  for the red-team service (ahead of an `Allow` policy for human IdP logins, since Service-Auth-only
  apps require the token on every request), leaving the broader host on its existing policies. See
  Open bugs.

**Prompt log rebuilt as a sortable, filterable table.**
- Was a list of collapsible cards; now a `<table>` — Time/Outcome/Route/Model/Prompt/Tok/PII columns,
  click any header to sort (numeric columns default descending, text ascending; click again to
  flip), defaults to **Time, newest first**. Verified numeric (not lexicographic) sort:
  `333 → 105 → 70 → 55 → 55 → 12`.
- **Time frame**: 1h/24h/7d/all preset buttons (default **1h**) plus a **Custom** option revealing
  native `datetime-local` from/to inputs, seeded with the currently-active preset's span on first
  open. Backend: `parseTimeWindow()` shared by the row query and the D1 rollups, so stat tiles and
  chart always describe the same window as the table. Verified via curl against seeded rows at
  1h/5h/10h/20h old — every preset and a custom `since/until` pair returned exactly the expected
  rows.
- **Outcome filter is multi-select** (color-coded toggle chips, not a single dropdown) — any
  combination of replied/guardrails-blocked/error, e.g. "show everything except guardrails-blocked".
  Backend takes a comma-separated `outcome` list → SQL `IN (...)`.
- **Client-side text filter** (prompt/reply/model/ray) and **empty-state disambiguation**: "no
  prompts logged yet" vs. "N prompts stored, just not in this window — try widening it" are now two
  different messages, previously conflated into one misleading one.
- Wide table scrolls in its own box at narrow viewports rather than the page (verified no horizontal
  page-scroll at 375px, despite a 766px table).

**Chat page layout — a real containment bug, plus positioning.**
- The message list never actually scrolled internally on some viewport sizes — a flex column chain
  missing `min-h-0` let it grow to fit all content instead, dragging the whole page taller and
  fighting the auto-scroll-to-bottom effect. Fixed by threading `min-h-0` through the chain.
- That fix then broke the layout **below** the `lg` breakpoint, where three fixed-height panes can
  no longer all fit one screen (sidebar + Attack Library are `shrink-0` with far more content than
  available height) — the chat pane collapsed to 32px (just its padding) and its toolbar painted
  over the Attack Library. Fixed by scoping the fixed-viewport shell to `lg:` and letting the whole
  page scroll as one column below it. Verified at 1400px (row, page fixed, 3194px of injected
  content still contained), 1023px (just under `lg`), 662px (the original bug report — chat pane
  32px→660px, no overlap), and 375px mobile.
- The ChatGPT-style prompt navigator (hover the right-edge tick rail → jump to an earlier prompt)
  was nested inside the centered message column, so it sat inset from the true pane edge instead of
  in the outer gutter like the reference. Restructured so it's a sibling of the centered column,
  anchored to the full-width pane.

**Chat core (`/`)**
- Model picker (7 models); per-reply metadata line: model · ray · tokens (in/out) · ~cost.
- **Multi-turn** toggle (default off): history sent + honored across turns; standalone when off.
- **Streaming** toggle (default on): live token render; real SSE `usage` when emitted, else
  estimated; client-side cost from served prices.
- **"log prompt" toggle** (default on, new this session): off → `excludeFromLog: true` skips the D1
  write for that turn, independent of AI Gateway's own request log. Verified with a fake `cf-ray`:
  logged turn wrote a row, excluded turn did not (`total` stayed at 1).
- **Chat session persistence**: survives tab switches, cleared on refresh (module-level store).
- **Reasoning models**: `extractReply()` falls back to `message.reasoning` and strips
  `<think>…</think>`.

**Edge verdict + flow trace**
- Unified verdict card per reply/blocked turn: filled action badge + plain-language outcome line +
  ray. A Guardrails block shows a purple `GUARDRAILS · 2016/2017` badge instead of the edge pill.
  The flow trace is the card body (no toggle) — every detection lives in its node.
- **Request-chips row** (new this session): the User Prompt node shows exactly what was requested at
  send time — route, stream/multi-turn, and (gateway only) every `cf-aig-*` setting that was
  non-default, plus any metadata tags — snapshotted per turn so it stays accurate even after the
  controls change for the next message.
- Custom-topic match strength = `100 − score` (higher = stronger), sorted strongest-first, bar width
  agrees with the printed number.
- AI-Gateway-aware: an AI Gateway node between Worker and Workers AI (cache HIT/MISS read off the
  REST response header, latency, log id, GUARDRAILS badge, and now a blue `ROUTE <name>` badge when
  a Dynamic Route picked the model). Guardrails-block cases (2016 vs 2017) render distinctly correct
  flows, not a generic "allowed" trace.

**AI Gateway Dynamic Routing** — code path shipped and generalized into the main gateway call this
session (previously a special case only reachable when a route name was set; now the same
`runGatewayRest()` handles plain gateway calls and Dynamic Routes uniformly).
- Route names accept either form (`normalizeDynamicRoute`): bare `demo-routes` or the dashboard's
  `dynamic/demo-routes`. An unusable name is a 400, never a silent fallback to the Model picker's
  model (that was a real shipped bug — it looked like it worked while running a different path).
- UI: **Route** input in the gateway controls. The Model picker is inert on this path — the reply
  reports the model that actually *ran* (now correctly read off streamed chunks too, see above),
  with a blue `ROUTE <name>` badge.
- Routes recommended for the demo (build in dashboard → gateway → Dynamic Routes):
  `canary-90-10` (Percentage split, verify via Prompt log's by-model bars) · `tiered-by-plan`
  (Conditional on `plan == "paid"`) · `budget-guard` (Budget Limit → cheap-model fallback) ·
  `abuse-shield` (Rate Limit → fallback).

**AI Gateway custom metadata** — up to 5 key/values per request, sent as the `cf-aig-metadata`
header (not a body field — silently ignored there). Cap enforced both sides (`MAX_METADATA_ENTRIES
= 5`); `parseMetadata()` shared by the input panel and the send pipeline so preview can't drift from
what's transmitted.

**Demo autopilot**: 6-step scripted tour (baseline → injection → PII → unsafe S9 → unsafe S6
log-only → custom topic), per-step expect-vs-actual with edge verdict polling, Stop button, final
scorecard.

**Attack Library / system prompts**: 13 preset personas + custom editor; searchable library with a
Multi-turn Jailbreak (Crescendo) category and graded custom-topic tuning presets. `ZONE_RULES`
mirrors the zone's 10 WAF rules (hand-maintained — see Open bugs).

**Session export** (JSON / Markdown): re-fetches each turn's verdict at export time (single lookup).
⚠️ Still uses the pre-fix unanchored window — see Open bugs, this is the same bug class just fixed
for the prompt log, not yet ported here.

**Analytics page**: edge tab (zone-scoped: tiles, events-over-time, top rules, injection-score
histogram, per-category breakdowns, scan-coverage readout) and gateway tab (account-scoped, gateway
dropdown, tiles, hit/miss/error over time, by-model, status codes — source is the AI Gateway logs
REST API, pages to 500 rows). Charts are line+area (unstacked — stacking misrepresents sparse
zero-heavy security data), shared by all three tabs via `EventSeries`. Prompt log tab: see above.

**Compliance page**: 6-framework coverage matrix + tabs with per-control detail cards, 4 graded
coverage levels, all 10 OWASP items incl. the 4 Cloudflare doesn't address. Every card cross-links
to the demo that exercises it.

**Cross-cutting**: two-row header + shared `NavTabs`; light/dark verified; `npm run check` + `npm
test` clean (49/49). **Not yet redeployed** — everything above past the 6 committed commits is
local/uncommitted.

---

## Open bugs / caveats

**Blocking / high severity**

1. **`CF_AIG_TOKEN` permission scope is unverified in prod, and now blocks the entire AI Gateway
   route, not just Dynamic Routing.** Diagnosed this session: the real requirement is `AI Gateway -
   Read`, `AI Gateway - Edit`, `Workers AI - Read` on a normal API token — our own prior docs/error
   text said "AI Gateway Run", which isn't a real permission name, and pointed people toward the
   gateway-scoped Authenticated-Gateway token instead, which this REST call rejects outright
   (`{"code":10000,"message":"Authentication error"}` — reproduced against the live token this
   session). Because the gateway route no longer has a binding fallback, **if this token is
   mis-scoped, toggling to "AI Gateway" in prod fails on every single request**, not just Dynamic
   Routes. Fix: recreate/re-scope the token with the three permissions above, `wrangler secret put
   CF_AIG_TOKEN`, then retest a plain (non-Dynamic-Route) gateway send in prod.
2. **Zero Trust Access misconfiguration — root cause of a live "false block attribution" incident.**
   An Access `Bypass` policy intended to exempt `/api/chat` for an AI red-team service was scoped to
   the entire application (no path restriction) and used `Bypass`, which Cloudflare separately
   documents as unreliable behind a Worker (recommends `Service Auth` instead). Net effect: traffic
   was stopped at Access, not the WAF, and — before this session's fix — the app wrongly displayed
   it as a WAF/AI-Security block. **Recommendation given, not yet applied**: split into a
   path-scoped `/api/chat` Access app with `Service Auth` + a service token (`CF-Access-Client-Id`/
   `-Secret` headers) for the scanner, plus an `Allow` policy for human IdP logins on the same app
   (required — a Service-Auth-only app demands the token on every request, including from the
   browser UI). Until this is restructured, either the host stays over-exposed via the current
   Bypass, or a future Access-side change could re-break `/api/chat` for humans the same way.

**Product / configuration**

3. **Guardrails not confirmed *blocking* live.** The guarded gateway processes requests and the
   GUARDRAILS badge shows, but no unsafe prompt has produced a real 2016/2017 → purple card on prod.
4. **WAF block responses are still Cloudflare's default HTML page**, not Custom JSON — set each
   block rule's response to Custom JSON so the blocked card pretty-prints instead of showing "not a
   custom JSON body".
5. **Account-level "Monitor Likely Attacks (Score GE 20 AND LE 50)" is a red herring** — fires on a
   non-LLM attack score despite the name; visible in the analytics top-rules list.
6. **Dynamic Routing prerequisites are unproven end to end** independent of bug #1: Routes need an
   Authenticated Gateway; a route branch calling third-party models also needs BYOK or Unified
   Billing credits.

**Known gaps introduced/left by this session's fixes**

7. **`export.ts` has the same unanchored-window bug `queryVerdict` used to have, unfixed.** Exporting
   a session left open more than ~15 minutes will mark every turn's verdict "not yet ingested" even
   though the data is sitting right there — same root cause as the prompt-log bug, different call
   site. Needs an epoch timestamp on `Msg` (today only a display string from `fmtTime`) before it
   can pass `ts` through the same way the prompt log now does.
8. **`GatewaySettingsPanel`'s client-side validation duplicates the Worker's clamping logic by
   hand** (`MAX_GATEWAY_ATTEMPTS`, `MAX_GATEWAY_RETRY_DELAY_MS` redefined in `FirewallPage.tsx`
   rather than imported) — the two will silently drift if the caps ever change server-side.

**Known limits (by design)**

9. **Verdict/autopilot timing for a just-sent prompt**: GraphQL ingests ~1–2 min behind; the poller
   waits 60s before its first check, then every 5s up to ~190s total. This is now *only* paid on
   live sends — historical lookups (prompt log) are one-shot, see Implemented.
10. **`ZONE_RULES` is a hand-maintained mirror** of the dashboard rules — rename/add a WAF rule and
    the flow-trace matching drifts until `web/src/lib/data.ts` is updated.
11. **Row caps**: zone analytics reads the latest 500 rows/dataset; gateway logs page to 500 (API
    caps `per_page` at 50) and set `truncated`. Prompt log rows cap at 200 per fetch.
12. **AI Gateway logs are account-scoped** and still store the **raw** prompt+response payload —
    unlike the D1 prompt log, which is PII-redacted and now individually opt-out-able per turn. Left
    on deliberately as a talking point; the UI states it.

## Next tasks

**Unblock (do first)**

- [ ] Verify/fix `CF_AIG_TOKEN`'s permission scope in prod (Open bug #1) — this now gates the whole
      AI Gateway route, not just Dynamic Routing. Self-check: a plain gateway send (no Dynamic
      Route) should succeed, not 10000.
- [ ] Apply the recommended Zero Trust Access restructuring for the AI red-team service (Open bug
      #2): path-scoped `/api/chat` app, `Service Auth` + service token, `Allow` policy alongside it
      for human logins. Re-verify the app still works for a normal browser session afterward.
- [ ] Commit the uncommitted work (see Version control) in reviewable chunks — it currently spans
      the AI Gateway REST migration, the verdict/retention fix, the attribution fix, the prompt log
      rewrite, and the layout fixes as one working-but-unstaged diff.

**Then verify what is currently unproven**

- [ ] Prod smoke test once #1 is fixed: a plain AI Gateway send, then a Dynamic Route send with
      `tier=free` (isolates routing from third-party billing) before `tier=pro`. Confirm the reply
      reports the *route's* model + blue `ROUTE` badge, not the Model picker's value.
- [ ] Confirm custom metadata actually lands in the gateway logs — still outstanding from before
      this session.
- [ ] Confirm Guardrails actually blocks on prod (unsafe prompt via the guarded gateway → purple
      card).
- [ ] Set WAF block-rule responses to Custom JSON (dashboard).

**Improvements**

- [ ] Port the anchored-verdict-window fix to `export.ts` (Open bug #7) — needs an epoch timestamp
      on `Msg`.
- [ ] De-duplicate the gateway-setting caps between `FirewallPage.tsx` and the Worker (Open bug #8)
      — export the constants from one place both sides import, or have the client ask the server.
- [ ] Map upstream AI Gateway auth failures (HTTP 401/403, `code 10000`) to an actionable message
      instead of dumping the raw Cloudflare error JSON into the chat bubble — directly relevant now
      that bug #1 can surface on every gateway send, not just Dynamic Routes.
- [ ] Extend tests to remaining pure functions (extractReply/stripThink, sanitizeHistory,
      buildHistory, cost calc, SSE line parser).
- [ ] Compliance page: GRC reviewer to sanity-check subcategory titles + section descriptions before
      regulated-customer use.

**Done this session** — AI Gateway REST migration (uniform per-request settings + validation) ·
anchored/retention-aware verdict lookup + one-shot historical fetch + ray cache · WAF-vs-Access
false-attribution fix (`denied`/STOPPED outcome) · prompt log rewritten as a sortable/filterable
table with time-frame + multi-select outcome filters · chat layout containment + responsive
stacking fix · prompt navigator repositioning · shared `Switch` component · per-turn "log prompt"
D1 opt-out · streamed Dynamic Route model attribution fix · 17 new tests (32→49).

**Previously done** — `git init` + signed history · PII-redaction tests · dead-code removal (file
upload, cache TTL) · line+area charts · `AnalyticsPage` split into `components/analytics/` · D1
prompt log + SQL rollups · Dynamic Routing call path · metadata transport fix.

## Setup checklist (fresh zone)

1. `npm install`, then `npm run deploy` (Node ≥ 22).
2. Enterprise zone with the AI Security add-on; attach the proxied custom domain.
3. Security → Settings → enable **AI Security for Apps**.
4. Security → Web Assets → ensure `POST <host>/api/chat` exists, apply the **`cf-llm`** label.
5. Security → WAF → custom rules on `cf.llm.*` (block/log). See README for expressions; set block
   responses to **Custom JSON**.
6. AI Gateway: create at least the two demo gateways; set `CF_AI_GATEWAY_ID` /
   `CF_AI_GATEWAY_GUARDED_ID` vars (guarded one has Guardrails enabled in the dashboard).
7. `wrangler secret put CF_ANALYTICS_TOKEN` — needs **Zone Analytics: Read** (verdict + analytics),
   **Account Analytics: Read** (neurons), and **AI Gateway Read** (account gateway dropdown **+
   the Analytics page's AI Gateway tab**). Any missing scope degrades only its feature; the
   gateway list falls back to the two var gateways and the gateway tab shows a scope hint.
8. `wrangler secret put CF_AIG_TOKEN` — **required for the whole AI Gateway route**, not just
   Dynamic Routing: every gateway request now goes through the OpenAI-compatible REST endpoint
   (not the `env.AI.run()` binding) so the full set of per-request `cf-aig-*` headers works
   uniformly. Needs **AI Gateway - Read**, **AI Gateway - Edit**, and **Workers AI - Read** — not
   the gateway-scoped "Run" token from Authenticated Gateway, which this REST call rejects with a
   bare `{"code":10000,"message":"Authentication error"}`. Kept apart from the read-only analytics
   token on purpose. Without it, any AI Gateway request returns a 501 naming the missing secret;
   the direct Workers AI route is unaffected (still the plain binding, no token needed).
9. If exempting any endpoint from Cloudflare Access for automated callers (e.g. a red-team
   scanner), scope the Access application to that **exact path** and use a **Service Auth** policy
   with a service token — not `Bypass`. `Bypass` disables Access logging entirely and is separately
   documented as unreliable behind a Worker (which this app always is). A Service-Auth-only app
   still needs a companion `Allow` policy for human IdP logins if the same path is also used
   interactively (e.g. the browser chat UI hitting `/api/chat` directly).
