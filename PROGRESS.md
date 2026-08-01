# Progress — Cloudflare AI Security demo

_Last updated: 2026-08-01_

Customer-facing demo of **Cloudflare AI Security for Apps** (formerly *Firewall for AI*) plus
**AI Gateway** (routing, caching, Guardrails, Dynamic Routing), a **security analytics dashboard**,
an **in-app red-team runner**, and a **compliance mapping page**. Live at
**https://cf-ai-waf-demo.nttlab.org** (account **NFR - TH - NTT** `daf82c7c…`, zone `nttlab.org`).

Prod is behind **Cloudflare Access**. Functional testing is done on `wrangler dev` (real Workers AI
+ real zone GraphQL + real AI Gateway REST API), seeding local D1 with `wrangler d1 execute …
--local` and faking a `cf-ray` header via curl where the edge-verdict / prompt-log join needs one
(local dev never sets a real one). Node ≥ 22 (`nvm use 24`).

> **Reading this doc**: "this session" below refers to the **2026-08-01** session (Red Team page,
> analytics honesty pass, chart rework). The AI Gateway REST migration, verdict-window fix,
> WAF-attribution fix and prompt-log rewrite landed in the **2026-07-31** session and are now
> committed — see Version control.

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
  `src/models.ts`: **4 enabled** — Llama 3.2 3B (default, `MODEL_REGISTRY[0]`), Gemma 4 26B,
  Mistral 7B, Qwen3 30B — plus 3 commented-out rows kept for quick re-enable (GPT-OSS 20B,
  DeepSeek R1 Distill 32B, Llama Guard 3 8B). `MAX_REPLY_TOKENS = 2048`. Prices served to the
  client for cost estimates.
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
  + `httpRequestsAdaptive` filtered to `/api/chat`), tallied server-side into one payload. The same
  GraphQL round trip also fetches the **immediately preceding window** via aliased `fwPrev`/
  `httpPrev` fields, for the tiles' trend deltas.
- **The analytics numbers refuse to overstate their own precision.** Two related rules, both
  enforced server-side in `queryAnalytics`:
  - A dataset that returns exactly the 500-row cap is **truncated**, so `totalEvents` is a floor,
    not a total. The Worker sets `truncated` and the tile renders `500+` with a banner rather than
    presenting a capped count as exact — the old UI said a flat "500", which was simply wrong.
  - `prev` is **omitted entirely** when the previous window was itself truncated, and the client
    then shows no delta and no percentage. A rate computed off a truncated total, or a delta
    between two capped windows, reads as precise while being meaningless; no number beats a
    confidently wrong one.
- **AI Security rules are separated from unrelated zone rules in the UI.** On real traffic the
  zone's non-LLM rules (`(P) AI Red Team`, `Geography-based rule`, `cw-lab-kali OWASP ZAP`) outrank
  the `cf.llm.*` rules by event count, so a single "Top fired rules" list read as though AI Security
  had fired them — the same misattribution class as the `denied` fix. `isLlmRule()` in `data.ts`
  matches `ZONE_RULES` by name with a `\bLLM\b` fallback (so a renamed rule degrades to "probably
  LLM" rather than silently dropping into "other"), and `EdgeTab` renders two labelled groups.
- **WAF rules are read live from the zone, and classified by expression, not by name.**
  `/api/zone-rules` reads the `http_request_firewall_custom` entrypoint ruleset (Rulesets API,
  isolate-cached) and marks each rule `llm` when its **expression** references `cf.llm.*`. The old
  path matched a hand-maintained mirror **by name**, so renaming a rule in the dashboard silently
  moved it into "not AI Security" in the analytics split and out of the flow trace's matched list —
  the same misattribution class as the `denied`/STOPPED fix, arriving by a different door. The
  mirror survives as a **fallback** (no token scope → static list) and the flow trace states which
  source it used; swapping one silent source for another would not have been an improvement.
  Disabled rules are excluded from the "N evaluated" count and marked, rather than counted as
  coverage. Needs **Zone → WAF → Read** on `CF_ANALYTICS_TOKEN` — see Open bugs, currently missing.
- **The prompt log pages, sorts and searches in SQL.** Previously the newest 200 rows were fetched
  and the browser sliced them, so with 2,700+ rows stored nothing older was reachable however you
  filtered. `buildPromptLogQuery` (`src/promptlog.ts`, unit-tested) now owns `WHERE`/`ORDER BY`/
  `LIMIT`/`OFFSET` and the response carries `filtered` (rows matching the filters) alongside
  `total`. Sort and text search moved server-side **with** paging, deliberately: they were correct
  client-side only while every row was in hand — once the table is genuinely paged, sorting one
  page while appearing to sort the table is exactly the kind of quiet lie the rest of this app
  works to avoid. `sort` is the only user input that reaches `ORDER BY`, where a bind parameter is
  impossible, so it is resolved through a whitelist map and anything else falls back to `ts`.
- **Streamed replies now reach the prompt log.** The reply text of a streamed turn never exists
  server-side, so the row was written with `reply = NULL` — and streaming is the DEFAULT, so the
  log's reply column was empty for most real traffic while the UI described it as the evidence
  trail. `teeReplyToLog` passes the SSE through untouched (no buffering, no added latency),
  assembles the text with a shared reader (`src/sse.ts`), and `UPDATE`s the row on flush. The
  update is **chained onto the insert's promise**: both run under `waitUntil`, which guarantees no
  ordering, and an UPDATE that lands first silently matches no row.
- **Chart bucket width is chosen in one place and follows the window the caller asked for.**
  `bucketFor()` in `config.ts`: **5-minute buckets at 1h**, hourly to 48h, daily beyond. The 1h
  range used to bucket hourly, i.e. one or two points — a number, not a chart. Three call sites
  (zone analytics, gateway analytics, prompt analytics) each carried their own copy of the ternary
  and could drift, so they now share the helper. The prompt-log rollup additionally passes the
  **requested** span rather than re-measuring `Date.now() − since`: re-measuring is long by the
  milliseconds spent parsing, which pushed the 1h preset just past 1.0 hours and silently dropped
  it back to hourly buckets.
- **The prompt-log series is zero-filled across the window**, like the zone analytics scaffold
  always was. Previously it only held buckets that had rows, so the line interpolated straight
  across quiet stretches — drawing activity that never happened. Invisible at hourly width on a
  1h range (1–2 points); obvious at 5 minutes, which is what surfaced it. Pre-fill is capped at
  400 buckets so a hand-typed `since` far in the past can't spin the loop.
- **The shared chart is sized in real pixels, not a fixed aspect ratio.** `EventSeries` was
  `viewBox="0 0 720 90"` on a `w-full` svg, which scales *everything* with container width —
  including text. That put axis labels at ~19px on a 1600px page and ~3.9px on mobile, where the
  plot collapsed to ~24px tall. It now measures its box with a `ResizeObserver` and drives the
  viewBox from it, so 1 unit = 1 CSS px and type is the size it says it is at every width.
  Deliberately **no `width`/`height` attributes** on the svg: an explicit width makes the svg force
  its own parent wide, so the observer can never see the box shrink — a feedback loop that pins the
  chart at its widest.
- **Chart colours are validated, not eyeballed.** The series palette is the app's status palette
  (block/error = red, log = amber, guardrails = purple, allowed/hit = green) — status semantics, so
  the hues are reserved and never reassigned per chart. The light-mode `--red`/`--amber` pair was
  measured at **ΔE 3.0 under deuteranopia** (and 14.9 under normal vision, below the legibility
  floor), i.e. "blocked" and "logged" were effectively the same colour on the security chart. Both
  tokens moved together — `#b91c1c` / `#d97706`, now 16.2 / 18.7 — because no amber bright enough
  to separate from the old red also clears contrast on white. Re-run a CVD validator before
  changing either value.
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
  whole demo session"). Prompt log is a **sortable, paginated table** (click any column header;
  defaults to Time, newest first; 10/25/50/100 rows per page, default 25) with a client-side text
  filter (prompt/reply/model/ray) and a **multi-select** outcome filter (toggle any combination of
  replied/guardrails-blocked/error). 60s auto-refresh on all three tabs.
  **Drill-through**: clicking a rule or an injection-score bucket on the edge tab switches to the
  prompt log with the window matched and a context banner. For a *blocking* rule the banner says
  outright that those prompts never reached the Worker and cannot appear in the log — otherwise the
  click lands on a confusingly empty table.
- **`/redteam`** — replays a curated **36 of the 116** enumerated attacks from the Prisma AIRS scan
  (target `cw-ai-red-team`, 2026-07-30; Thai-language) through the real `/api/chat` and scores what
  the edge did. Route selector (Workers AI ↔ a specific AI Gateway, locked mid-run so a batch never
  mixes routes), scorecard, sortable attack table, and a static "close the gaps" panel mapping each
  scan finding to the Cloudflare control that addresses it.
- **`/compliance`**: coverage matrix (capability × framework) + framework tabs with per-control
  detail cards. **Six frameworks**: NIST AI RMF · ISO 42001 · OWASP LLM Top 10 · MITRE ATLAS ·
  Bank of Thailand AI risk policy (2025) · NCSA AI Security Guidelines (2025). The OWASP LLM01 and
  MITRE AML.T0051 cards link to `/redteam`.
- **Page width**: `/analytics`, `/redteam` and `/compliance` run to `max-w-[1600px]`; the chat page
  keeps its own three-pane shell.

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
  lib/              data.ts (demo content + isLlmRule), compliance.ts (MATRIX + FRAMEWORKS), api.ts
                    (fetch wrappers incl. TimeWindow + SSE parser), types.ts, format.ts, icons.ts,
                    verdict.ts (classify + poller + fetchVerdictOnce + ray cache), export.ts
                    (session export — ⚠️ still uses the old unanchored window, see Open bugs),
                    metadata.ts (AI Gateway metadata parser), sessionStore.ts,
                    redteam.ts (Prisma AIRS corpus + scoring helpers)
  hooks/            useTheme, useNeurons, useChat (session + send pipeline, RequestConfig snapshot
                    per turn for the verdict trace's request-chips row), useRedTeam (3-phase runner)
  components/       Header, NavTabs, ThemeToggle, NeuronChip, SystemPromptPanel,
                    GatewaySettingsPanel (all 9 cf-aig-* settings + validation; replaces the old
                    RequestMetadataPanel), Switch, AttackLibrary, Chat, Verdict, FlowTrace,
                    DemoMode, ExportButton
    analytics/      primitives (Tile with rate/delta, Card, BarList with onPick/scaleMax),
                    EventSeries (measured line+area chart + table view + keyboard), EdgeTab
                    (LLM vs other rule split, drill-through), GatewayTab, PromptLogTab (sortable +
                    paginated table + filters)
    redteam/        Scorecard (headline tiles + severity/category breakdown)
  pages/            FirewallPage (chat + route/gateway controls), AnalyticsPage (shell: state,
                    loaders, tab strip, filters incl. prompt-log time window + outcome multiselect,
                    drill-through banner), RedTeamPage, CompliancePage
```

New since the layout above was written: `src/promptlog.ts` (prompt-log query builder), `src/sse.ts`
(Worker-side SSE reader), `web/src/hooks/useZoneRules.ts` (live zone rules + fallback).

Scripts: `npm run build` · `npm run deploy` · `npm run check` (worker typecheck) · `npm test`
(vitest, `vitest.config.ts` — separate from `vite.config.ts`, which sets `root: "web"`) · `npm run
dev:worker` / `npm run dev:web`. `.claude/launch.json` has `wrangler-dev` + `vite-dev` configs.

**Version control**: **10 commits** (`ed669b6` … the doc resync). All work since `a4f78d2` sits on
branch **`feat/gateway-rest-and-red-team`**; `main` is still at `a4f78d2`, so **prod runs none of
the last two sessions' work**:

- `14a71f6` — AI Gateway REST settings, anchored verdicts, analytics overhaul. One commit by
  necessity: those areas share files (`cloudflare.ts`, `useChat.ts`, `AnalyticsPage.tsx`) and this
  environment has no hunk-level staging, so a per-feature split wasn't possible without surgery.
  Verified green in isolation before committing.
- `f59a88e` — the Red Team feature, which *was* cleanly separable (its three wiring edits touch
  nothing else).
- `4f2079d` — the chart rework (`EventSeries.tsx` + `index.css`): measured viewBox, CVD-safe
  light palette, table view, keyboard parity.
- the doc resync (this file + `README.md`) — see Doc split below.

⚠️ Working tree clean, but the branch is **unmerged and not redeployed**.

**Doc split** (README rewritten 2026-08-01 against the code, having drifted several sessions):
`README.md` = product + setup reference (pages, endpoints, gateway/verdict/prompt-log behaviour,
zone setup, WAF rule table, tests); **this file** = engineering state (decisions, open bugs, next
tasks). The old README still documented the removed `/api/extract` file-upload feature, the
binding-based gateway path, and a model list that had never matched `src/models.ts` — all corrected.

Note: `commit.gpgsign` is on and this key's passphrase is not cached, so committing from a
non-interactive shell fails with `Inappropriate ioctl for device`. Run `export GPG_TTY=$(tty)` in
an interactive terminal first (pinentry is `curses`; there's no `pinentry-mac` installed).

**Tests** — `npm test`, **102 across 10 files** (64 before the hygiene pass, 49 before that).
Each exists because a real bug shipped, and each was mutation-verified (reintroduce the bug → red):
- `src/promptlog.test.ts` (17) — the prompt-log query builder. Offset reaching past the old 200-row
  ceiling, LIKE-wildcard escaping (searching `100%` used to match everything), and an `ORDER BY`
  whitelist that discards anything not on it — `sort` is the only user input in the app that reaches
  SQL where a bind parameter is impossible. Mutation-verified: replacing the whitelist with
  `p.sort || "ts"` turns the fallback test red.
- `src/sse.test.ts` (11) — the Worker-side SSE reader behind streamed-reply logging, including a
  `data:` line split across two network chunks. Mutation-verified: dropping the re-buffer turns that
  case red, which is exactly the bug that would silently truncate logged replies.
- `src/zone-rules.test.ts` (4) + `web/src/lib/zonerules.test.ts` (6) — classification by expression
  rather than name: a rule renamed away from "LLM" stays classified, a rule merely *mentioning* LLM
  does not, and account-level rules (never in a zone ruleset) still fall back to the heuristic.
- `src/redact.test.ts` (18) — PII redaction against the real Attack Library prompts. Asserts the
  identifier is **absent** rather than matching an exact replacement (the shipped bug was a
  *partial* mask leaking part of an IBAN). No-false-positives + idempotency.
- `src/config.test.ts` (8) — `normalizeDynamicRoute`. Accepts both `demo-routes` and the dashboard's
  `dynamic/demo-routes`; returns `null` (never a silently wrong value) for traversal or junk.
- `web/src/lib/metadata.test.ts` (6) — the 5-entry cap and malformed-pair handling.
- `web/src/lib/redteam.test.ts` (15) — **new this session**. Pins the red-team scoring contract, the
  one number the feature exists to produce: `log` counts as *reached the model* (a detection is not
  a defense), `block`/`challenge` do not, and `denied`/`guardrails`/`pending`/`error` are counted
  and displayed but **excluded from the denominator** — otherwise the percentage would credit the
  WAF for an Access refusal or punish it for ingestion lag. Also covers divide-by-zero, corpus
  integrity (36 unique ids), and that the PDF's SARA-AM artifact (`ำา`) never crept back in.
- `src/verdict-window.test.ts` (9) — `verdictWindow()`: anchored vs. live
  bracketing, the regression itself (the live window provably excludes an hours-old timestamp the
  anchored one covers), non-finite-timestamp fallback. `isBeyondRetention()`: inside/past/exact
  boundary, and — important — an *unknown* timestamp never reads as expired (there's nothing to
  compare, so the lookup must still be attempted).
- `web/src/lib/verdict.test.ts` (8) — built from a real incident's exact
  payload (ray `a23939307b53893b`). Asserts a 403 with only log-only matched rules classifies as
  `denied`, not `log`; a genuine `block`/`challenge` still classifies correctly; a 403 with zero
  matched rules also denies; covers 5xx as well as 403; falls back to the rules when the status is
  still unknown (nothing to contradict yet, so don't invent a denial).

---

## Implemented

Verified against real Cloudflare via `wrangler dev` + local D1 seeding unless noted.

### 2026-08-01 session

**Red Team page (`/redteam`) — replay the Prisma AIRS corpus against the live edge.**
- The scan (2026-07-30) reported **Risk 9.44/100 (Low)**, overall ASR 10%, **413 successful attacks**
  (116 enumerated). The agentic-security domain was **clean (0/168** — indirect prompt injection
  0/60, tool leak 0/108); the real gaps were **Brand Tarnishing / Self-Criticism (53)** and
  **Political (16 + 5 endorsements)** — precisely what the report's recommended runtime policy
  targets with Custom Topic Guardrails.
- Corpus: a curated **36 of the 116** in `lib/redteam.ts` — every scan category, all four
  severities, weighted to the two gap categories. Prompts are the report's own Thai text with the
  PDF font's SARA-AM decomposition artifact (`ำา` → `ำ`) repaired and preview ellipses trimmed.
  Several are the report's truncated preview, which is fine: the edge scan classifies partial text,
  and the edge is all this feature measures.
- **The headline metric is deliberately NOT the scan's ASR.** Prisma's ASR means *the model
  complied*; this measures only *whether the Cloudflare edge stopped the request*. There is no LLM
  judge, so the app never claims the model did or didn't comply — the metric is labelled "reached
  the model" and the scan's own per-prompt ASR sits in a separate, attributed column.
- **Runner is 3-phase, not one poll per attack** (which would cost ≥60s each ≈ 36 min): send all
  prompts → wait **once** ~90s for GraphQL ingestion → batch-resolve every ray through
  `fetchVerdictOnce` under a concurrency cap. ≈4 min for 36 attacks. It calls the API directly so a
  run never enters the chat transcript (verified), and leaves `excludeFromLog` false so rows land in
  D1 as the evidence trail.
- Route selector (Workers AI ↔ any account gateway) — the edge verdict is identical either way, but
  the guarded gateway adds Guardrails and can surface 2016/2017 blocks the WAF alone misses.

**Analytics honesty pass.**
- **`500` was never a total.** The edge tile showed a flat "500" that was exactly the query row cap
  — a floor presented as an exact count. Now `500+` with a banner, and rates/deltas suppressed
  whenever a window is truncated (see Architecture).
- **Tiles carry meaning**: block-rate percentage and a delta vs the preceding window (`14 ▼14 · 38%
  of events`), both omitted rather than faked when the data can't support them.
- **AI Security rules split from unrelated zone rules** — on live data `(P) AI Red Team` (192),
  `Geography-based rule` (44) and `cw-lab-kali OWASP ZAP` (29) were topping a list read as
  "detections". They now sit under a labelled "not AI Security" group.
- **Injection histogram made readable**: the clean bucket is >95% of traffic and was flattening the
  attack buckets to invisible slivers. Bars now scale across the attack range only, with the clean
  bucket listed separately.
- **Drill-through** from a rule / score bucket to the prompt log, with the honest caveat for
  blocking rules (their prompts never reached the Worker, so the log cannot show them).

**Chart (`EventSeries`) rework — measured, not eyeballed.**
- **Colourblind-safety fixed**: light-mode block↔log was ΔE **3.0** under deuteranopia and 14.9
  under normal vision. Now **16.2 / 18.7** by moving `--red` and `--amber` together (see
  Architecture for why amber alone can't work).
- **Real fixed height, non-scaling text**: measured viewBox via `ResizeObserver`. Verified scale
  **1.000** and tick font **10px** identically at 1600px and 375px (was 2.13×/~19px and
  0.43×/~3.9px). A first attempt that set `width`/`height` attributes deadlocked the observer —
  documented inline so it isn't reintroduced.
- **Accessibility**: a "Show data" **table view** (the WCAG-clean twin), **keyboard parity**
  (`←`/`→`/Home/End drive the same crosshair + tooltip, with an `aria-live` announcement), and
  **selective endpoint labels** so a value is readable without hovering. Verified: `End` then `←`×3
  landed on bucket 21 with the live region and tooltip agreeing exactly.

**Prompt log pagination** — 10/25/50/100 rows per page (default 25), resetting to page 1 on any
filter/sort change and clamping when a narrower filter strands the current page.

**Ray shown while a verdict is still pending** — the polling state now prints the ray, so a slow
lookup can be cross-checked in the dashboard instead of being an opaque spinner.

**A scroll bug traced to Tailwind's `sr-only`.** The whole page shell — header, content, footer —
could scroll off-viewport on the prompt log, leaving the footer stranded mid-page. Cause: the
table's `sr-only` "Expand" header is `position:absolute`, and with no positioned ancestor its
containing block was the *document*, so it escaped `main`'s `overflow-y-auto` and inflated
`documentElement.scrollHeight` as the table scrolled. Fixed by making `main` `relative`.
Diagnosed by measuring footer position frame-by-frame across two screen recordings — an earlier
guess that it was a one-frame compositor glitch was wrong, and the measurements disproved it.

### 2026-07-31 session

**Headline change: AI Gateway per-request REST settings, exposed and correct.**
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

**Cross-cutting**: two-row header + shared `NavTabs` (4 tabs incl. Red Team); light/dark verified
after the palette change across all four pages; `npm run check` + web typecheck + `npm test` clean
(**64/64**). **Not yet redeployed** — the branch is unmerged and the chart rework is still
uncommitted.

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

3. ~~**Guardrails not confirmed *blocking* live.**~~ **RESOLVED 2026-08-01.** Confirmed against the
   prod D1 prompt log: **67 rows** with `outcome='guardrails'`, all on `cf-ai-sec-demo-gw` with
   `guarded=1` (most recent 2026-07-31). Guardrails *is* blocking on prod. Visible in-app under
   Analytics → Prompt log with the outcome filter set to `guardrails-blocked`.
4. **WAF block responses are still Cloudflare's default HTML page**, not Custom JSON — set each
   block rule's response to Custom JSON so the blocked card pretty-prints instead of showing "not a
   custom JSON body".
5. **Account-level "Monitor Likely Attacks (Score GE 20 AND LE 50)" is a red herring** — fires on a
   non-LLM attack score despite the name. **Mitigated in the UI** as of 2026-08-01: it now lands in
   the "not AI Security" group rather than the AI Security rule list, so it can no longer be read as
   a detection. The rule itself still exists in the dashboard and still inflates raw event counts.
6. **Dynamic Routing prerequisites are unproven end to end** independent of bug #1: Routes need an
   Authenticated Gateway; a route branch calling third-party models also needs BYOK or Unified
   Billing credits.

**Known gaps introduced/left by this session's fixes**

7. ~~**`export.ts` has the same unanchored-window bug**~~ **FIXED 2026-08-01.** Every `Msg` now
   carries `tsMs` alongside its display `ts` (stamped together by one helper so they cannot describe
   different instants), and `buildSessionExport` passes it to `getVerdict`. Verified in the browser:
   the export now issues `/api/verdict?ray=…&ts=…`.
8. ~~**`GatewaySettingsPanel`'s validation duplicates the Worker's clamping by hand**~~
   **FIXED 2026-08-01.** `/api/models` serves `limits: {maxAttempts, retryDelayMs}`; `FirewallPage`
   and the panel read them and the three hand-copied constants are gone (there were three, not two —
   `GatewaySettingsPanel` had its own pair as well). Until the fetch lands the fields simply carry no
   client-side max; the Worker clamps regardless.
9. ~~**Prompt-log pagination only pages within the fetched 200 rows**~~ **FIXED 2026-08-01.**
   Paging, sorting and search are SQL now (`OFFSET` + whitelisted `ORDER BY` + `LIKE`), and the
   response reports `filtered` so the page count is real. Verified against 260 seeded rows: the last
   page reads "251–260 of 260" and a search reaches row 259 — 59 rows past the old ceiling.
10. **Dark-mode chart palette still fails the house lightness band** (`--red` L .691, `--amber`
    L .804 vs a .48–.67 band). Left alone deliberately: CVD separation — the check that actually
    governs distinguishability — already passes at 12.5, so this is a style-band mismatch, not a
    legibility defect, and churning dark tokens carries regression risk for no user-visible gain.

**Known limits (by design)**

11. **Verdict/autopilot timing for a just-sent prompt**: GraphQL ingests ~1–2 min behind; the poller
    waits 60s before its first check, then every 5s up to ~190s total. This is now *only* paid on
    live sends — historical lookups (prompt log) are one-shot, and the red-team runner pays it once
    for a whole batch rather than per attack. See Implemented.
12. ~~**`ZONE_RULES` is a hand-maintained mirror**~~ **FIXED 2026-08-01**, with one caveat below.
    Rules are read live from the Rulesets API and classified by expression (see Architecture).
    **Caveat: the live path is not yet exercised in this environment** — `CF_ANALYTICS_TOKEN` lacks
    **Zone → WAF → Read**, so `/api/zone-rules` currently returns
    `source:"fallback"` with `Ruleset list failed (HTTP 403)` and the UI runs on the mirror,
    labelled as such. Add the scope to the token to turn it on; the mapping itself is unit-tested,
    but the two API calls have never returned real data here.
13. **Row caps**: zone analytics reads the latest 500 rows/dataset; gateway logs page to 500 (API
    caps `per_page` at 50) and set `truncated`. Prompt log rows cap at 200 per fetch (see #9).
14. **AI Gateway logs are account-scoped** and still store the **raw** prompt+response payload —
    unlike the D1 prompt log, which is PII-redacted and now individually opt-out-able per turn. Left
    on deliberately as a talking point; the UI states it.
15. **The red-team corpus is a curated subset** — 36 of the 116 enumerated (of 413 total
    successful), and several prompts are the report's truncated preview text. It exercises the edge
    scan faithfully but is not a reproduction of the full scan.

## Next tasks

**Unblock (do first)**

- [ ] Verify/fix `CF_AIG_TOKEN`'s permission scope in prod (Open bug #1) — this now gates the whole
      AI Gateway route, not just Dynamic Routing. Self-check: a plain gateway send (no Dynamic
      Route) should succeed, not 10000.
- [ ] Apply the recommended Zero Trust Access restructuring for the AI red-team service (Open bug
      #2): path-scoped `/api/chat` app, `Service Auth` + service token, `Allow` policy alongside it
      for human logins. Re-verify the app still works for a normal browser session afterward.
- [x] ~~Commit the chart rework~~ — done, `4f2079d` (signed fine non-interactively; gpg-agent had
      the passphrase cached from an earlier session).
- [ ] Merge `feat/gateway-rest-and-red-team` into `main` and **redeploy** — prod is still running
      `a4f78d2`, i.e. none of the last two sessions' work is live.

**Then verify what is currently unproven**

- [ ] Prod smoke test once #1 is fixed: a plain AI Gateway send, then a Dynamic Route send with
      `tier=free` (isolates routing from third-party billing) before `tier=pro`. Confirm the reply
      reports the *route's* model + blue `ROUTE` badge, not the Model picker's value.
- [ ] Confirm custom metadata actually lands in the gateway logs — outstanding for two sessions now.
- [ ] **Run the red-team corpus on prod.** Local dev has no `cf-ray`, so verdicts never resolve and
      nothing is scored — only the runner mechanics are exercised locally. The real test is whether
      the Brand-Tarnishing / Political rows come back `reached the model`, reproducing the scan's
      finding; then add the Self-criticism custom topic and re-run to prove the gap closed. That
      before/after is the entire point of the feature.
- [ ] Set WAF block-rule responses to Custom JSON (dashboard).

**Improvements**

- [x] ~~Port the anchored-verdict-window fix to `export.ts`~~ — done (bug #7).
- [x] ~~De-duplicate the gateway-setting caps~~ — done via `/api/models` `limits` (bug #8).
- [x] ~~Add server-side `OFFSET` paging to `/api/prompt-log`~~ — done, with sort and search (bug #9).
- [ ] **Add `Zone → WAF → Read` to `CF_ANALYTICS_TOKEN`** so the live rule list actually engages —
      the code ships and falls back cleanly, but `/api/zone-rules` returns 403 here today, so the
      flow trace still runs on the static mirror (Open bug #12).
- [ ] Map upstream AI Gateway auth failures (HTTP 401/403, `code 10000`) to an actionable message
      instead of dumping the raw Cloudflare error JSON into the chat bubble — directly relevant now
      that bug #1 can surface on every gateway send, not just Dynamic Routes.
- [ ] Extend tests to the remaining pure functions (extractReply/stripThink, sanitizeHistory,
      buildHistory, cost calc). The SSE line parser is now covered (`src/sse.test.ts`).
- [ ] Add the **Self-criticism** custom topic to the zone (block) — the scan's single largest gap
      (53 successful attacks) has no rule covering it at all.
- [ ] Compliance page: GRC reviewer to sanity-check subcategory titles + section descriptions before
      regulated-customer use.

**Done this session (2026-08-01)** — Red Team page: curated 36-attack Prisma AIRS corpus, 3-phase
runner, scorecard, route selector, 15 scoring tests · analytics honesty pass (truncation-aware
counts, tile rates + prev-window trend, LLM-vs-other rule split, readable injection histogram,
drill-through to the prompt log) · chart rework (light-mode CVD fix, measured fixed height with
non-scaling text, table view, keyboard parity, endpoint labels) · prompt-log pagination · ray shown
while a verdict is pending · `sr-only` page-scroll bug fixed · full-width pages · 15 new tests
(49→64) · confirmed Guardrails blocking on prod (closed Open bug #3) · committed the previous
session's backlog in two reviewable commits · **README rewritten against the code** (removed
`/api/extract` docs, binding-based gateway path, wrong model list; added Red Team, prompt log,
gateway analytics, `CF_AIG_TOKEN`, the real 10-rule zone table).

**Done 2026-07-31** — AI Gateway REST migration (uniform per-request settings + validation) ·
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
