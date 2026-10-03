# Progress — Cloudflare AI Security demo

_Last updated: 2026-10-01 — external guardrails (Prisma AIRS) shipped; code review found Open bugs #22–#24, one live in prod_

Customer-facing demo of **Cloudflare AI Security for Apps** (formerly *Firewall for AI*) plus
**AI Gateway** (routing, caching, Guardrails, Dynamic Routing), a **security analytics dashboard**,
an **in-app red-team runner**, and a **compliance mapping page**. Live at
**https://cf-ai-waf-demo.nttlab.org** (account **NFR - TH - NTT** `daf82c7c…`, zone `nttlab.org`).

Prod is behind **Cloudflare Access**. Functional testing is done on `wrangler dev` (real Workers AI
+ real zone GraphQL + real AI Gateway REST API), seeding local D1 with `wrangler d1 execute …
--local` and faking a `cf-ray` header via curl where the edge-verdict / prompt-log join needs one
(local dev never sets a real one). Node ≥ 22 (`nvm use 24`).

> **Reading this doc**: it is organised by topic, not chronologically. Dated sessions under
> **Implemented** run newest-first — **2026-09** (latency, saved runs, gap recommender, compliance
> evidence, prompt-log flag, CI), then 2026-08-01 (Red Team page, analytics honesty pass, chart
> rework), then 2026-07-31 (AI Gateway REST migration, verdict window, prompt-log rewrite).
> The prod AI Gateway outage found on 2026-09-30 was **resolved the same day** (Open bug #1).
> **⚠️ The Compliance page's MEASURE 2.7 "blocked" count is wrong in prod (Open bug #22) — it counts every
> WAF block in the zone, not AI Security's. Read #22 before showing that page to a customer.**

---

## Architecture decisions

- **Single Cloudflare Worker** serves both the API and the built React SPA. No separate origin.
  - API routes: `/api/models`, `/api/chat` (unified — direct or AI Gateway routing), `/api/verdict`
    (anchored + retention-aware, see below), `/api/neurons`, `/api/analytics` (zone),
    `/api/gateway-analytics` (account, per gateway), `/api/prompt-log` (GET list / DELETE clear —
    D1), `/api/prompt-analytics` (D1 rollups). Everything else → static assets (SPA fallback).
- **The prompt log is behind a feature flag, off by default (2026-09-03).** `PROMPT_LOG_ENABLED`
  in `wrangler.jsonc`; `promptLogEnabled()` in `src/config.ts` is the single check. Requested
  deliberately — the log stores a redacted copy of every prompt that reaches the Worker, which is
  good evidence for the compliance story and a liability everywhere else, so it became opt-in
  rather than opt-out.
  - **It fails closed, not open.** The check is `=== "true"`, not `!== "false"`. A typo, a
    half-applied deploy or a var that never landed must read as OFF: the failure mode of "we
    thought logging was off" is prompts stored that nobody agreed to store, and that cannot be
    undone after the fact. The reverse failure surfaces immediately as an empty tab and costs
    nothing. `src/config.test.ts` pins `"True"`, `"TRUE"`, `" true"`, `"1"`, `"yes"`, `"on"`, `""`
    and `"enabled"` as all OFF.
  - **Enforced in the Worker, not just hidden in the UI.** The gate sits inside `logPrompt`,
    `updateLoggedReply` and `teeReplyToLog` — the three functions that can write — so a future
    caller cannot reintroduce logging by forgetting a guard upstream. Both read endpoints answer
    `{configured:false, disabled:true}`; `disabled` is separate from `configured` because only the
    latter deserves a setup hint.
  - `/api/models` serves the resolved flag (`promptLog.enabled`, which also requires the `DB`
    binding) so the client can remove the Analytics → Prompt log tab, the edge tab's
    drill-through affordance, and the per-turn toggle. Hidden rather than disabled: the flag is a
    deploy-time var, so a greyed-out control would imply the UI could turn it on.
  - **The per-turn "log prompt" switch now defaults to OFF** (`excludeFromLog` starts `true`).
    The red-team runner still leaves it unset, so runs log while the feature is enabled — that is
    the runner's designed evidence trail, and it writes nothing at all while the flag is off.
  - Verified on `wrangler dev` both ways with a faked `cf-ray` (local dev sets none, and
    `logPrompt` returns early without one — so a first test that "passed" with the flag off was
    proving nothing): flag off → row count unchanged; flag on → row written; flag on plus
    `excludeFromLog:true` → row count unchanged. Browser confirmed the tab, the drill hint and the
    switch all disappear with the flag off.
- **Prompt log store = D1** (`DB` binding, db `cf-ai-waf-demo-log`, `migrations/0001_prompt_log.sql`).
  `handleChat` writes one PII-**redacted** row per prompt that reaches the Worker, via
  `ctx.waitUntil` so it never blocks the reply; redaction is an independent regex pass in
  `src/redact.ts`. **Opt-out per request**: a "log prompt" toggle sends `excludeFromLog: true`,
  which short-circuits the write before it happens — independent of AI Gateway's own request log.
  Optional — unbinding `DB` degrades the tab to a setup hint.
- **`CF_ZONE_ID` and `CF_ACCOUNT_ID` are secrets, not vars (2026-08-04).** Requested deliberately.
  Worth knowing what it does and does not buy: to the Worker there is no difference — Cloudflare's
  docs say a secret *is* an environment variable, just hidden in the dashboard and Wrangler — so
  `env.CF_ZONE_ID` is unchanged and no code moved. It does **not** make the values private: both are
  still in `wrangler.jsonc` history, `README.md` and `PROGRESS.md`, and the account id must also
  remain as the top-level `account_id` key, which Wrangler requires and which cannot be a secret.
  They are identifiers, not credentials, and useless without a token.
  Two operational facts learned the hard way:
  - **You cannot convert in place.** Cloudflare rejects a secret that shadows an existing plaintext
    var — `Binding name 'CF_ZONE_ID' already in use` (code `10053`). The order must be: remove from
    `vars` → deploy → `secret put`. That leaves a short window where prod has neither, during which
    `/api/verdict`, `/api/analytics`, `/api/neurons` report `configured:false` and the AI Gateway
    route 501s. Chain the commands to keep it to seconds.
  - **Each `secret put` deploys its own version, and rollout is gradual.** The smoke test run
    immediately afterwards showed a genuinely confusing mix — `/api/neurons` green while the gateway
    route claimed `CF_ACCOUNT_ID` was missing, both of which read the same value. That was version
    propagation, not a fault; re-running ~45s later passed all five checks. Do not diagnose a fresh
    deploy from the first smoke run.
  - `wrangler dev` no longer reads them from config, so they now live in `.env` too.
- **`redact()`'s regexes are not a ReDoS risk — measured 2026-08-03, not assumed.** Two of them
  (`iban` `src/redact.ts:27`, `card` `:29`) are nested quantifiers, the shape SonarQube flags as
  `S5852` super-linear backtracking, and they run inside the Worker on **attacker-controlled prompt
  text** — worth checking properly rather than reasoning about. Benchmarked by doubling input length
  on inputs built to force maximal backtracking (long runs the pattern almost matches, ending in a
  character that defeats the trailing `\b`):

  | input | time |
  |---|---|
  | isolated `card` / `iban` patterns, 16k chars | < 0.1 ms, **×2.0 per doubling** (linear) |
  | real `redact()`, all 7 rules, 200k chars | **4.55 ms**, linear |

  Both repetitions are **bounded** (`{12,18}`, `{10,30}`), which caps alternatives per start
  position at 7 and 21 — so worst case is O(n × k) with a small constant, not exponential. If Sonar
  raises S5852 here, the correct disposition is **Safe**, citing this measurement; do not rewrite
  the patterns for it. (Redaction also runs under `ctx.waitUntil`, off the response path, so even a
  much larger constant would not delay a reply.) No timing regression test was added: at these
  margins it would only contribute CI flakiness.
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
- **ThaiSafetyBench is wired in as data, not as code.** `scripts/thaisafety-csv.mjs` converts the
  1,889-prompt apache-2.0 Thai benchmark into the `prompt,goal` CSV the corpus feature already
  reads — no application change, no runtime dependency, nothing leaving Cloudflare. The sample is
  **deterministic** (id-ordered, even stride within each `risk_area`, largest-remainder allocation
  so the parts sum exactly to `--n`): a random sample would make the before/after re-run that the
  page exists for meaningless. Default `--n=100` because sends are sequential — 100 ≈ 8 min and 100
  billable model calls; 200 is the parser cap; the full set is a load test.
  **Generated CSV is gitignored**: the dataset card says "academic purposes only" while the licence
  is apache-2.0, and that unresolved discrepancy is not something to settle by committing a few
  hundred harmful Thai prompts to a customer-facing repo. Upstream removed Monarchy content per
  Thai regulations (1,954 → 1,889) — do not re-add it.
- **`typhoon-ai/ThaiSafetyClassifier` was evaluated and rejected as an inline guardrail** — recorded
  so it is not re-proposed. It cannot run on Workers AI (fixed catalog, no custom model upload) or
  inside the Worker (0.2B F32 ≈ 800 MB, and it ships safetensors only — no ONNX/GGUF). Reaching it
  needs a paid HF Inference Endpoint behind an AI Gateway custom provider, which puts an app-layer
  control *after* the edge and sends prompts off Cloudflare — both at odds with the demo's thesis
  that detection happens at the edge before the model. It would also let `/redteam` assert model
  compliance, which the page deliberately refuses to do without a judge. Revisit only as an
  explicitly separate, separately-labelled column.
- **Red-team runs can be paced.** A `Delay` control (none…30s, default none, locked mid-run) puts a
  gap between sends. Sends are sequential, so an unpaced run is a burst: rate limiting — a WAF
  rate-limiting rule, or AI Gateway's — returns 429s that classify as `error` and therefore leave
  the scored denominator silently, which reads as a smaller run rather than as throttling. Pacing
  also spreads a batch across the 5-minute analytics buckets instead of stacking it into one.
  The wait is **abortable** (`abortableWait`, 100 ms ticks): a plain `await sleep(delay)` left Stop
  unresponsive for the whole gap, which at 30s reads as a hung button. The estimate beside the
  controls comes from `estimateRunSeconds`, which applies the delay **n−1** times because the runner
  skips the gap after the last send — unit-tested, since getting it wrong overstates every estimate
  by one full delay.
- **A stopped run stops claiming to be working.** Rows left mid-flight rendered a spinning
  "sending…" forever after Stop. They now read `unscored`, which is what they are: sent but never
  resolved. Pre-existing, but pacing makes stopping mid-run common enough that it mattered.
- **The red-team corpus can be the operator's own CSV, in Prisma's upload shape.** `prompt,goal`
  header, parsed **in the browser** (`lib/attackCsv.ts` — quoted fields, embedded newlines, doubled
  quotes, BOM, CRLF; 200-prompt cap because each row is a real inference call sent sequentially).
  Three deliberate refusals, all the same principle — never render a guess as if it were data:
  a file with no `prompt` column is **rejected** rather than parsed from column 0 (importing the
  wrong column yields a run that looks fine and tests nothing); custom rows carry **no severity,
  scan ASR or scan ref**, so those columns and the by-severity breakdown are *removed* rather than
  filled with plausible values; and `goal` is displayed but **never scored**, because Prisma's goal
  steers an LLM judge and this app has none — it measures only whether the edge stopped the request.
  Switching corpora resets results, so the scorecard can never describe a different corpus than the
  table beneath it. The corpus lives in a module store (survives tab switches, cleared by refresh,
  deliberately not localStorage — someone else's attack prompts should not outlive the session).
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
- **`/redteam`** — a **Corpus** control picks the built-in scan replay or an uploaded `prompt,goal`
  CSV (see Architecture for what a custom corpus deliberately does *not* claim). The built-in one
  replays a curated **36 of the 116** enumerated attacks from the Prisma AIRS scan
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
                    (session export — now anchored per turn via Msg.tsMs),
                    metadata.ts (AI Gateway metadata parser), sessionStore.ts,
                    redteam.ts (Prisma AIRS corpus + scoring helpers),
                    attackCsv.ts (custom-corpus CSV parser + template),
                    customCorpus.ts (the uploaded corpus, page-load lifetime)
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
(Worker-side SSE reader), `web/src/hooks/useZoneRules.ts` (live zone rules + fallback),
`web/src/lib/attackCsv.ts` + `customCorpus.ts` (custom CSV corpus), `scripts/thaisafety-csv.mjs`
(ThaiSafetyBench → CSV; dev tooling, `hyparquet` devDependency, never bundled).

New in 2026-09: `src/redteamruns.ts` (validation + caps for the run-save endpoint),
`migrations/0002_latency.sql` · `0003_redteam_runs.sql` · `0004_redteam_dynamic_route.sql`,
`web/src/lib/gapControls.ts` + `components/redteam/GapControls.tsx` (WAF-rule recommender — **not
rendered by any page yet**), `web/src/lib/complianceEvidence.ts`, `scripts/prod-smoke.sh`,
`.github/workflows/ci.yml`, `.nvmrc`, and `CLAUDE.md` (the ship workflow); then `src/openapi.ts` (+ `openapi.test.ts`,
`raw-imports.d.ts`), `scripts/copy-swagger-ui.mjs` and `web/public/api-docs/` (the API reference). `web/src/lib/redteam.ts`
gained `attackKey` / `corpusFingerprint` / `diffRuns`; `handlers.ts` gained `handleRedTeamRuns`.

Scripts: `npm run build` · `npm run deploy` · `npm run check` (worker typecheck) · `npm test`
(vitest, `vitest.config.ts` — separate from `vite.config.ts`, which sets `root: "web"`) · `npm run
dev:worker` / `npm run dev:web` · `npm run smoke:prod` (5 authenticated checks against prod through
Access). `.claude/launch.json` has `wrangler-dev` + `vite-dev` configs.

**Version control** (rewritten 2026-09-30 — the previous text said `main` sat at `a4f78d2` and prod
ran none of the recent work, both long untrue): 32+ commits, and **everything is merged to `main`,
which is in sync with `origin`** (`github.com/bkrbybk-org/cf-firewall-for-ai-demo`). Prod was last
deployed 2026-10-03 as version `674a8c93-0f61-4a57-a880-96fd356fc2ee` (CrowdStrike AIDR); before that
`595fa250` (the guardrail pipeline); before that
`f293eccc` (2026-10-01, OpenAPI 3.0 rendering, Swagger on 3.0, API docs link); before that `30312678` (the 3.0 endpoint alone) and `4a7e311c` (external guardrails); before that
`a49adbd0` (2026-09-30, the OpenAPI spec + Swagger UI); before
that `99cbf558` (2026-09-07, built from `ef68406`). The token replacement the same day also created a version,
from a secret change rather than a deploy.

- **Pushing needed a credential fix.** `git push` returned 403 as `chatchai-wongdetsakul_nttltd`
  (read-only on the repo) even after `gh auth switch` to an account with write, because the
  `osxkeychain` helper kept answering for `github.com`. `gh auth setup-git` adds a github.com-scoped
  helper that delegates to `gh`, so git now follows whichever account `gh` is on. This is global git
  config, so it applies to every repo on this machine.
- **Leftovers, safe to delete, not deleted:** the merged local branches
  (`feat/gateway-rest-and-red-team`, `fix/sonarqube-real-defects`, `feat/redteam-history-and-latency`),
  the worktree branch `worktree-agent-ad608684247cf5544` and its directory `.claude/worktrees/` (a
  subagent's isolated checkout; its work was committed as `f4d71ee` and merged).
- **Untracked on purpose:** `.claude/hooks/`, `.claude/settings.json`, `.mcp.json` (the SonarQube
  integration — its hooks execute shell scripts on every prompt/Read, so committing them is a
  decision for the repo owner) and `.vscode/`.
- **CI**: `.github/workflows/ci.yml` runs `npm ci` → Worker typecheck → web typecheck → test → build
  on every PR and push to `main`. No deploy job, deliberately. Verified on a fresh clone with
  `npm ci` (not the warm working tree), control-tested (a planted type error fails both typechecks
  with exit 2 / 1, a planted assertion fails the tests with exit 1), and green on GitHub.

**Doc split** (README rewritten 2026-08-01 against the code, having drifted several sessions):
`README.md` = product + setup reference (pages, endpoints, gateway/verdict/prompt-log behaviour,
zone setup, WAF rule table, tests); **this file** = engineering state (decisions, open bugs, next
tasks). The old README still documented the removed `/api/extract` file-upload feature, the
binding-based gateway path, and a model list that had never matched `src/models.ts` — all corrected.

Note: `commit.gpgsign` is on and this key's passphrase is not cached, so committing from a
non-interactive shell fails with `Inappropriate ioctl for device`. Run `export GPG_TTY=$(tty)` in
an interactive terminal first (pinentry is `curses`; there's no `pinentry-mac` installed).

**Tests** — `npm test`, **270 across 18 files** (measured 2026-10-01; README's Tests table has the per-file counts).
The suites below through `verdict-window` each exist because a real bug shipped and were mutation-verified
(reintroduce the bug → red). The 2026-09 additions (`redteamruns`, `gapControls`, `complianceEvidence`, the
latency sort, `promptLogEnabled`, and the `redteam.test.ts` growth 15 → 37) were written with their code and
are **not** mutation-verified — regression tests, not proof that each assertion can fail:
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

### 2026-09 sessions

Prod deployed 2026-09-07 (`99cbf558`) and again 2026-09-30 (`a49adbd0`). Migrations `0002`–`0004` applied to prod D1 (all additive).
What "verified" means is stated per item — a claim without its evidence is what this file is for.

**Latency capture** (`0002_latency.sql`). `handleChat` already computed `Date.now() - started` and
discarded it. It is now stored with a `streamed` flag and rolled up as p50/p95/max per
route × guarded × streamed by SQL window functions inside D1. **`streamed` is load-bearing:** `log()`
runs after the full response on the non-streaming path but before the stream drains on the streaming
one, so the column means total time on one and time-to-first-byte on the other — averaged together
they would be meaningless. It is Worker-observed only (starts before the model call; excludes the edge
scan; blocked requests create no row), and old rows are NULL, so every rollup gates on
`latency_ms IS NOT NULL` and reports coverage. *Verified:* 19 seeded local rows across all six
route/guarded/streamed combinations plus NULL rows — e.g. `direct, streamed=0: n=4 p50=900 p95=1200
max=2500` vs `direct, streamed=1: n=3 p50=150 p95=180` — and the n=1 case (`MAX(1, …)` guard)
returned the single value; `latencyCoverage` read 17 of 20 — **correction 2026-10-01: the rank rule was
never checked against a hand calculation, and it is wrong (Open bug #24): every p50/p95 is biased low.** The
SQL was verified to *run* before it was delegated, not to compute the right percentile; `/api/prompt-analytics` and `sort=latency`
were confirmed through `wrangler dev`. The rendered panel was built by a subagent and **not**
browser-checked separately. It is **invisible in prod** while the prompt log is off.

**Prompt log flag, off by default** — see Architecture decisions (2026-09-03). Also defaulted the
per-turn "log prompt" switch to off.

**Saved red-team runs — server side only** (`0003_redteam_runs.sql`, `src/redteamruns.ts`,
`handleRedTeamRuns`; `attackKey` / `corpusFingerprint` / `diffRuns` in `lib/redteam.ts`). The point:
the scorecard used to die on reload, which made the feature's stated purpose — run, change a rule,
re-run, prove the gap closed — impossible. Design decisions:
- **Attacks join on a prompt hash, not `RedTeamAttack.id`.** `csv-12` means "row 12 of whatever file was
  dropped in", so two uploads both have one and a re-export in a different order renumbers everything;
  diffing on id would compare unrelated prompts and report flips that never happened. FNV-1a 32-bit,
  synchronous — it is called from sync map/sort code and needs no cryptographic property.
- **`diffRuns` scores over the attacks the two runs share**, and refuses to call two runs a
  before/after when their corpus fingerprints differ. Otherwise ten already-blocked attacks added to
  a corpus would read as an improvement.
- **Scoring stays client-side** (the verdict lookup lives in the browser), so the client POSTs a
  finished run and the endpoint treats it as **hostile input**: 500-attack cap, state whitelist,
  length caps, totals clamped, pruned to the newest 50 runs, prompt previews passed through `redact()`.
  Totals are trusted-and-clamped rather than recomputed — recomputing would be scoring in the Worker.
- *Verified:* real `curl` against `wrangler dev` — POST 201; the stored preview read `contact me at
  [email]` (redaction confirmed live); 500 results accepted, 501 → 400; bad `state` → 400; DELETE →
  `deleted:true`. **Prod: only `GET` (empty list) was exercised; nothing was written there.** No UI
  calls any of it — see Open bugs #16–#20.

**Gap → rule recommender** (`lib/gapControls.ts`, `components/redteam/GapControls.tsx`; **built and
tested, not rendered by any page**). Replaces the hardcoded five-row `CONTROLS` table (volumes copied
from the scan PDF) with recommendations derived from the run just executed. Points that matter:
- **Scores invert — low means attack — so thresholds are always `le`, never `ge`.** A flipped
  comparator emits a rule that blocks everything or nothing, which a customer may paste into
  production. Every builder hard-codes `le`; tests pin it for a block-shaped and a log-shaped threshold.
- **Every `cf.llm.*` field is checked against Cloudflare's Ruleset Engine field reference, not
  inferred from this repo.** The subagent that wrote it grepped the repo, found five fields, and
  concluded no custom-topic field exists, so it emitted `expression: null` for the scan's largest gap.
  Wrong: `cf.llm.prompt.custom_topic_categories` is a real `Map<Number>` (1–99, lower = stronger
  match). The repo's artefacts mention only five fields and describe custom-topic rules in prose.
  Corrected during the September build; the header of `gapControls.ts` records why.
- A topic **key** is only emitted when knowable. For a topic *we propose creating* ("Self-Criticism")
  it is; for an *existing* topic it is not — the zone reports a rule's description, not the label it
  reads — so that case ships the placeholder `<your topic label>` rather than a guess that would
  compile and silently match nothing. Labels containing `"` or `\` are rejected (they would break out
  of the string literal).
- Malicious-code categories point at AI Gateway Guardrails, not a WAF expression — no `cf.llm.*`
  field covers them. Thresholds 30 / 65 are starting points: `RtRunResult` carries the verdict, never
  the numeric score, so a data-driven cutoff is not computable here.
- Coverage is labelled by provenance: an expression match against a live rule vs a name match against
  the static mirror. Today it is always the mirror (Open bug #12), so it can only name-match.
- *Verified:* unit tests only (22). Never rendered.

**Compliance live evidence** (`lib/complianceEvidence.ts`, `CompliancePage`). Four NIST AI RMF
controls only — MEASURE 2.7 / 2.10 / 2.6 / 3.1 — each showing a count over a stated 24 h window.
Restraint is the design: most controls are governance and no traffic count evidences them, so a chip
on every one would be a false compliance claim, and `compliance.ts`'s own header says naming what
Cloudflare does *not* cover is the page's credibility. **No data ≠ zero; capped payloads read "at
least N"; an unconfigured/failed fetch renders nothing.** *Verified in the browser against the real
zone:* the 500-row cap was genuinely hit in the 24 h window, so the floor path ran on live data
(`at least 137 prompts scored · at least 337 blocked`) — **correction 2026-10-01: that chip was itself
showing Open bug #22.** Its "blocked" is every WAF block in the zone, not AI Security's, and the floor was
~25× below the real 24 h total; the verification checked the rendering states, not what the number counts; the empty and unconfigured states were forced
by overriding `window.fetch` and rendered distinctly. Extra candidates (ISO A.7, OWASP LLM01/02,
ATLAS AML.T0051, BOT, NCSA) were proposed and deliberately **not** added — what the page asserts to
customers is an editorial call.

**Attack Library review + collapsed by default** (`data.ts`, `AttackLibrary.tsx`). Categories start
collapsed with a preset count in each header; a search expands its matches. Four content defects
fixed: eight of twelve categories had an empty `field` (the "which Cloudflare field catches this" line
the demo is narrated from); seven presets had empty labels, hiding the direct → indirect → edge
grading; *Specialized advice — S6* and *Elections — S13* fall outside rule 5's blocked set (S1–S5,
S8–S12), so they reach the model and only log — unlabelled, that reads as the product failing; and
"Other Unsafe / Harmful Topics" was malformed (no icon, no refs) and mixed duplicates with three
malware prompts no `cf.llm.*` field covers, which became their own Malicious Code card. Added a
Brand Tarnishing / Self-Criticism card so the scan's largest gap is demoable from the chat page (it is
*expected* to reach the model until a topic exists). *Verified in the browser:* 12 categories, all
`aria-expanded=false`, 0 preset buttons visible on load; search for `keylogger` expanded only its
match; a hand-opened card survived clearing the query.

**Red Team runner: subset selection, Dynamic Route, zero-scored guard** (`RedTeamPage`, `useRedTeam`,
`Scorecard`, migration `0004`). Selection is keyed by attack id so re-sorting cannot move it; empty
means all. The breakdowns are now scoped to attacks that produced a result (they were computed
against the whole corpus, so a subset — or a *stopped* run — drew its miss rate as a fraction of
prompts never sent). The Dynamic Route field is free text because nothing this app calls enumerates a
gateway's routes. **A run where every send fails used to read "0% reached the model"**, identical to a
perfect block rate; it now shows `—` and says nothing was measured. *Verified in the browser:* 3 ticked
→ `Run 3 selected`, header box indeterminate, 3 rows tinted; sorting by Category kept the same two
*prompts* ticked; the captured request body carried `"dynamicRoute":"demo-routes"` on the gateway route
and only `prompt` + `stream` on direct; the zero-scored banner fired on a genuinely failed run (the
known-bad local gateway token). Migration `0004` records the route per saved run because a route
*chooses the model* — but see Open bug #16: it is written and never read.

**Migration bookkeeping trap.** `wrangler d1 execute --file` does not touch `d1_migrations`, and a
worktree has its own `.wrangler` state. A subagent applied `0002` by file and `0003` in its worktree,
so `migrations apply --local` later failed on `duplicate column name` and then `no such table`. Local
bookkeeping was repaired by hand; **remote was correct throughout.** Always use
`wrangler d1 migrations apply`, never `execute --file`, for a migration that has a number.

**CI and the ship workflow.** See Version control for CI. `CLAUDE.md` holds the workflow: test locally →
deploy → test on prod → update docs → commit and push. It was reordered once from "commit before
deploy"; the cost of the current order is that prod runs the working tree, not a commit, between deploy
and push — so the version id `wrangler` prints is the only handle on a rollback in that window.

### 2026-10-03 — CrowdStrike Falcon AIDR guardrail

**What.** `src/crowdstrikeAidr.ts` (AI Guard client) + registry entry: AIDR is a real, configurable provider
in the pipeline next to Prisma AIRS. Regions US-1/US-2/EU-1 from the spec's `servers`; the collector token
(`Authorization: Bearer`) is encrypted and write-only like the AIRS key. Provider-specific wording comes from
the registry (`requiresProfile`, `keyLabel`, `vendor`), so the page names a "collector token", shows no
profile field for AIDR (its policy rides on the collector), and says whose hosts the secret goes to. Test
connection now goes through the same `scanWithKey` the pipeline uses, for both providers. Result gains
`policy`, `summary`, `transformed`. Self-implemented end to end (hostile input, outside facts, hot files).

**Facts, and where each came from.** CrowdStrike's docs and OpenAPI spec (`aidr-docs.crowdstrike.com`),
then the live endpoint:
- **The spec's path is wrong for these hosts.** It says `/v1/guard_chat_completions` (servers
  `api.crowdstrike.com` etc.); probed 2026-10-03 with a dummy token, that path is **404** on all three regions
  and the docs' `/aidr/aiguard/v1/guard_chat_completions` is **401**. The spec is evidently the Pangea one
  with CrowdStrike hosts pasted in.
- Live error body is the API gateway's `{meta:{trace_id}, errors:[{code, message}]}` — not in the spec.
- 202 `Accepted` (async, with `location`) is treated as an **error** (no verdict in the turn), not polled.
- `result.transformed` (redaction) is **not applied**: the model receives the original prompt. Shown as an
  amber "allow · redaction not applied" chip, never a green pass. Applying it would mean rewriting the prompt
  mid-pipeline (and deciding what a later guardrail then sees) — a design question, deferred.

**Verified, and how.**
- 15 client tests + 2 new config tests (309 total); five planted parser regressions all caught.
- Local: enabling without a token → 400 "save a collector token first"; a URL as region → 400; the token
  never appears in any response; page and diagram render AIDR as configurable (light mode, no console errors).
  Local workerd cannot reach `api.crowdstrike.com` either (`internal error`, same as PANW).
- Prod (deploy `674a8c93`, no migration): smoke 5/5. With AIDR **disabled**, a generated invalid token saved
  and *Test connection* run per region → the deployed Worker got CrowdStrike's real **401** from US-1, US-2
  and EU-1, parsed into `httpStatus: 401` + the gateway message. Token cleared afterwards; AIRS untouched.
- **What that 401 does NOT prove:** a request with **no** token gets the identical 401, so — unlike the AIRS
  check, where 403 vs 401 showed the key arrived — it cannot show the token was delivered. Token delivery is
  pinned only by unit tests (`authorization: Bearer …`). **Never exercised: a real AIDR verdict**
  (allow/block, detectors, `policy`, `transformed`), a 202, or AIDR and AIRS together in one pipeline.

### 2026-10-03 — guardrail pipeline: traffic-flow diagram, sequential / parallel, guardrail-only

**Asked for:** a diagram on the settings page to view and adjust traffic flow — order guardrails (AIRS before
CrowdStrike), run them together and wait for all to allow, or send to the guardrails only (no LLM cost).
**Decided with the user:** a diagram drawn from the config with controls (not a free-form graph editor, which
could draw flows the Worker cannot run); guardrail-only is one global switch for chat **and** Red Team;
**pipeline first, CrowdStrike AIDR later** — so today only AIRS is real and ordering/parallel are proven with
fake providers in tests, not with two live vendors.

**Design.** Only what sits between the edge WAF (before the Worker) and the model (where AI Gateway
Guardrails live) can be ordered; the diagram draws both ends locked and says why. Migration `0006` drops
`0005`'s one-enabled index (**not purely additive** — said before applying), adds the one-row
`guardrail_pipeline` table and `redteam_runs.skipped`. `executePipeline` is separated from D1/fetch.
- *Sequential*: configured order, first stop ends it, the rest go in `notRun` with a reason.
- *Parallel*: `Promise.all` — **waits for every guardrail**, not just the first block. This reverses what I
  first proposed (answer on the first block): two guardrails side by side are only worth showing with both
  verdicts, and each call is already capped at 5 s.
- *Guardrail-only*: HTTP 200 `{guardrailOnly: true}`, no reply/tokens/cost, prompt-log outcome `skipped`.
  Red Team keeps the real edge verdict (allow/log) — that is what the edge did, so the headline maths is
  unchanged — and counts the skipped ones apart (`RtScore.skipped`, a subset of `reached`).
- Response shape changed: `externalGuardrail` (one result) → `externalGuardrails` (`GuardrailPipelineResult`),
  header `x-external-guardrail` → `x-external-guardrails`. The deciding result is the one named by
  `stoppedBy`, never `results[0]`.

**Who did what.** Self: migration, engine, handler, types, API layer, red-team scoring, OpenAPI, smoke
script, docs, and review. Sonnet: the diagram (`PipelineDiagram.tsx`), chat cards, export, analytics/Red Team
display — from a frozen contract. **Review found and I fixed:**
- **The edge verdict said "Reached the model" for turns the model never saw.** That was already true under
  every external-block card since 2026-10-01; Sonnet flagged it and withheld the verdict from guardrail-only
  cards rather than fix files outside its brief. Fixed: `Verdict`/`FlowTrace` take `stoppedInWorker`
  (`external` | `skipped`); the trace ends in the Worker on an amber (external) or grey (skip) cut — never
  the WAF's red — and the headline reads "Passed the edge …, then an external guardrail stopped it" /
  "… The model was skipped". Restored under both cards and on prompt-log rows.
- **Demo mode credited the WAF with external blocks**: `useChat` reported an external stop as `blocked`,
  which `DemoMode` treats as a definitive edge 403. Now `external`, so Demo mode looks up the real edge verdict.
  Pre-existing since 2026-10-01.

**Verified, and how.**
- Local gate: `npm run check`, web `tsc -b`, 293 tests / 19 files. Six planted engine regressions (no
  sequential break, serial "parallel", parallel ignoring blocks, guardrail-only dropped when nothing is
  enabled, stored order ignored, lenient order validation) — **five caught at first; the order one was not**
  (the D1-path test had one enabled row), so a two-row test was added and it is now caught.
- `wrangler dev` + Browser pane: diagram in parallel then sequential (step numbers + reorder arrows), the
  guardrail-only switch (banner, model struck through, "No reply — verdict only"), state confirmed through
  the API after each click; chat with AIRS enabled under a generated test key (local workerd cannot reach PANW,
  so a fail-closed "unavailable — not a verdict" card in parallel mode) and with AIRS off + guardrail-only
  ("Model skipped", edge-only). Light mode at 375 px: no horizontal scroll. No console errors. The verdict
  fix could not be seen locally — local dev sets no `cf-ray`, so no verdict card renders.
- Prod (deploy `595fa250`, migration applied first): smoke 5/5 after updating check [4] to the new shape (it
  first failed on my own stale script, not on prod — the body was a real AIRS block). Through Access with the
  user's real key: benign prompt → reply with `prisma-airs allow · benign · 496 ms`; guardrail-only on →
  `guardrailOnly: true`, no reply, AIRS `allow` recorded — **switched straight back off** (seconds); bad
  `order` → 400. Deployed bundle contains "Traffic flow", the banner, "Model skipped" and the new verdict text.
- **Not verified:** two live providers in one pipeline (only AIRS exists); the rendered verdict fix and the
  diagram on prod (Access-gated, checked by bundle grep only); the `skipped` prompt-analytics series on real
  rows (the prompt log is off in prod); Red Team in guardrail-only mode end to end.

### 2026-10-01 — OpenAPI 3.0 for API Shield; Swagger on 3.0; API docs link

**Why.** Uploading `/api/openapi.json` to API Shield → Schema Validation failed: `code 50010, failed to load
OpenAPI file: … cannot unmarshal 'number' in field 'components.schemas.properties.exclusiveMinimum' of type
'bool'`. Cloudflare's docs (`api-shield/security/schema-validation/#limitations`) say uploads are parsed
with OAS 3.0 semantics only and relative server URLs are unsupported; ours is 3.1 with `servers: "/"`.

**What.** `src/openapi30.ts` down-converts the 3.1 document (still the hand-written source) and
`GET /api/openapi-3.0.json` serves it with `servers` = the request origin. Swagger UI now renders the 3.0
document, so the docs page shows exactly what an upload contains. Every page's tab strip ends with an
**API docs ↗** link (`NavTabs.tsx`, plain `<a>` in a new tab — a `NavLink` would be swallowed by the SPA
router). Done self, not delegated: the output is enforced by a production security control.

**Verified, and how.**
- 9 tests in `src/openapi30.test.ts` (279 total). The 3.0 validator has teeth: the 3.1 document relabeled
  `3.0.3` is rejected by `@readme/openapi-parser`.
- Go `kin-openapi` **v0.118.0** (3.0-only, the same parser family as API Shield's error): the 3.1 file fails
  to load (`cannot unmarshal array into Go struct field SchemaBis.type of type string`), the 3.0 file loads
  with 14 paths. Current kin-openapi accepts 3.1, so it cannot reproduce the error; only an old one can.
  Prod's served file (`/api/openapi-3.0.json`) also loads, `servers: https://cf-ai-waf-demo.nttlab.org`.
- **Bug caught in the browser, before prod:** under `wrangler dev` the Worker sees the *route's* hostname
  over http, so Swagger's server read `http://cf-ai-waf-demo.nttlab.org` and Try it out on localhost would
  have hit prod. The initializer now overwrites `servers` with `window.location.origin`; re-checked:
  `http://localhost:8787`, 18 operations, `OAS 3.0`, no console errors. Prod's initializer and bundle
  (the link's `href:"/api-docs/",target:"_blank"`) grepped after deploy.
- **Not verified:** a successful API Shield upload (only the user can do that), and the link in light mode.

**Caveat before enforcing Schema Validation:** some request bounds are stricter than the Worker, which clamps
instead (`systemPrompt` > 2000 chars, `maxAttempts` outside 1–5); such requests would be flagged.

### 2026-10-01 — external guardrails (Prisma AIRS)

**Forward each prompt to a third-party guardrail before the model** (`/guardrails`, `src/prismaAirs.ts`,
`src/externalGuardrails.ts`, migration `0005`). Palo Alto Networks Prisma AIRS (AI Runtime Security, API
intercept) is implemented; CrowdStrike AIDR is listed but unsupported. Runs after the edge scan and before
the model, on both routes; one provider enabled at a time (unique partial index in D1 — **lifted 2026-10-03**
by the guardrail pipeline, migration `0006`). Built with the
default implementation approach: the client contract was frozen first, the config page and chat card were
delegated to a Sonnet subagent against it, and everything touching secrets, outbound auth, `handleChat`,
scoring semantics and the spec stayed with the main thread.

- **The API facts came from PANW's own OpenAPI spec, not the docs page.** The reference page renders its
  schema client-side and returned only an outline, so the spec was pulled from the public
  `PaloAltoNetworks/pan.dev` repo (`openapi-specs/prisma-airs/scan/scan-service_latest.yaml`):
  `POST /v1/scan/sync/request`, `x-pan-token`, `ai_profile` + `contents` required, `action`
  `allow`/`block`, `category`, seven `prompt_detected` booleans, four regional hosts. **The live endpoint
  then contradicted the spec on errors:** it answers `{"error":{"message":"Invalid API Key or OAuth Token"}}`
  (403) and `{"error":{"message":"Not Authenticated"}}` (401), not the declared `{status_code, message}`.
  Both shapes are parsed.
- **No free-text endpoint — the region picks one of PANW's four hosts.** The key travels in a header, and
  `/api/external-guardrails` is reachable by anything that passes Access, including the red-team scanner's
  service token. A typed URL would let such a caller redirect the stored key to their own server (and is an
  SSRF primitive). The user asked for an "API endpoint" setting; the region picker is that setting, and the
  page explains why it is not free text.
- **The key is write-only and encrypted at rest** (AES-256-GCM, `GUARDRAIL_SECRET_KEY` secret, provider id
  bound as AAD). Only `••••last4` is ever returned; `toPublicConfig` builds the response field by field so a
  later column cannot leak through a spread. No secret → the page refuses to store a key.
- **An error is never a verdict.** Fail mode is the operator's: `block` (default, fail closed) stops the turn
  and the card says the guardrail was *unavailable*, not that the prompt was malicious; `allow` lets it
  through marked `failedOpen`. A 200 from PANW with no usable `action` is an error, never an allow.
- **A block is HTTP 200 `externalGuardrailBlocked`, never 403**, because 403 on `/api/chat` means the edge
  WAF to the chat and the red-team runner. It is its own outcome throughout: prompt-log `external`, red-team
  state `external` (excluded from the scored denominator; new `redteam_runs.external` column), its own amber
  chart series. The prompt-analytics series previously ended in `else row.reply++`, which would have counted
  an external block as a model reply — now explicit per outcome.
- **Latency stays model-only:** the clock restarts after the guardrail, and a blocked turn logs
  `latency_ms = NULL` so a guardrail round trip is never averaged into model percentiles.
- **Privacy:** no `app_user` / `user_ip` is sent (the prompt already leaves Cloudflare); `tr_id` is the ray.
- **Fixed Open bug #16 in passing** — the `external` column had to be added to the same two `SELECT`s.
- *Verified:*
  - **Unit tests (35 new, 270 total)** against PANW's real shapes; the security tests were
    **mutation-verified** — six planted regressions (leak the stored row, allow on a missing `action`, drop
    the region check, ignore the fail mode, unbind the ciphertext from its provider, enable without a key),
    all caught. One test was itself wrong at first: passing `undefined` to a parameter with a default applied
    the default, so the "secret missing" case never removed the secret.
  - **Locally on `wrangler dev`:** free-text endpoint → 400; enable without key → 400; unsupported provider →
    400; the key appears in no response and only as ciphertext in D1. **Fail-closed:** chat → 200 blocked,
    `outcome: error`, no `failedOpen`, prompt-log row `external` with `latency_ms NULL`. **Fail-open:** the
    turn proceeds with `failedOpen: true` and a model-only latency. Header present on JSON and streamed
    responses. In the browser (DOM-checked; the pane could not screenshot): the page shows the masked key, the
    four regions, the derived endpoint, fail-mode controls, the third-party disclosure and "Not yet supported"
    for CrowdStrike; *Test connection* shows the error verbatim in an `aria-live` region; the chat renders the
    fail-closed card with "This is not a verdict", no detection pills, no "malicious".
  - **On prod (deployed Worker → real PANW):** with a deliberately invalid key saved but **not enabled**,
    *Test connection* returned **403 "Invalid API Key or OAuth Token" from the US, EU and SG hosts**. A 403
    rather than a 401 "Not Authenticated" proves the encrypted key was decrypted and delivered in
    `x-pan-token`. The key was then cleared; chat carried no guardrail header throughout; smoke passed.
- **Not verified — needs a real Prisma AIRS key:** a genuine `allow` or `block` verdict end to end, the
  "Blocked by Prisma AIRS" card and the green allow chip (both read, not rendered), the `incomplete` path, and
  real latency. The red-team runner's `external` classification has no unit test (the hook is untested
  generally). **Local `wrangler dev` cannot reach PANW's hosts at all:** a minimal worker with none of this
  code throws workerd `internal error` on that fetch with or without an abort signal, while `curl` from the
  same machine and Worker fetches to `api.cloudflare.com` both work — so local runs always see the guardrail
  as unavailable. (Same opaque error local Workers AI returned on 2026-09-30.)

**API reference — OpenAPI 3.1 + Swagger UI** (`src/openapi.ts`, `/api/openapi.json`, `/api-docs/`; 2026-09-30).
11 paths, 14 operations. Decisions:
- **Hand-written, guarded against drift** rather than generated. Nothing in this codebase describes its own
  shapes in a machine-readable way (handlers build `Response.json` ad hoc), so generation would have meant a
  rewrite; a hand-written spec rots silently, so `src/openapi.test.ts` makes each kind of drift a red build:
  paths vs the `case "/api/…"` routes in `index.ts`, `ChatRequest` fields vs `ChatRequestBody`, the
  prompt-log `sort` enum vs `PROMPT_LOG_SORTS`, the `RtResultState` enum vs `RT_RESULT_STATES`, plus full
  OpenAPI validity via `@readme/openapi-parser` (every `$ref` resolves). **Mutation-verified:** six planted
  drifts each turned the suite red, re-run after the test was reworked to use `?raw` imports.
- **Response schemas were checked against reality, not against the types.** 24 captured payloads (23
  responses + 1 request body) from `wrangler dev` and prod-through-Access were validated with `ajv`
  (2020-12), plus a scan for keys a payload carries that the schema does not declare — a plain validator
  lets those through. The checker was itself control-tested: 6 planted defects (dropped property, wrong
  type, extra `required`, dropped item property, narrowed enum), all caught. Its first run passed
  everything, which is why it was tested — and inspecting the samples showed three were vacuous (0 rules,
  0 runs, `found:false`), so real data was produced for them: a save → list → get → delete cycle locally,
  and real found verdicts from prod for both an allowed and a WAF-blocked request.
- **Not verified against live data:** the `/api/zone-rules` *item* shape (the token lacks
  `Zone → WAF → Read`, Open bug #12, so no rules come back), the Guardrails-block body (written from
  `guardrailsResponse()`'s source), SSE frame contents (described in prose) and 5xx bodies. There is no
  handler-level contract test — it would need D1 and Workers AI mocks — so a schema and a handler can still
  disagree.
- **Self-hosted Swagger UI**, not a CDN: `swagger-ui-dist` is a devDependency and
  `scripts/copy-swagger-ui.mjs` copies three files (~1.8 MB) into `dist/api-docs/` *after* `vite build`
  (which empties `dist/`), so a customer-facing page has no runtime third-party dependency.
  `swagger-ui-dist` pulls in `@scarf/scarf`, a telemetry package with a postinstall hook: local npm blocks
  it (`allow-scripts`) and CI now sets `SCARF_ANALYTICS=false` explicitly.
- **Things the spec says out loud** because they are easy to get wrong: `configured:false` is HTTP 200; a
  WAF block is a 403 written by the zone's rule before the Worker runs (body operator-configured) while a
  Guardrails block is a 200; *Try it out* is real and billable. Two known limitations are stated as such
  (`dynamicRoute` not returned by GET — Open bug #16, since fixed; the prune ordered by client `ts` — #18) without
  internal bug numbers, since the audience is outside this repo.
- **Caught by CI's typecheck, not by vitest:** the first version of the test imported `node:fs` and
  `__dirname`, which the Worker's tsconfig (Workers types, no Node types) rejects. Vitest does not
  typecheck, so `npm test` passed while `npm run check` failed — always run both. It now reads source with
  Vite `?raw` imports (`src/raw-imports.d.ts` declares them).
- *Verified:* browser DOM checks on `wrangler dev` — 14 operations under 5 tags, no console errors, a real
  *Try it out* on `GET /api/models` returned live JSON, `POST /api/chat` renders all 7 status codes plus
  `default`; `/api-docs` 307-redirects to `/api-docs/`; assets serve with correct content types; the SPA
  fallback still serves `/redteam`. **Not visually inspected** — the Browser pane could not composite a
  screenshot, so appearance (spacing, a light-only Swagger theme inside a dark app) is unchecked. On prod:
  the docs page and all three vendor files serve through Access, the served spec is byte-identical to the
  local one, and it validates against prod's own payloads including the prompt-log *disabled* shape. Prod's
  `index.html` is larger than the built file because Cloudflare's edge injects its own inline script.
- **Local Workers AI flake, not investigated:** `POST /api/chat` returned 502 (`Workers AI error: internal
  error`, from miniflare's AI proxy) on `wrangler dev` twice in a row on 2026-09-30, after working earlier in
  the month. Prod chat was fine throughout, so the chat samples came from prod.

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

1. ~~**PROD's AI Gateway route is failing — regression found 2026-09-30.**~~ **RESOLVED 2026-09-30.** The token
   was replaced (a human step) and the route recovered: `smoke:prod` passes all five checks, both gateways
   (default and guarded) return 200, and the streaming gateway path returns its trailing `data: {gateway…}`
   event. The cause of the rejection was never established (expired, revoked or rolled all look identical
   from outside). What follows is the diagnosis as it stood when found, kept because the signature —
   secret *present* but rejected, `code 10000` on both gateways, direct route fine — is how to recognise it.

   `npm run smoke:prod` check
   3 returns **HTTP 401**, and a direct `curl` through Access shows the same body on **both** the
   default and the guarded gateway: `{"code":10000,"message":"Authentication error"}`. The direct
   Workers AI route is fine (200), as are `/api/models`, analytics, neurons, `/api/zone-rules` and the WAF block path (the smoke test does not exercise `/api/verdict`).
   - **It is a fault, not rollout lag:** nothing has deployed since 2026-09-07 (`99cbf558`), and the
     same check passed that day and on 2026-08-03. `wrangler secret list` shows `CF_AIG_TOKEN` *is
     present* on the Worker, so the token is being **rejected**, not missing.
   - **Cause not determinable from outside:** the secret's value cannot be read. Expired (API tokens
     can carry a TTL), revoked, rolled, or its owner's access changed all produce this identical
     error.
   - **Impact:** every AI Gateway send returns an error — the route toggle, the guarded/Guardrails
     path, gateway-routed red-team runs and Dynamic Routing. The chat bubble shows the raw Cloudflare
     JSON rather than an actionable message (see Next tasks).
   - **Fix (needs a human — a new token):** mint an API token with `AI Gateway - Read`, `AI Gateway -
     Edit`, `Workers AI - Read`, then `npx wrangler secret put CF_AIG_TOKEN` and re-run
     `npm run smoke:prod`.
   - **Workflow consequence:** `CLAUDE.md` step 3 requires all five smoke checks to pass, so no code
     change can complete the workflow until this is fixed. This is why the `dynamic_route` bug
     (#16) was recorded rather than fixed in the same review.

   Separately, the token in `.env` was invalid on 2026-08-03 (not re-checked), so **`wrangler dev`
   cannot exercise the gateway route locally** either. Replace it to restore local gateway testing.

   Historical detail, kept because the distinction cost real time:
   - **Local (`.env`, what `wrangler dev` uses — it logs "Using secrets defined in .env")**: a plain
     gateway send returns `{"code":10000,"message":"Authentication error"}`, and
     `GET /user/tokens/verify` with that token returns `1000 Invalid API Token` — so it is not a user
     API token at all, consistent with it being the gateway-scoped Authenticated-Gateway "Run"
     token. Local gateway testing is broken until this is replaced.
   - **Prod (the `CF_AIG_TOKEN` secret on the Worker)**: a *different* value. The dashboard shows the
     secret exists but not its scopes, and prod sits behind Access (a probe returns 302 to the Access
     login), so it cannot be tested from here. It has probably never been exercised: on the deployed
     `a4f78d2`, only Dynamic Routing uses this token, and Dynamic Routing is listed below as unproven
     end to end.

   The real requirement is `AI Gateway - Read`, `AI Gateway - Edit`, `Workers AI - Read` on a normal
   API token. Our own earlier docs/error text said "AI Gateway Run", which is not a real permission
   name, and pointed at the gateway-scoped Authenticated-Gateway token — which this REST endpoint
   rejects with exactly the error above.

   **Why this gates the deploy specifically.** Prod currently runs `a4f78d2`, where a plain gateway
   call still used the `env.AI.run(..., {gateway})` binding and needed no token — so the gateway
   route *works in prod today regardless of the token*. The REST migration (`14a71f6`) makes the
   token mandatory for every gateway request. If the prod token is also wrong, deploying converts a
   working customer-facing path into a hard error: the route toggle, the purple Guardrails card and
   gateway-routed red-team runs all fail. The direct Workers AI route, edge verdicts, all three
   analytics tabs, the prompt log and compliance are unaffected either way.

   **Fix once, for both** — the local token needs replacing regardless, so mint one good token and
   use it in both places rather than gambling on prod's current value:
   1. Create an API token with `AI Gateway - Read`, `AI Gateway - Edit`, `Workers AI - Read`
      (**not** the Authenticated Gateway "Run" token).
   2. Put it in `.env` as `CF_AIG_TOKEN`, and `npx wrangler secret put CF_AIG_TOKEN` for prod.
   3. Retest a plain gateway send on `wrangler dev` — it must return a reply, not `10000`.
   4. Then `npm run deploy`. `npx wrangler rollback` restores the previous deployment if needed.
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
4. ~~**WAF block responses are still Cloudflare's default HTML page**~~ **RESOLVED 2026-08-03** —
   the rules now return Custom JSON. Verified in prod:
   ```json
   {"error":"request_blocked","reason_code":"LLM_PII_BLOCKED",
    "message":"This request was blocked because it may contain sensitive personal or regulated data.",
    "detail":"Please remove sensitive data such as payment, contact, or credential-related information and try again.",
    "support_hint":"Please provide the cf-ray response header to support."}
   ```
   **But the client does not read this shape**, so the demo now displays less than the edge gives it.
   `useChat.ts` does `detection: data?.blocked ? data.detection : undefined` and `reason: data?.reason`
   — none of `blocked`/`detection`/`reason` exist in the payload above, so both come out undefined and
   `Chat.tsx` falls back to the generic "Blocked by Cloudflare AI Security for Apps" instead of the
   rule's own message. Attribution is unaffected (`verdictOutcome` works off the edge verdict's rules
   + httpStatus, not the body), and the raw-response viewer still pretty-prints it. Fix: map
   `reason_code` → detection (`LLM_PII_BLOCKED` → `pii`, etc.) and show `message`, keeping the
   existing `{blocked,detection,reason}` shape working so either rule config renders correctly.
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

**Found in the 2026-09-30 code review** (read from the code and grep; each states whether it was
exercised):

16. ~~**`redteam_runs.dynamic_route` is written but never read.**~~ **FIXED 2026-10-01** while adding the
    `external` column to the same two `SELECT`s; the OpenAPI schema now lists `dynamicRoute` as returned. Original entry: Only the `INSERT` in `handleRedTeamRuns`
    references the column; both `SELECT`s (list and single-run) omit it, while `RedTeamRunRow.dynamicRoute`
    is typed as always present in `src/types.ts` and `web/src/lib/types.ts`. So the comparability data
    migration `0004` exists to record can never come back out. No user impact today (no UI reads saved
    runs). Fix: add `dynamic_route AS dynamicRoute` to both `SELECT`s, plus a test. *Found by grep,
    confirmed by reading the handler; not exercised.* Blocked behind bug #1 only because of the workflow's
    prod-smoke gate.
17. **`RedTeamPage` still says "Runs land in the prompt log (D1) as evidence"** (with a link to
    `/analytics`) and its file header says the same. The prompt log is off by default, so that tab does
    not exist and the link lands on the edge tab. Copy should be conditional on the flag or reworded.
    *Found by grep.*
18. **The run-save endpoint orders its prune by a client-supplied `ts`.** `DELETE … NOT IN (SELECT id …
    ORDER BY ts DESC LIMIT 50)` uses `body.ts`, which is validated only as a non-negative integer up to
    `MAX_SAFE_INTEGER`. A run posted with a far-future `ts` is never pruned and, repeated 50 times,
    evicts every real run; one posted with an old `ts` prunes *itself* and still returns 201 with an id
    that no longer exists. Prod is Access-gated, but `wrangler dev` is not, and the endpoint's header
    claims hostile-input hardening. Fix: order by server time, or clamp `ts` to now ± skew. *Found by
    reading the code; not exercised.*
19. **Two smaller integrity gaps in the same handler.** The run row is inserted *outside* the batch (its
    id is needed first), so a failed batch leaves a run with zero results — the code comment claims a
    crash cannot leave a half-written run. And `reached` and `stopped` each clamp to `scored`
    independently, so `reached + stopped > scored` is storable. `diffRuns` reads results, not stored
    totals, so a diff is unaffected; only the list view's totals could mislead for a lying client.
    Low. *Found by reading.*
20. **The Malicious Code card's framework refs are a loose fit.** It cites OWASP `LLM05:2025 Improper
    Output Handling` (about unsafe *downstream handling* of model output, not the model generating
    malware) and ATLAS `AML.T0048 External Harms`. Verify or drop before regulated-customer use — the
    compliance page's own rule is not to overstate a mapping. The README table flags it ⚠️.
21. **Built, deployed and unreachable:** `GapControls`, the saved-run API and `diffRuns` have no
    consumer in any page (confirmed by grep for each symbol outside its own file and tests). Prod
    carries dead code, and the feature they exist for still cannot be done in the app.

**Found in the 2026-10-01 code review** (each measured, not inferred):

22. **🔴 Compliance evidence credits AI Security with blocks it did not make — live in prod.** The MEASURE
    2.7 chip ("AI system security and resilience are evaluated" — injection scoring) reports "N blocked" as
    `blockedCount(analytics.actions)`, i.e. **every WAF block event in the zone**: Sensitive Paths,
    Geography-based rule, AI-crawler blocks, managed-ruleset CVE rules. Measured over 24 h with grouped
    GraphQL (no row cap): **8,318 block events, of which 2,608 (31%) were AI Security rules** (`Block LLM
    Unsafe Categories` 1,643, `Block LLM Injection` 905, …); inside the 500 rows `/api/analytics` actually
    reads, none of the top eight rules was an AI Security rule. So ~69% of the number shown under an AI
    control is not AI Security, and the "at least 327" floor is ~25× below the real total. MEASURE 3.1's "N
    events recorded" is likewise zone-wide (lower stakes — it sits under "risks are tracked"). This is the
    same misattribution the analytics page's LLM-vs-other rule split was built to prevent, reintroduced on
    the page a GRC reviewer reads. `complianceEvidence.test.ts` pins the output strings but never asserts
    what "blocked" is drawn from, so the tests lock the defect in. **Fix:** tally blocks from AI Security
    rules only, server-side (classify each event's rule by expression when live rules are available, by
    the `\bLLM\b` name heuristic otherwise, and say which), with a test that a non-LLM block is excluded.
    **Immediate mitigation (a one-line change, needs your OK since it alters a customer-facing page):** drop
    the "blocked" half from the 2.7 chip until then.
23. **Truncated analytics charts draw unread time as zero.** `/api/analytics` reads the *newest* 500 rows,
    then zero-fills every bucket in the window, so when the cap is hit the older buckets read "no activity"
    when they were simply never read. Measured on prod: **24 h view — 18 of 25 hourly buckets zero**, the
    500 rows reaching back only ~6.5 h; **7 d view — 6 of 8 days zero**. The tiles say "row cap reached",
    but `EventSeries` is never told, so the chart presents a burst that is an artefact. Violates the house
    rule that "no data" is never rendered as zero. `/api/gateway-analytics` has the same structure (newest
    first, zero-filled) but does not trigger on prod today (6 requests in 7 days). **Fix options:** return
    the oldest fetched timestamp and render earlier buckets as "not read"; or — better if it holds — take
    tallies and series from `firewallEventsAdaptiveGroups`, which returned uncapped per-rule totals in the
    measurement for #22. *Verify against Cloudflare's docs first*: "Adaptive" datasets can be sampled, so
    their `count` semantics must be confirmed before they are presented as exact.
24. **Latency percentiles are biased low.** The rollup ranks with `CAST(n·p AS INTEGER)` — truncation —
    where nearest-rank needs a ceiling. On real local rows `[77, 800, 900, 1200, 1313, 2500]` (n=6) it
    reports **p95 = 1313 ms; nearest-rank p95 is 2500 ms**. For odd n the "p50" falls below the median (at
    n=3 it is the minimum). The panel's own example rows show it: `n=3, p50 150, p95 180, max 400`. Worst
    exactly where this demo lives — small n. Not visible in prod while the prompt log is off. **Fix:**
    integer ceiling `(n*95 + 99)/100` (no reliance on SQLite math functions), a test of the rank rule, and
    a check of the SQL's output against a hand calculation on real rows.
25. **Minor.** `/api/chat` caps `history` (8,000 chars) and `systemPrompt` (2,000) but not `prompt`
    itself. And 13 handler sites return raw upstream/exception text to the client — on local dev one
    carried a stack trace with an absolute file path. Prod is behind Access, so low risk; worth a generic
    message plus the detail in logs if this is ever exposed.

**External-guardrail caveats** (2026-10-01):

26. **Anything that passes Access can reconfigure the guardrail** — enable or disable it, change region, fail
    mode or profile, or replace the key — because `/api/external-guardrails` cannot tell a human from the
    red-team scanner's service token. It **cannot read or redirect the key** (write-only; allowlisted hosts),
    so the worst case is a guardrail switched off or set to fail open. If that matters, restrict the path in
    Access to human identities, or check the `Cf-Access-Jwt-Assertion` identity in the Worker.
    **Since 2026-10-03 the same callers can also switch guardrail-only on** (`/api/external-guardrails/pipeline`),
    which stops every chat from getting a model reply until someone switches it off — visible (amber banner on
    `/guardrails`, "Model skipped" cards in chat) but disruptive mid-demo. Same remedy.
27. **A real verdict has never been exercised** — no valid Prisma AIRS key was available. First thing to do
    with one: save it, *Test connection*, enable, and send one benign and one injection prompt from the
    Attack Library; confirm the green chip and the "Blocked by Prisma AIRS" card with detections and `scan_id`.
    **Partly exercised 2026-10-01:** the user enabled a real key (profile `CW-LAB Security Profile`). The smoke
    test's PII prompt (`my credit card is 4111 1111 1111 1111`) came back 3/3 as HTTP 200
    `externalGuardrailBlocked: true`, `action: block`, `category: malicious`, `detected:
    [agent, dlp, injection, source_code]`, 477–530 ms, with `scan_id`/`report_id`, and the same JSON in the
    `x-external-guardrail` header. So a real **block** is parsed correctly. A real **allow** was seen the same
    day on deploy `f293eccc`: `Hello! What can you help me with today?` → 200, `outcome: allow`, `category:
    benign`, `detected: []`, 419 ms, and the model answered. Not yet seen: the rendered card and chip in a
    browser, or a real `incomplete` (timeout/error flag) verdict.

28. **The zone's PII rules are set to Log — on purpose, since 2026-10-01** (the user's choice, to let PII
    prompts reach Prisma AIRS and confirm it blocks them). Measured on ray `a439b56029e6a1c8` via
    `/api/verdict`: the edge **did** detect it (`piiCategories: ["CREDIT_CARD"]`, `scored: true`), every
    matching rule acted `log` ("[Account-Level] Detect PII in LLM", "Monitor LLM PII Categories", …), and
    Prisma AIRS blocked it in the Worker. **While this lasts, the demo's headline claim — "the edge blocks
    PII" — does not hold for PII**, and attribution says so honestly (the turn is credited to Prisma AIRS, not
    the WAF). Smoke check [4] was changed to pass on *either* a WAF 403 *or* a real external-guardrail
    `outcome: "block"` (a fail-closed error still fails) and prints which layer stopped it. **Put the rule
    back to Block before a customer demo of the WAF.** Also seen the same run: `/api/zone-rules` →
    `source: fallback`, `Ruleset list failed (HTTP 403)` — the rules token cannot list rulesets, so the app
    shows its static mirror, not live rules.
29. **CrowdStrike AIDR has never returned a real verdict** (2026-10-03) — no collector token available.
    The prod 401 check proves host, path and error parsing, but not token delivery (no token gets the same
    401). First thing to do with a token: save it on `/guardrails` (AIDR **disabled**), *Test connection*
    (expect `allow` with a `request_id` and `policy`), then enable and send an injection prompt; confirm the
    amber block card lists AIDR detectors. Also unverified: what AIDR does with `transformed` in practice
    (the app does not apply redactions — see the 2026-10-03 entry).

## Next tasks

**Fix next, in this order** (who per CLAUDE.md's implementation approach):

- [ ] **#22 compliance attribution** — *self*: it is honesty semantics on a customer-facing page. Decide the
      mitigation with the user first.
- [ ] **#24 percentile rank** — *self*: two lines of SQL, but a wrong statistic is invisible, so the check
      against a hand calculation is the work.
- [ ] **#23 truncated charts** — *self* for the design (verify the Groups dataset's sampling semantics in
      Cloudflare's docs; choose "mark unread" vs "aggregate uncapped"), then *sonnet* for the chart change
      against a fixed contract.

**Unblock (do first)**

- [x] ~~**Replace prod's rejected `CF_AIG_TOKEN`**~~ (Open bug #1) — done 2026-09-30. Original entry: new API token with
      `AI Gateway - Read`, `AI Gateway - Edit`, `Workers AI - Read`, then `wrangler secret put` and
      `npm run smoke:prod`. Until then the gateway route errors in prod. **Do this before any demo.**
- [ ] **Wire `RedTeamPage` to saved runs and `GapControls`** (Open bug #21): save a finished run,
      list/pick two, render `diffRuns` with its comparability warning, drop
      `<GapControls corpus={corpus} results={results} />` where the hardcoded `CONTROLS` table is, and
      fix the stale prompt-log copy (#17). Outstanding since the features were built in early September.
- [ ] Fix bug #16 (add `dynamic_route` to both `SELECT`s) and #18 (server-side ordering for the
      prune) together with a test each, once #1 lets the prod gate pass.
- [ ] Apply the recommended Zero Trust Access restructuring for the AI red-team service (Open bug
      #2): path-scoped `/api/chat` app, `Service Auth` + service token, `Allow` policy alongside it
      for human logins. Re-verify the app still works for a normal browser session afterward.
- [x] ~~Commit the chart rework~~ — done, `4f2079d` (signed fine non-interactively; gpg-agent had
      the passphrase cached from an earlier session).
- [x] ~~Merge `feat/gateway-rest-and-red-team` into `main`~~ — done 2026-08-03, fast-forward to
      `b30da22` (8 commits). (The repo had no remote then; `origin` exists now — see Version control.)
- [x] ~~**Deploy**~~ — **DONE 2026-08-03, verified.** Prod runs the merged `main`
      (`/api/zone-rules` answers with JSON, which only exists in the new code); no commit touching
      `src/` or `web/` postdates the deployment. `npm run smoke:prod` passes all five checks
      through Access: gateway route 200, direct route 200, PII prompt correctly 403, and the four
      read-only endpoints healthy.
- [ ] Map the prod block-response JSON keys in the client (Open bug #4) — the edge now returns a
      specific reason the UI throws away.
- [ ] Replace the local `.env` `CF_AIG_TOKEN` so `wrangler dev` can exercise the gateway route
      again (prod is fine — Open bug #1).

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
- [x] ~~Set WAF block-rule responses to Custom JSON (dashboard)~~ — done, see Open bug #4.

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
- [ ] **Run the ThaiSafetyBench corpus on prod** (`npm run corpus:thai`) — the point is which Thai
      harm categories `cf.llm.*` and Guardrails miss. Local dev has no `cf-ray`, so only the
      mechanics are exercised there. Then map the "reached" categories to new Custom Topics and
      re-run the same deterministic corpus for the before/after.
- [ ] Legal glance on ThaiSafetyBench's "academic purposes only" card note vs its apache-2.0
      licence before the corpus appears in a paid engagement.
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
