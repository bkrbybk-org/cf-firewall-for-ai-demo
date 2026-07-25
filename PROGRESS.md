# Progress — Cloudflare AI Security demo

_Last updated: 2026-07-21_

Customer-facing demo of **Cloudflare AI Security for Apps** (formerly *Firewall for AI*) plus
**AI Gateway** (routing, caching, Guardrails), a **security analytics dashboard**, and a
**compliance mapping page**. Live at **https://cf-ai-waf-demo.nttlab.org** (account
**NFR - TH - NTT** `daf82c7c…`, zone `nttlab.org`). Deployed version `951ae59c` (2026-07-21).

Prod is behind **Cloudflare Access**, so functional testing is done on `wrangler dev` (loads
`.env`, hits real Workers AI + real zone GraphQL + real AI Gateway REST API). Node ≥ 22
(`nvm use 24`).

---

## Architecture decisions

- **Single Cloudflare Worker** serves both the API and the built React SPA. No separate origin.
  - API routes: `/api/models`, `/api/chat` (unified — optional AI Gateway routing), `/api/verdict`,
    `/api/neurons`, `/api/analytics` (zone), `/api/gateway-analytics` (account, per gateway),
    `/api/prompt-log` (GET list / DELETE clear — D1), `/api/prompt-analytics` (D1 rollups).
    Everything else → static assets (SPA fallback).
- **Prompt log store = D1** (`DB` binding, db `cf-ai-waf-demo-log`, `migrations/0001_prompt_log.sql`).
  `handleChat` writes one PII-**redacted** row per prompt that reaches the Worker, via
  `ctx.waitUntil` so it never blocks the reply; redaction is an independent regex pass in
  `src/redact.ts` (Firewall for AI gives categories, not offsets, so it can't drive masking).
  Optional — unbinding `DB` degrades the tab to a setup hint.
- **Detection happens at the edge, not in app code.** AI Security scans the request body *before*
  the Worker runs; WAF custom rules block/log. The app generates traffic + reads back what the edge
  did via GraphQL Analytics. Fires only on the proxied zone hostname + `cf-llm`-labeled `/api/chat`.
- **One `/api/chat` endpoint, two routes.** Direct = `env.AI.run(model, inputs)`. Gateway =
  `env.AI.run(model, inputs, { gateway })`. Because the edge WAF scans the inbound request *before*
  the Worker chooses how to call the model, **the verdict applies to both routes** — the whole
  reason AI Gateway was merged in at the endpoint rather than kept as a second page.
- **LLM backend = Workers AI** (native `AI` binding). Model allowlist in `src/models.ts`
  (7 models incl. `llama-guard-3-8b`; default = **Gemma 4 26B**, `MODEL_REGISTRY[0]`).
  `MAX_REPLY_TOKENS = 2048`. Prices are served to the client so it can estimate streamed-reply cost.
- **Multi-turn keeps the top-level `prompt` field** (latest user message) so AI Security's body
  scan is unchanged; prior turns ride in `history[]`, server-revalidated (10 turns / 8k chars), and
  only completed user→assistant pairs are sent (blocked prompts never re-enter history).
- **Streaming = SSE passthrough.** `stream:true` → Worker returns the model's `text/event-stream`;
  client parses `data:` lines. For a **streaming gateway** call the Worker appends a trailing
  `data:{gateway:…}` event (cache/log id) via a `TransformStream` flush. Blocked requests come back
  as 403 HTML/JSON regardless — content-type decides the parse path.
- **AI Gateways are listed live from the account.** `/api/models` calls the AI Gateway REST API
  (`GET /accounts/{id}/ai-gateway/gateways`, needs `CF_ANALYTICS_TOKEN` with **AI Gateway Read**)
  and returns every gateway. Falls back to the two wrangler-var gateways if the token lacks the
  permission. Wrangler vars: `CF_AI_GATEWAY_ID = cf-ai-sec-demo-gw-no-guardrail` (default),
  `CF_AI_GATEWAY_GUARDED_ID = cf-ai-sec-demo-gw` (marked as the guarded one). The list API carries
  **no** per-gateway Guardrails flag, so the `guarded`/GUARDRAILS badge is derived from the var,
  not auto-detected. Guardrails blocks surface as binding errors 2016 (prompt) / 2017 (response) →
  `{guardrailsBlocked, direction}`.
- **Analytics aggregates in the Worker**: latest 500 raw rows per dataset (`firewallEventsAdaptive`
  + `httpRequestsAdaptive` filtered to `/api/chat`), tallied server-side into one payload.
- **One send pipeline** (`useChat` hook) drives both manual chat and the demo autopilot; shared
  verdict poller in `web/src/lib/verdict.ts` powers the Verdict chip and autopilot scoring. Chat
  session state lives in a **module-level store** (`lib/sessionStore.ts`) so it survives tab
  switches and is cleared by a full refresh (deliberately *not* localStorage/sessionStorage).
- Server-side allowlists for model + system prompt. Frontend: React 18 + Vite 6 + Tailwind v4 +
  lucide, light/dark via `data-theme`.

### Pages / layout

- **`/` — Firewall / chat** (nav-tab label is currently "AI Guardrails Demo"): System Prompt (left)
  · Chat (center) · Attack Library (right). Header (two rows): brand + **Run demo** (autopilot),
  theme, Neuron chip on top; nav tab strip below (Firewall · Analytics · Compliance, active
  underlined). Chat controls: model picker, **Workers AI ↔ AI Gateway toggle**, stream toggle, and
  — when gateway is on — a **Gateway dropdown** (all account gateways), skip-cache, TTL. File-upload
  buttons under the composer. `/gateway` redirects here (the old standalone page was removed).
- **`/analytics`**: three tabs (edge / AI Gateway / prompt log) sharing one range picker. Stat
  tiles, **line + area** events-over-time chart, top-fired-rules bars, injection-score histogram.
  Range 1h/24h/7d, 60s auto-refresh.
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
  config.ts         reply/history/upload limits, pricing + gateway constants
  cloudflare.ts     gqlFetch, queryVerdict, queryNeuronUsage, queryAnalytics, listAiGateways
  handlers.ts       one handler per endpoint; handleChat unifies direct + gateway routing;
                    extractReply/stripThink, sanitizeHistory, gateway registry helpers, handleExtract
web/src/
  lib/              data.ts (** demo content: CATEGORIES, PRESET_SYSTEM_PROMPTS, DEMO_SCRIPT,
                    ZONE_RULES, UNSAFE_TOPICS **), compliance.ts (** MATRIX + FRAMEWORKS **),
                    api.ts (fetch wrappers + SSE parser), types.ts, format.ts, icons.ts,
                    verdict.ts (classify + poller), export.ts (session export), sampleFiles.ts
                    (on-the-fly PDF/image builders), sessionStore.ts (module-level chat store)
  hooks/            useTheme, useNeurons, useChat (session + send pipeline)
  components/       Header, NavTabs, ThemeToggle, NeuronChip, SystemPromptPanel, AttackLibrary,
                    Chat, Verdict, FlowTrace, DemoMode, ExportButton
    analytics/      primitives (Tile/Card/BarList), EventSeries (line+area chart + series defs),
                    EdgeTab, GatewayTab, PromptLogTab
  pages/            FirewallPage (chat + route/gateway controls), AnalyticsPage (shell: state,
                    loaders, tab strip, filters), CompliancePage
```

Scripts: `npm run build` · `npm run deploy` · `npm run check` (worker typecheck) · `npm test`
(vitest, `vitest.config.ts` — separate from `vite.config.ts`, which sets `root: "web"` and would
otherwise hide the Worker's tests under `src/`) · `npm run dev:worker` / `npm run dev:web`.
`.claude/launch.json` has a `wrangler-dev` config.

**Version control**: `git init` done (branch `main`, initial commit `ed669b6`). `.gitignore`
covers `.env`, `.wrangler/`, `dist/`, `node_modules/`, `*.tsbuildinfo` — verified with
`git check-ignore` before the first commit, and the tracked set was secret-scanned.

**Tests**: `src/redact.test.ts` — 18 cases over the PII redaction pass, run against the *real*
Attack Library prompts from `web/src/lib/data.ts`. Assertions check the original identifier is
**absent** from the output rather than matching an exact replacement string, because the failure
mode that actually shipped was a *partial* mask (`card` ran before `iban` → `IBAN DE89 [card
****3000]`, leaking `DE89`). Verified by mutation: reintroducing that ordering makes 2 tests fail
with exactly that message. Also covers no-false-positives on clean prose and idempotency.

---

## Implemented (verified via `wrangler dev` against real Cloudflare unless noted)

**Chat core (`/`)**
- Model picker (7 models); per-reply metadata line: model · ray · tokens (in/out) · ~cost.
- **Multi-turn**: history sent + honored (model recalls a name across turns; prompt_tokens grow),
  turn counter, Clear conversation. **Toggle** (checkbox next to "stream replies", default **on**):
  when off, each prompt is sent standalone (`history` omitted from the request) so the model can't
  recall earlier turns — useful for showing multi-turn attacks (Crescendo) only build when the
  toggle is on. Turn counter label adapts: "N turns of context" (on) vs. "N turns in transcript
  (multi-turn off — not sent)" (off) — the transcript itself is never cleared, only what's sent.
  `useChat` cfg takes `multiTurn: boolean`; gates the `buildHistory()` call in `sendPrompt`.
- **Streaming** (toggle, default on): live token render with cursor; real SSE `usage` when emitted,
  else estimated (`~`); client-side cost from served prices.
- **Chat session persistence**: survives tab switches, cleared on refresh (module-level store, not
  web storage). Verified both halves; also fixed a latent in-flight-guard race across remounts.
- **Reasoning models**: `extractReply()` falls back to `message.reasoning` and strips
  `<think>…</think>`; `max_tokens` 512→2048. DeepSeek R1 returns clean prose.

**Edge verdict + flow trace** (redesigned — "timeline-native", the flow *is* the card)
- **Unified verdict card** per reply/blocked turn: filled action badge + a **plain-language outcome
  line** (`summaryLine()` in `Verdict.tsx`, e.g. "Reached the model — 3 log-only rules flagged it
  for analytics" / "Stopped at the gateway — prompt moderation (2016). The model never ran.") + ray.
  A Guardrails block shows a purple `GUARDRAILS · 2016/2017` badge instead of the edge action pill.
- **The flow trace IS the body — always shown, no toggle.** Every detection lives in its node, so
  nothing is repeated (the old design duplicated rules/injection/topics between the flow and the
  sections below). The **AI Security scan node** carries compact detection MiniChips (injection ·
  clean/attack, PII, unsafe topics) plus **custom-topic match bars**. Node tone: red if
  injection-attack/PII/unsafe, amber if only custom topics, green if clean.
- **Custom-topic scoring fixed**: the model's raw score is inverted (lower = stronger match), so the
  UI now shows **match strength = 100 − score** (higher = stronger), sorted strongest-first, and the
  bar width agrees with the number (the old bars used `100−score` width but printed the raw score, so
  a weak `76` had the *shortest* bar). `TopicBars` in `FlowTrace.tsx`.
- Removed `FlowToggle` and the old injection tile / rules-hit chips / PII·unsafe·custom sections from
  `Verdict.tsx`. Verified in `wrangler dev` (mocked verdict) across all three: LOGGED direct, ALLOWED
  gateway (with gateway node), and GUARDRAILS·2016 block.
- **Request-flow trace**: vertical trace User prompt → AI Security
  scan → WAF rules (matched vs the full `ZONE_RULES` list, misses dimmed behind an expander) →
  outcome (blocked: severed rail; allowed: Worker + Workers AI nodes). **AI Gateway-aware**: when
  the reply was routed via gateway, an **AI Gateway node** is inserted between Worker and Workers
  AI — cache HIT/MISS, latency, log id, GUARDRAILS badge — and the Worker line's `env.AI.run(...)`
  call reflects the `{ gateway }` third arg. `Verdict`/`FlowTrace` now take optional `gateway:
  GatewayMeta` + `guardrails: { direction, detail }` props threaded from the message in `Chat.tsx`.
  **Guardrails-block cases are now accurate** (previously the trace wrongly showed "Worker allowed →
  Workers AI generated the reply" even when Guardrails blocked): on a **2016 (prompt)** block the
  Worker node reads "edge allowed → routed via AI Gateway", followed by a purple "Blocked by AI
  Gateway Guardrails — 2016" node with a severed purple rail, then a dimmed "Workers AI — never
  reached" node; on a **2017 (response)** block the model node stays green ("generated a reply —
  returned through the gateway") and the purple block node terminates the trace ("response
  moderation withheld the reply"). The edge verdict badge stays LOGGED/ALLOWED — correct, since the
  edge WAF is a separate control from gateway Guardrails. Also fixed a latent Worker bug: the
  guardrails 2016/2017 response returned `gatewayId`/`guarded` **top-level**, but the client reads
  `data.gateway.*`, so the guarded flag was always `false` and the gateway id never surfaced — the
  Worker now nests them under `gateway` to match the reply-path shape (`src/handlers.ts`).
  Verified in `wrangler dev` with mocked `/api/chat` + `/api/verdict` (local dev has no real
  `cf-ray`): gateway-allowed, direct, and both guardrails-block directions all render correctly.

**AI Gateway (merged into the chat page)**
- Route **toggle** (Workers AI ↔ AI Gateway) + **gateway dropdown** listing all account gateways
  (live via AI Gateway REST API; var fallback). Gateway route adds a cache HIT/MISS badge, latency,
  log id; the `guarded` gateway shows a purple GUARDRAILS badge and its 2016/2017 blocks render a
  purple "Blocked by AI Gateway Guardrails" card — with the edge verdict still shown below it.
- Verified real Cloudflare: cache HIT on identical repeat (219ms vs 1059ms, $0); streaming trailing
  gateway event carries log id + latency; routing through an arbitrary account gateway works.
- Tradeoff (user chose full features on both routes): history/streaming change the request body so
  identical prompts rarely cache — a UI note says to clear + resend for a clean HIT.

**Demo autopilot**: 6-step scripted tour (baseline → injection → PII → unsafe S9 → unsafe S6
log-only → custom topic), clears the conversation on start, per-step expect-vs-actual with edge
verdict polling (blocked 403 counts immediately), Stop button, final scorecard. Panel is portaled
to `document.body` (the header's backdrop-blur was the fixed-position containing block — real bug).

**Attack Library / system prompts**: 13 preset personas + custom editor; searchable library with a
**Multi-turn Jailbreak (Crescendo)** category and **graded custom-topic tuning presets**
(direct/indirect/edge per topic) for threshold tuning. `ZONE_RULES` mirrors the zone's 10 WAF rules
(kept in sync with the dashboard; used by the flow trace).

**Session export** (JSON / Markdown): re-fetches each turn's verdict fresh at export time (single
lookup, not the live poll), bundles prompt/reply/verdict per turn.

**Visual prompt injection (file upload)**: two-stage — `POST /api/extract` (multipart, ≤1 MB,
**unscanned**) converts a PDF/image to text via `env.AI.toMarkdown()`; an extraction card shows the
result with "Load into prompt →" that routes it through the scanned `/api/chat`. Verified real API:
PDF white-on-white hidden text extracts in full; image path is captioning (not OCR) — a faint
hidden line was *noticed* in the caption but not transcribed. Samples built on the fly client-side,
no binary assets in the repo.

**Analytics page**: two tabs sharing one range picker (1h/24h/7d) + refresh + 60s auto-refresh.
- **AI Security (edge)** — zone-scoped. Tiles (events/blocked/logged/PII), events-over-time, top
  fired rules, injection-score histogram, plus per-category **detection breakdowns**:
  **unsafe topics** (labelled via `topicLabel()`, e.g. `S7 (Privacy)`), **PII categories**,
  **custom topic matches** (count + *avg match strength* = mean of `100 − score`, the same
  inversion the verdict card's `TopicBars` uses so both surfaces agree), and a **scan-coverage**
  readout (`labeledRequests / scannedRequests`) that surfaces the "endpoint not labeled `cf-llm`"
  misconfiguration in aggregate. All from fields `queryVerdict()` already proved available —
  `queryAnalytics()` now selects them too.
- **AI Gateway** — *account-scoped*, with a gateway dropdown (reuses the `gateways` list already
  served by `/api/models`). Tiles (requests · cache hit % · total cost · avg+p95 latency),
  hit/miss/error over time, requests-by-model (tokens + cost), status codes, token totals.
  Source is the **AI Gateway logs REST API** (`GET …/ai-gateway/gateways/{id}/logs`) — no GraphQL
  dataset exists for it; `per_page` caps at **50**, so the Worker pages up to 500 rows and sets
  `truncated`. Needs only the **AI Gateway Read** scope the gateway dropdown already required.
- Verified against real account data: the guarded gateway shows **22× HTTP 424** — Guardrails
  blocks surfacing in aggregate — alongside `llama-guard-3-8b` (the moderation model) in the
  by-model bars. An explicit in-page **Scope** card states gateway data is account-wide, unlike
  the zone-scoped edge tab. Empty + not-configured + error states verified on both tabs; light
  and dark checked; `EventSeries` generalized to take `rows`/`bucket`/`defs` so both tabs share it.
- **Charts are line + area** (was stacked columns), shared by all three tabs: 10%-opacity area
  wash for magnitude, 2px line for shape, markers only when the series is sparse (≤ 24 buckets),
  hairline gridlines on clean `1/2/5 × 10ⁿ` ticks, and a **crosshair + single tooltip** that reads
  out every series at the hovered bucket (value leads, label follows) so the pointer never has to
  land on a line. Series are drawn **unstacked**, each from its own zero baseline — stacking was
  tried first and is wrong for this data: it is sparse and zero-heavy, so a series sitting at 0
  inherits the cumulative height beneath it and paints a flat line across the top that reads as a
  constant nonzero value (the `error` line appeared pinned at 1 while errors were actually 0). The
  tooltip still reports the total, so nothing is lost. Tick values are deduped after rounding —
  with `max = 1` the fractional midpoint otherwise printed "1 / 1 / 0".
- **Prompt analytics** (top of the Prompt log tab) — rollups over the *whole* log, computed as SQL
  `GROUP BY` **inside D1** (not a Worker-side pass over capped rows, so numbers stay right as the
  table grows — the payoff of picking D1). Tiles (prompts logged · carried PII % · guardrails-blocked
  · via AI Gateway), prompts-over-time by outcome (reply/guardrails/error), by-model with tokens,
  route split, and **repeated prompts** (`GROUP BY prompt HAVING COUNT(*) > 1` — surfaces autopilot
  reruns and replayed attacks). `hours=0` = all time, span derived from the data itself. Rollups
  deliberately ignore the row filters (they describe the whole log, not the filtered view).
- **Prompt log** tab (D1) — PII-redacted prompts for further analysis, one row per prompt that
  **reached the Worker** (edge-blocked 403s never invoke the Worker → not here; see the edge tab).
  Route/outcome filters, expandable rows (redacted prompt + reply + the **live edge verdict joined
  by `cf-ray`** — reuses `<Verdict>`, so you see a prompt next to the detections that fired on it),
  a redaction-count chip, and a **Clear log** button (confirm → `DELETE /api/prompt-log`). An
  *About this log* card states redaction protects only this store — **AI Gateway still logs the raw
  prompt+response payload** (`collect-log-payload` defaults on; left on deliberately as a demo
  talking point). Redaction (`src/redact.ts`) unit-tested against the Attack Library's PII formats
  (card→`[card ****1111]`, email, IBAN, crypto wallet, IP, phone, Thai national ID); a clean prompt
  is untouched. Streamed replies aren't captured server-side (prompt logged, reply null — UI says
  so). **Caveat**: like verdict/autopilot, the chat→write path needs a real `cf-ray`, so local
  `wrangler dev` writes nothing; verified end-to-end by seeding local D1 + exercising the tab
  (render, redaction display, filters, expand+verdict-join, clear). Real-`cf-ray` write is a prod
  smoke-test item.

**Compliance page**: 6-framework coverage matrix + tabs with per-control detail cards, sorted
full → partial → supporting → out-of-scope. **Honesty is the point**: 4 graded coverage levels; all
10 OWASP items incl. the 4 Cloudflare doesn't address; banner clarifying Cloudflare supplies
technical controls, not certification. ISO 42001 is paid → top-level Annex A groups only; the two
Thai docs (BOT, NCSA) are Thai-language → section/phase refs paraphrased, never reproduced. Every
card cross-links to the demo that exercises it.

**Cross-cutting**: two-row header + shared `NavTabs`; light/dark verified on all pages; Worker
typecheck + build clean; deployed to prod.

---

## Open bugs / caveats

1. **Guardrails not confirmed *blocking* live.** The guarded gateway `cf-ai-sec-demo-gw` now exists
   and processes requests (no more error 2001), and the GUARDRAILS badge shows. But whether
   Guardrails moderation is actually enabled + blocking has **not** been verified with an unsafe
   prompt — need to send one and confirm a real 2016/2017 → purple card on prod.
2. **WAF block responses are still Cloudflare's default HTML page**, not Custom JSON — set each
   block rule's response to Custom JSON (bodies in README) so the blocked card pretty-prints.
3. **Account-level "Monitor Likely Attacks (Score GE 20 AND LE 50)" is a red herring** — fires on a
   non-LLM attack score despite the name; visible in the analytics top-rules list. Flag to whoever
   owns the account ruleset.
4. **Verdict/autopilot timing**: GraphQL ingests ~15–130s behind; a full 6-step autopilot run on
   prod can take minutes when log-only steps wait for both rows. Blocks resolve instantly. Local
   dev has no `cf-ray`, so verdict/autopilot show "pending" (by design; mock to preview the UI).
5. **`ZONE_RULES` is a hand-maintained mirror** of the dashboard rules — rename/add a WAF rule in
   the dashboard and the flow-trace matching drifts until `web/src/lib/data.ts` is updated.
6. **Analytics caps at latest 500 rows/dataset** per query — fine for a demo zone; noted in-page.

## Next tasks

- [ ] Confirm Guardrails actually blocks on prod (unsafe prompt via the guarded gateway → 2016/2017
      → purple card). If it isn't enabled, turn it on in dashboard → AI → AI Gateway → Guardrails.
- [ ] Set WAF block-rule responses to Custom JSON (dashboard).
- [ ] Prod smoke test after Access login: autopilot full run (expect 6/6), streaming + verdict on
      the prod hostname, analytics with fresh LLM-rule traffic, **and the Prompt log writing real
      `cf-ray` rows**. Prod (version `8a5a461a`, 2026-07-25) already carries the `DB` binding, so
      prompt-log works there; **prompt-analytics needs a redeploy** (added after that version).
- [ ] Extend tests to the remaining pure functions (extractReply/stripThink, sanitizeHistory,
      buildHistory, cost calc, verdict classify, SSE line parser). `redact()` is now covered.
- [x] Remove dead code left by the file-upload removal — `postExtract`/`ExtractResponse`,
      `MAX_UPLOAD_BYTES`/`ALLOWED_UPLOAD_MIME`/`DEFAULT_CACHE_TTL`, and the stale `cacheTtl` field
      on the client `ChatRequest` type. All gone; zero residual references.
- [x] Split `web/src/pages/AnalyticsPage.tsx` (was ~1,200 lines, 11 components) into
      `web/src/components/analytics/` — `primitives.tsx` (Tile/Card/BarList), `EventSeries.tsx`
      (chart + series defs), and one file per tab (`EdgeTab`/`GatewayTab`/`PromptLogTab`). The page
      is now a ~250-line shell: state, loaders, tab strip, filters. Pure move — the built JS bundle
      hashed identically before and after.
- [ ] Compliance page: GRC reviewer to sanity-check the NIST subcategory titles + ISO/BOT/NCSA
      section descriptions before regulated-customer use (defensible, but not an audited crosswalk).
- [ ] Optional: cache `/api/verdict` responses. `npm audit` reports 5 pre-existing advisories, all
      under `node_modules/wrangler`.

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
