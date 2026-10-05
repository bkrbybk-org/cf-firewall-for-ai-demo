# CLAUDE.md

Cloudflare AI Security for Apps demo — Worker (API + React SPA) on `cf-ai-waf-demo.nttlab.org`.

`PROGRESS.md` and `README.md` are the source of truth for architecture, open bugs and setup.
Read them before answering questions about how this app works.

## Default implementation approach

For any change bigger than a one-line edit, **draft a plan before touching code**, then implement
it, then run the workflow below. Delegation to subagents is authorised by default for the tasks
the plan marks delegable — no need to ask each time.

**The plan lists, per task:** what changes and which files; dependencies; who does it (**self**,
**sonnet** or **haiku**) and why; and how the result will be verified. Tasks that touch the same
file are serialised; only tasks with disjoint file sets run in parallel. Say which files are hot
(`src/handlers.ts`, `src/types.ts`, `web/src/lib/types.ts`, `RedTeamPage.tsx`) — those are edited
by one party at a time.

**Who takes a task** — decided by the cost of a wrong judgment, not by size:

- **Self** when a mistake would be costly *or invisible*: anything handling hostile input or
  producing text a customer will paste into production (WAF expressions); scoring and honesty
  semantics; design decisions with tradeoffs; edits to a hot file; deploys, credentials and
  anything on prod; facts about Cloudflare or a standard that must be checked against its own
  docs; writing the docs; and **reviewing whatever a subagent returns**.
- **Sonnet** when the semantics can be pinned in a brief and the work is a well-specified
  feature: multi-file implementation, components from a fixed props contract, test writing,
  mechanical-but-broad refactors. The brief states the non-negotiable semantics (with the *why*),
  the files it may and may not edit, "no formatter", "do not commit or deploy", and asks for real
  command output rather than "should work".
- **Haiku** when the task is mechanical, low-judgment and verifiable by a tool: inventories and
  greps, stale-string sweeps, applying an exact before/after edit, running a command and reporting
  its output. If writing the brief costs more than doing the edit, do the edit.

**Delegated work is a claim, not a result.** Re-run the gates yourself, grep the facts, and check
anything about the outside world against its source. A subagent once concluded a real Cloudflare
field did not exist because this repo never mentioned it; another applied a migration by file into
its own worktree so this checkout's database never got it. **Running is not correct:** a percentile query was checked to *run* before it was delegated, ranked with
truncation instead of a ceiling, and under-reported every p50/p95 for a month — check any computed number
against a hand calculation on real rows, and check what a count actually counts before labelling it.
Subagents leave their work uncommitted:
commit or merge it deliberately. Prefer disjoint files in the same tree over `isolation: worktree`,
whose separate `.wrangler` state has already caused one bug.

## Default workflow for any change

Run this end to end without being asked. **Each gate must pass before the next step** — a
failure stops the chain, and the fix comes before moving on.

1. **Test locally.**
   ```bash
   npm run check && npx tsc -b web/tsconfig.json && npm test
   ```
   For anything the browser can show, also run `wrangler dev` and verify in the Browser pane —
   console errors, the actual rendered result, both light and dark. Never ask the user to check
   something manually.

   CI (`.github/workflows/ci.yml`) runs these commands on every PR and every push to `main`, after
   `npm ci`, and then `npm run build`. The three commands above do not build, so a break that only shows
   in the bundle (Vite/Tailwind, the Swagger copy) surfaces at `npm run deploy` or in CI — for front-end
   work, `npm run build` locally (you need it anyway: `wrangler dev` serves `dist/`). CI does not deploy —
   see step 5 for why.

2. **Deploy to prod.**
   ```bash
   npx wrangler d1 migrations apply cf-ai-waf-demo-log --remote   # only when migrations are pending
   npm run deploy
   ```
   Apply migrations **before** the Worker, so the new code never meets an old schema. Read any
   migration before applying it to prod and say plainly if it is not purely additive.

   Note what this ordering means operationally: `npm run deploy` ships the **working tree**, so
   between here and step 5 prod is running a revision that does not exist in git yet. Keep the
   version id `wrangler` prints — with no commit to point at, that id and
   `npx wrangler rollback` are the only way back. Do not start unrelated edits in this window.

3. **Test on prod.**
   ```bash
   npm run smoke:prod
   ```
   All five checks must pass. Prod is behind Cloudflare Access, so use the service token in
   `.env`; a bare probe returns a 302 to the Access login, which is not a failure. Also curl
   anything the smoke test does not cover that this change touched — the smoke test never sees
   the SPA, so for front-end work fetch the deployed bundle and grep it for the change. A fresh
   deploy rolls out gradually, so a mixed result immediately after deploying is usually version
   propagation: re-run ~45s later before diagnosing it as a fault. A failure that **predates** the
   change (nothing deployed since it last passed) still fails this gate — record it in
   `PROGRESS.md` Open bugs and stop, rather than deploying on top of it or waving it through.

4. **Update the docs.** Only once prod has proven the change, so the docs describe what is
   actually running rather than what was intended.
   - `PROGRESS.md` — architecture decisions, open bugs, and what was verified *and how*. Record
     the measurement, not the conclusion: a claim with no evidence behind it is what this file
     exists to prevent.
   - `README.md` — anything that changes setup, endpoints, rules, env vars or what a reader
     would see on a page.
   - `src/openapi.ts` — when an endpoint, a request field or a response shape changed. The test
     suite fails on added/removed routes and `ChatRequestBody` fields, but **not** on a changed
     response shape, so that one is on you: re-check the affected schema against a real payload.
   - This file — when the workflow, environment or house style itself changed.

   A change with no doc impact is normal; say so rather than padding a file to look thorough.

5. **Commit, then push to origin.** One commit covering the change and its docs, so the
   repository never holds code whose documentation is a commit behind. `npx wrangler rollback`
   restores the previous deployment if prod turns out to be wrong after all.

### When a change cannot reach prod

Skip steps 2 and 3 for changes that cannot affect what the Worker serves — CI config, `.nvmrc`,
docs, editor settings. Deploying those is churn, and a smoke test that exercises nothing new
proves nothing. Say the steps were skipped and why; do not skip them silently.

### When to stop and ask

Do not run ahead through a gate when the change is outward-facing in a way the user may not have
priced in — turning off a feature that is live in prod, a destructive migration, or anything that
alters what a customer sees in a demo. State it and let them choose.

## Environment

- Node ≥ 22 — `nvm use 24`.
- `export GPG_TTY=$(tty)` before committing; commits are signed.
- Prod is Access-gated, so functional testing happens on `wrangler dev` against real Workers AI,
  real zone GraphQL and the real AI Gateway REST API.
- `wrangler dev` reads `.env`, **not** `wrangler.jsonc` vars for secrets. A token that fails
  locally says nothing about the same-named secret in prod — that distinction has cost real time
  here twice.
- `npm test` (vitest) does **not** typecheck; `npm run check` does, and it includes test files. A
  test can pass under vitest and fail CI — this happened with `node:fs` in a test, which the
  Worker's tsconfig (Workers types, no Node types) rejects. Run both, and read the whole output of
  `npm run check` — piping it through `tail -1` once hid the error.
- Local `wrangler dev` Workers AI can 502 (`internal error` from miniflare's AI proxy) while prod is
  fine; take chat samples from prod when that happens.
- Local workerd cannot fetch Palo Alto Networks' Prisma AIRS hosts **or** `api.crowdstrike.com`
  (`internal error`, reproduced with a minimal worker; `curl` works). Locally every external guardrail
  reports unavailable — verify it on prod with *Test connection* while it is **disabled**, so live chat is
  never affected.
- Facts about a third-party API come from its own OpenAPI spec (PANW's is in the public
  `PaloAltoNetworks/pan.dev` repo; CrowdStrike's is `aidr-docs.crowdstrike.com/docs/openapi/aidr_openapi.json`),
  then get checked against the live endpoint — **both vendors' specs were wrong**: PANW's error body and
  its report service names (`pi`, `tc`, `uf`, `agent_security`… not the spec's), and CrowdStrike's path
  (`/v1/…` is 404; `/aidr/aiguard/v1/…` is real). Never document a vendor field's meaning before seeing a
  real payload: PANW's `transaction_id` looked like our `tr_id` echoed back and is not.
  PANW's hosts answer a made-up path with the same 403/401 as a real one, so a dummy-credential probe there
  proves nothing about whether an endpoint exists. Also check what a live error *proves*:
  AIDR returns the same 401 with no token as with a bad one, so it cannot confirm a token arrived.
  Lakera's live error body differs from its own API reference too (`error` is a code like `ErrMissingToken`,
  the text is in `message`). Cisco AI Defense and Lakera hosts DO answer a made-up path with 404, so a no-key
  probe there does prove a path exists. A provider stays `supported: false` until a real verdict payload has
  been seen.
- In zsh, never name a variable `path`: it is tied to `$PATH`, and a `for path in …` loop leaves every
  later command "not found".
- Migrations: always `npx wrangler d1 migrations apply cf-ai-waf-demo-log [--local|--remote]`,
  never `d1 execute --file` — that bypasses the `d1_migrations` table, and a git worktree has its
  own `.wrangler` state, so a migration applied there never reaches this checkout. Both have
  produced `duplicate column name` / `no such table` here.
- `git push` authenticates through `gh` (`gh auth setup-git` installs the helper), so `gh auth
  switch` decides which account pushes. A 403 with `permissions.push: false` from
  `gh api repos/bkrbybk-org/cf-firewall-for-ai-demo` means the active account has read-only access.
- In this zsh, an unquoted `--include=*.tsx` fails with `no such match` *and the pipeline carries
  on*, so a grep-based "no consumers" check silently reports zero. Quote the glob.
- zsh does **not** word-split an unquoted variable: `J='-H content-type:application/json'; curl $J …` passes
  one malformed argument, and prod answers with Access's 302 page — which looks like an auth failure. Put
  curl headers in an array (`H=(-H "…" -H "…"); curl "${H[@]}"`).
- Under `wrangler dev`, `request.url` carries the **route's hostname over http**
  (`http://cf-ai-waf-demo.nttlab.org`), not `localhost`. Never build a link or server URL from it for the
  browser — derive it client-side (`window.location.origin`), or local "Try it out" hits prod.
- API Shield Schema Validation only parses **OpenAPI 3.0**: upload `/api/openapi-3.0.json` (generated by
  `src/openapi30.ts`), never the 3.1 `/api/openapi.json`. To reproduce its parser, use Go `kin-openapi`
  v0.118 — current versions accept 3.1 and prove nothing.
- An organisation PreToolUse policy blocks some shell heredocs (`python3 - <<EOF`, `cat > f <<EOF`) as
  "persistence". Use the Edit/Write tools for file edits instead. A second policy blocks any shell command
  containing the SQL keyword that empties a table — **including the word inside `truncated`** (a field
  name here). Grep for `runcated`, or build the key as `j["trunc"+"ated"]`.
- **D1 enforces foreign keys.** A batch that deletes a parent row before its children fails whole with
  `SQLITE_CONSTRAINT_FOREIGNKEY`: delete children first. The red-team prune did this the other way round and
  every save failed once 50 runs existed; nothing noticed for a month because no page called it. An
  endpoint with no consumer is untested however good its unit tests are: exercise it end to end on a real
  (local) D1 before calling it done.
- Local D1: `npx wrangler d1 execute cf-ai-waf-demo-log --local --command "…"`. Local dev sets no
  `cf-ray`, so any test of the prompt-log write path must fake one or it proves nothing.
- The prompt log is off in `wrangler.jsonc` (and in prod), so `/api/prompt-log` and `/api/prompt-analytics`
  answer `disabled` on a plain `wrangler dev`. To exercise them, start the **`wrangler-dev-promptlog`** launch
  config (port 8788, `--var PROMPT_LOG_ENABLED:true`) — never flip the flag in `wrangler.jsonc` to test.

## House style

- No formatter is configured. Double quotes, ~110 columns, closing JSX bracket on its own line.
  **Never run Prettier or Biome** — one accidental run produced a 624-line diff with one line of
  real change in it.
- Comments explain **why**, not what. This codebase reasons about its own honesty; match that
  density and never delete a comment to make room.
- Analytics and compliance surfaces grade their own coverage honestly: "no data" is never
  rendered as zero, capped counts read as "at least N", and every number states its window.
  Keep that property — it is the credibility of the whole demo.
