# CLAUDE.md

Cloudflare AI Security for Apps demo — Worker (API + React SPA) on `cf-ai-waf-demo.nttlab.org`.

`PROGRESS.md` and `README.md` are the source of truth for architecture, open bugs and setup.
Read them before answering questions about how this app works.

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

   CI (`.github/workflows/ci.yml`) runs exactly these commands on every PR and every push to
   `main`, so a green local run is a green CI run. It does not deploy — see step 5 for why.

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
   propagation: re-run ~45s later before diagnosing it as a fault.

4. **Update the docs.** Only once prod has proven the change, so the docs describe what is
   actually running rather than what was intended.
   - `PROGRESS.md` — architecture decisions, open bugs, and what was verified *and how*. Record
     the measurement, not the conclusion: a claim with no evidence behind it is what this file
     exists to prevent.
   - `README.md` — anything that changes setup, endpoints, rules, env vars or what a reader
     would see on a page.
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
- Local D1: `npx wrangler d1 execute cf-ai-waf-demo-log --local --command "…"`. Local dev sets no
  `cf-ray`, so any test of the prompt-log write path must fake one or it proves nothing.

## House style

- No formatter is configured. Double quotes, ~110 columns, closing JSX bracket on its own line.
  **Never run Prettier or Biome** — one accidental run produced a 624-line diff with one line of
  real change in it.
- Comments explain **why**, not what. This codebase reasons about its own honesty; match that
  density and never delete a comment to make room.
- Analytics and compliance surfaces grade their own coverage honestly: "no data" is never
  rendered as zero, capped counts read as "at least N", and every number states its window.
  Keep that property — it is the credibility of the whole demo.
