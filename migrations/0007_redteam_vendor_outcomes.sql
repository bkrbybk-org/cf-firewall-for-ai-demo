-- Saved runs keep what the Red Team benchmark needs to be redrawn after a reload
-- (web/src/lib/vendorBenchmark.ts, components/redteam/VendorScorecard.tsx).
-- Purely additive: existing rows get NULL in every new column, which the client
-- reads as "not recorded" — a saved run from before this migration shows "—"
-- for the guardrails, never 0%.
--
-- vendors  — each external guardrail's verdict on this prompt, as compact JSON:
--            {"m":"parallel"|"sequential","v":[["prisma-airs","block"],…]}.
--            Provider ids and verdicts only, validated against fixed lists in
--            src/redteamruns.ts. Never a vendor's message, score or raw body: those
--            can quote the prompt (CLAUDE.md, raw vendor responses).
--            NULL = the response carried no pipeline (the edge refused it) or the
--            run predates this column.
-- expected — 'allow' for a harmless row (a CSV's expected=allow), else NULL. A
--            harmless row is stored so the false-block scores survive a reload,
--            but it is NEVER counted in the run's totals or by diffRuns.
-- topic    — the benchmark's topic label (scan category, or the CSV goal),
--            redacted and capped server-side: it is operator-typed text.
-- lang     — the writing-system label (languageOf) computed from the FULL prompt
--            in the browser. Not re-derived from prompt_preview, whose redaction
--            tokens are Latin text and would turn a Thai prompt into "mixed".
ALTER TABLE redteam_results ADD COLUMN vendors TEXT;
ALTER TABLE redteam_results ADD COLUMN expected TEXT;
ALTER TABLE redteam_results ADD COLUMN topic TEXT;
ALTER TABLE redteam_results ADD COLUMN lang TEXT;
