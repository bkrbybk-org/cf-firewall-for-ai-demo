-- Per vendor: include it in the 6-hourly scheduled re-run (src/scheduledRerun.ts) — 12 prompts, 2 reply pairs and the
-- smoke canary, about 15 calls a run. Off = the cron sends that vendor nothing; chat and Red Team still use it.
-- DEFAULT 1 keeps every existing row exactly as it behaves today. Additive.
ALTER TABLE external_guardrails ADD COLUMN scheduled INTEGER NOT NULL DEFAULT 1 CHECK (scheduled IN (0, 1));
