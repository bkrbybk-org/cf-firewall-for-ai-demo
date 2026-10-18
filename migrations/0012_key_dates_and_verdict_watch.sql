-- 2026-10-18. Purely additive: two nullable columns and a new table.
--
-- Key age (Settings): when each stored credential was saved. NULL for a key saved before this migration — the page then
-- shows an age of AT LEAST (now − updated_at), since updated_at moves on every save and so is no earlier than the key's.
ALTER TABLE external_guardrails ADD COLUMN api_key_set_at INTEGER;     -- epoch ms; NULL = no key, or saved before 0012
ALTER TABLE external_guardrails ADD COLUMN second_key_set_at INTEGER;  -- the same, for the second credential (Datadog)

-- Verdict changes (src/verdictWatch.ts): each vendor's last CONFIRMED verdict on each prompt of the scheduled set, so a
-- change is announced once — when a different verdict has held for two runs in a row — not on every run, and not on
-- one noisy answer. Errors are not verdicts and never touch a row.
CREATE TABLE IF NOT EXISTS guardrail_prompt_verdicts (
  provider    TEXT NOT NULL,                                       -- an ExternalGuardrailProvider id
  prompt_id   TEXT NOT NULL,                                       -- "v<set version>/<id>", e.g. "v1/han-600"
  outcome     TEXT NOT NULL CHECK (outcome IN ('block', 'allow')), -- the confirmed verdict
  since       INTEGER NOT NULL,                                    -- epoch ms it was first seen (or confirmed)
  pending     TEXT CHECK (pending IN ('block', 'allow')),          -- a different verdict seen once, awaiting a second
  updated_at  INTEGER NOT NULL,                                    -- epoch ms of the last run that gave a verdict
  PRIMARY KEY (provider, prompt_id)
);
