-- External guardrails become a pipeline: several providers may be enabled at
-- once, run in order (sequential) or together (parallel), optionally stopping
-- before the model (guardrail-only). See src/externalGuardrails.ts.

-- NOT purely additive: this removes the "at most one enabled provider" rule
-- that migration 0005 put in the database. Existing rows are untouched — a
-- single enabled provider keeps working exactly as before.
DROP INDEX IF EXISTS idx_external_guardrails_one_enabled;

-- One row (id = 1). Absent row = defaults: sequential, model runs, registry order.
CREATE TABLE IF NOT EXISTS guardrail_pipeline (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  mode            TEXT NOT NULL DEFAULT 'sequential' CHECK (mode IN ('sequential', 'parallel')),
  guardrail_only  INTEGER NOT NULL DEFAULT 0 CHECK (guardrail_only IN (0, 1)),
  provider_order  TEXT NOT NULL DEFAULT '',       -- comma-separated provider ids; normalised on read
  updated_at      INTEGER                         -- epoch ms
);

-- Red-team runs: how many of the attacks that got past every check were NOT
-- sent to the model (guardrail-only). They still count as "reached" — the
-- edge and the guardrails let them through — but no model answered them.
ALTER TABLE redteam_runs ADD COLUMN skipped INTEGER NOT NULL DEFAULT 0;
