-- External guardrail configuration (Prisma AIRS first): one row per provider.
-- See src/externalGuardrails.ts for why each column is shaped the way it is.
CREATE TABLE IF NOT EXISTS external_guardrails (
  provider      TEXT PRIMARY KEY,                -- 'prisma-airs' | 'crowdstrike-aidr'
  enabled       INTEGER NOT NULL DEFAULT 0,      -- 0/1
  region        TEXT NOT NULL,                   -- an allowlisted region id, never a free URL
  profile_name  TEXT,                            -- Prisma AIRS AI security profile name
  fail_mode     TEXT NOT NULL DEFAULT 'block',   -- 'block' (fail closed) | 'allow' (fail open)
  api_key_enc   TEXT,                            -- base64(iv || AES-256-GCM ciphertext); never plaintext
  api_key_last4 TEXT,                            -- the only part of the key ever shown back
  updated_at    INTEGER                          -- epoch ms
);

-- "Only one guardrail at a time", enforced by the database rather than the UI:
-- at most one row may have enabled = 1.
CREATE UNIQUE INDEX IF NOT EXISTS idx_external_guardrails_one_enabled
  ON external_guardrails (enabled) WHERE enabled = 1;

-- Red-team runs: an external-guardrail block is its own outcome, counted apart
-- from AI Gateway Guardrails and from the edge WAF so neither is credited with it.
ALTER TABLE redteam_runs ADD COLUMN external INTEGER NOT NULL DEFAULT 0;
