-- Prompt log for further analysis. One row per prompt that REACHED the Worker
-- (edge-blocked 403s never invoke the Worker, so they are not here — see the
-- Analytics edge tab for those). Prompt/reply are PII-redacted at write time.
CREATE TABLE IF NOT EXISTS prompt_log (
  ray               TEXT PRIMARY KEY,
  ts                INTEGER NOT NULL,          -- epoch ms
  route             TEXT NOT NULL,             -- 'direct' | 'gateway'
  model             TEXT NOT NULL,
  gateway_id        TEXT,                      -- null for the direct route
  guarded           INTEGER NOT NULL DEFAULT 0,
  outcome           TEXT NOT NULL,             -- 'reply' | 'guardrails' | 'error'
  prompt            TEXT NOT NULL,             -- PII-redacted
  reply             TEXT,                      -- PII-redacted; null if streamed/blocked
  redactions        INTEGER NOT NULL DEFAULT 0,
  prompt_tokens     INTEGER,
  completion_tokens INTEGER
);

CREATE INDEX IF NOT EXISTS idx_prompt_log_ts ON prompt_log (ts DESC);
