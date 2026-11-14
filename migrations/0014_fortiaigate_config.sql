-- FortiAIGate (Fortinet's self-hosted AI gateway): one row of connection settings, edited in Settings → System.
-- FortiAIGate is an inline PROXY, not a scan API, so it is not a row of external_guardrails: the guardrail pipeline,
-- the scheduled re-runs and the vendor analytics must never treat it as a pre-check (src/fortiAiGate.ts).
-- Credentials are AES-256-GCM ciphertext (GUARDRAIL_SECRET_KEY), each bound to its own AAD; only the last 4 characters
-- are kept in clear. base_url is an origin under FORTIAIGATE_ALLOWED_HOST_SUFFIX, checked on every write.
-- New table, additive.
CREATE TABLE fortiaigate_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  base_url TEXT,
  models TEXT NOT NULL DEFAULT '[]',
  block_message TEXT,
  virtual_key_enc TEXT,
  virtual_key_last4 TEXT,
  virtual_key_set_at INTEGER,
  access_client_id_enc TEXT,
  access_client_id_last4 TEXT,
  access_client_secret_enc TEXT,
  access_client_secret_last4 TEXT,
  access_set_at INTEGER,
  updated_at INTEGER
);
