-- A second credential per external guardrail, for a vendor that needs two (Datadog AI Guard: an API key
-- AND an application key). Purely additive: both columns are nullable, and every existing provider takes
-- one key, so its rows stay as they are.
ALTER TABLE external_guardrails ADD COLUMN second_key_enc TEXT;   -- base64(iv || AES-256-GCM ciphertext); never plaintext
ALTER TABLE external_guardrails ADD COLUMN second_key_last4 TEXT; -- the only part of it ever shown back
