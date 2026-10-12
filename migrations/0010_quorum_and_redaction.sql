-- Quorum pipeline mode (#7) and applying a vendor's redaction (#11). Purely additive: every column has a
-- default that reproduces how the app behaved before.

-- Quorum mode. `mode` keeps its CHECK (sequential | parallel) — SQLite cannot alter a CHECK without
-- rebuilding the table — so quorum is its own switch: quorum_on = 1 reads as mode "quorum" (and `mode` then
-- holds 'parallel', which quorum runs like). `quorum`: how many votes (blocks, fail-closed errors) stop a turn.
ALTER TABLE guardrail_pipeline ADD COLUMN quorum_on INTEGER NOT NULL DEFAULT 0 CHECK (quorum_on IN (0, 1));
ALTER TABLE guardrail_pipeline ADD COLUMN quorum INTEGER NOT NULL DEFAULT 2 CHECK (quorum BETWEEN 1 AND 6);

-- Per provider: send the vendor's redacted prompt to the model instead of the original. 0 (default) = the
-- redaction is reported, not applied — the only behaviour before this migration.
ALTER TABLE external_guardrails ADD COLUMN apply_redaction INTEGER NOT NULL DEFAULT 0 CHECK (apply_redaction IN (0, 1));
