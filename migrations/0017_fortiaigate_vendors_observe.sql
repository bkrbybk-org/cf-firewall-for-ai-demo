-- FortiAIGate route: let the external guardrails OBSERVE only (2026-11-15). On: on the FortiAIGate route the enabled
-- vendors still check the prompt and the reply, and their verdicts are logged and scored, but they never stop the
-- turn, never withhold the reply and never redact — so FortiAIGate sees every prompt and the two can be compared on
-- the same traffic. The other routes are unaffected. DEFAULT 0 keeps today's behaviour (vendors can stop the turn).
-- Additive.
ALTER TABLE fortiaigate_config ADD COLUMN vendors_observe INTEGER NOT NULL DEFAULT 0 CHECK (vendors_observe IN (0, 1));
