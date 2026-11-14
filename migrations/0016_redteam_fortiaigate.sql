-- Red Team through FortiAIGate (2026-11-14): a run may use the third route, and an attack FortiAIGate blocked gets its
-- own result state `fortiaigate` and its own run total — never folded into `guardrails` (AI Gateway Guardrails) or
-- `external` (the external guardrails), so each control is credited only with what it stopped. Like those two it is
-- kept out of the edge headline (reached / scored). route stays TEXT (no CHECK; 'direct' | 'gateway' | 'fortiaigate').
-- DEFAULT 0 keeps every saved run exactly as it reads today. Additive.
ALTER TABLE redteam_runs ADD COLUMN fortiaigate INTEGER NOT NULL DEFAULT 0;
