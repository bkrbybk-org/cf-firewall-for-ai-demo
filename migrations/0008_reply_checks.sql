-- Design J: external guardrails may also check the model's REPLY. Purely additive.

-- The switch. 0 (default) = prompts only, exactly how the app behaved before.
-- On: a turn is answered in one piece (never streamed), so the reply can be
-- checked before anyone sees it, and every enabled guardrail that can check
-- replies is called a second time.
ALTER TABLE guardrail_pipeline ADD COLUMN scan_replies INTEGER NOT NULL DEFAULT 0 CHECK (scan_replies IN (0, 1));

-- Saved red-team runs: each guardrail's verdict on the reply, the same compact JSON
-- as `vendors` (src/redteamruns.ts). Null when the reply was not checked — the
-- switch was off, there was no reply, or the run predates this migration — which
-- the benchmark shows as "not checked", never as a pass.
ALTER TABLE redteam_results ADD COLUMN reply_vendors TEXT;
