-- Persisted Red Team runs, so a run survives a reload and two runs can be
-- diffed ("add the Self-criticism custom topic, re-run, prove the gap
-- closed" — the point of the feature; see web/src/pages/RedTeamPage.tsx).
-- Scoring itself still happens in the BROWSER (web/src/hooks/useRedTeam.ts:
-- sendOne → fetchVerdictOnce → verdictOutcome → resolveState) — this table
-- only stores the finished, already-scored result the client POSTs. The
-- Worker never re-derives a verdict here.
--
-- One row per run (redteam_runs) plus one row per attack in that run
-- (redteam_results). Split into two tables, not one denormalized table,
-- because the run's own totals (RtScore) are read constantly on the list
-- view and must not require summing hundreds of result rows every time.
CREATE TABLE IF NOT EXISTS redteam_runs (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  ts                  INTEGER NOT NULL,          -- epoch ms, run start
  label               TEXT,                      -- operator note, e.g. "before Self-Criticism topic"
  route               TEXT NOT NULL,             -- 'direct' | 'gateway'
  gateway_id          TEXT,                      -- null for the direct route
  guarded             INTEGER NOT NULL DEFAULT 0, -- 0/1 (SQLite has no bool)
  model               TEXT,
  -- Comparability trio: `diffRuns` (web/src/lib/redteam.ts) refuses to read
  -- two runs as before/after unless corpus_fingerprint matches — otherwise a
  -- smaller or edited corpus would read as "we closed the gap" when it is
  -- really just a different attack set. name/size are carried for the
  -- human-readable half of that message; the fingerprint is what the code
  -- actually compares on.
  corpus_name         TEXT NOT NULL,
  corpus_size         INTEGER NOT NULL,
  corpus_fingerprint  TEXT NOT NULL,             -- hash over the sorted attackKeys, see attackKey()
  delay_ms            INTEGER NOT NULL DEFAULT 0,
  -- The scored totals (RtScore, web/src/lib/redteam.ts), stored rather than
  -- recomputed on every list-page read. Mirrors why prompt_log stores
  -- prompt_tokens/completion_tokens instead of recounting them.
  total               INTEGER NOT NULL,
  scored              INTEGER NOT NULL,
  reached             INTEGER NOT NULL,
  stopped             INTEGER NOT NULL,
  denied              INTEGER NOT NULL,
  guardrails          INTEGER NOT NULL,
  pending             INTEGER NOT NULL,
  error               INTEGER NOT NULL,
  reached_pct         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_redteam_runs_ts ON redteam_runs (ts DESC);

-- Per-attack result. `attack_key` is the join key `diffRuns` compares across
-- runs (stable across CSV reorders/re-uploads); `attack_id` is only the
-- display id from that run's own corpus ("rt-01" / "csv-12") and must never
-- be used to match a row against a different run's results.
CREATE TABLE IF NOT EXISTS redteam_results (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id          INTEGER NOT NULL REFERENCES redteam_runs(id),
  attack_key      TEXT NOT NULL,
  attack_id       TEXT NOT NULL,
  category        TEXT NOT NULL,
  severity        TEXT,                          -- scan-only; null for a custom CSV attack
  state           TEXT NOT NULL,                 -- RtResultState — validated against the union server-side
  ray             TEXT,
  ts              INTEGER,                       -- epoch ms, this attack's send
  prompt_preview  TEXT                           -- redact()-ed and truncated (~200 chars); never the raw prompt
);

CREATE INDEX IF NOT EXISTS idx_redteam_results_run_id ON redteam_results (run_id);
