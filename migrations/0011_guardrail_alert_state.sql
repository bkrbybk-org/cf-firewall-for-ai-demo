-- Vendor outage alerts (#17, src/vendorAlerts.ts): the last state the hourly check saw per vendor, so an alert is sent
-- when a vendor GOES down or COMES back — not every hour while it stays down. Purely additive: a new table.
CREATE TABLE IF NOT EXISTS guardrail_alert_state (
  provider    TEXT PRIMARY KEY,                                 -- an ExternalGuardrailProvider id
  state       TEXT NOT NULL CHECK (state IN ('ok', 'down')),
  since       INTEGER NOT NULL,                                 -- epoch ms the state began (as the check saw it)
  updated_at  INTEGER NOT NULL                                  -- epoch ms of the last check that had data for it
);
