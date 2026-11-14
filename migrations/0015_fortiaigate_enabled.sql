-- FortiAIGate as a third chat route (2026-11-14): the Settings switch. Enabled = the chat page offers a "FortiAIGate"
-- route next to Direct and AI Gateway; off = the route is refused (400), never a silent fallback. DEFAULT 0 keeps the
-- saved settings exactly as they behave today. Additive.
ALTER TABLE fortiaigate_config ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1));
