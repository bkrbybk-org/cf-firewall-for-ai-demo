// Vendor health on the Settings rows: is this guardrail actually answering? Read from the same Analytics Engine
// verdict data as the Analytics page's External guardrails tab (GET /api/guardrail-analytics, last 24h, all traffic —
// a Red Team call is a real call to the vendor too).
//
// Honesty: "unknown" when the data could not be read (never "healthy"); "idle" when the vendor ran no check in the
// window (never "0% errors"); a check that ended without a verdict (fail closed or fail open) is what makes a vendor
// "degraded" — a block is an answer, not a fault. Counts carry "≈" when Analytics Engine sampled the window.
// "rejected" (2026-10-18): most checks without a verdict got HTTP 401/403 — the vendor rejected the key, which no
// retry fixes (Cato, from 2026-10-13). Same rule as the outage alert's (src/vendorAlerts.ts keyRejected).
import type { ExternalGuardrailProvider, GuardrailAnalytics } from "./types";

export type HealthState = "unknown" | "idle" | "ok" | "degraded" | "rejected";

export interface VendorHealth {
  state: HealthState;
  checked: number; // prompt + reply checks that ran
  noVerdict: number; // error (fail closed) + failed open
  error: number;
  failedOpen: number;
  authFailed: number; // of noVerdict: HTTP 401/403
  lastTs: number | null; // the newest check that ran, epoch ms
  sampled: boolean;
  hours: number;
}

export function vendorHealth(provider: ExternalGuardrailProvider, d: GuardrailAnalytics | null | undefined): VendorHealth {
  const base = { checked: 0, noVerdict: 0, error: 0, failedOpen: 0, authFailed: 0, lastTs: null, sampled: false, hours: 24 };
  if (!d || d.configured === false || d.error || !Array.isArray(d.vendors)) return { state: "unknown", ...base };
  const rows = d.vendors.filter((v) => v.provider === provider);
  const checked = rows.reduce((n, v) => n + v.checked, 0);
  const error = rows.reduce((n, v) => n + v.error, 0);
  const failedOpen = rows.reduce((n, v) => n + v.failedOpen, 0);
  const authFailed = rows.reduce((n, v) => n + (v.authFailed ?? 0), 0); // absent from an older Worker → 0
  const times = rows.map((v) => v.lastTs).filter((t): t is number => typeof t === "number");
  const h = {
    checked,
    error,
    failedOpen,
    authFailed,
    noVerdict: error + failedOpen,
    lastTs: times.length ? Math.max(...times) : null,
    sampled: !!d.sampled,
    hours: d.rangeHours ?? 24,
  };
  const state: HealthState =
    checked === 0 ? "idle" : h.noVerdict === 0 ? "ok" : authFailed / h.noVerdict > 0.5 ? "rejected" : "degraded";
  return { state, ...h };
}

export function ago(ts: number, now: number): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const hr = Math.round(m / 60);
  return hr < 48 ? `${hr} h ago` : `${Math.round(hr / 24)} d ago`;
}

// `downSince`: when the hourly outage check last marked this vendor down (automation.alerts.states), if it still says
// so — it reaches back past the 24h window ("since 13 Oct"), which these counts cannot.
export function healthText(h: VendorHealth, now: number, downSince?: number): string {
  const mark = h.sampled ? "≈" : "";
  const n = (v: number) => `${mark}${Math.round(v)}`;
  const win = `last ${h.hours}h`;
  const since = downSince != null ? ` · down since ${new Date(downSince).toLocaleString()}` : "";
  switch (h.state) {
    case "rejected":
      return `Key rejected — ${n(h.authFailed)} of ${n(h.checked)} checks got HTTP 401/403 (${win})${since}. Issue a new key in the vendor's console and save it here.`;
    case "unknown":
      return "Health unknown — the verdict data could not be read";
    case "idle":
      return `No checks in the ${win}`;
    case "ok":
      return `Last checked ${h.lastTs != null ? ago(h.lastTs, now) : "—"} · ${win}: ${n(h.checked)} check${h.checked === 1 ? "" : "s"}, every one answered`;
    case "degraded": {
      const pct = Math.round((h.noVerdict / h.checked) * 100);
      const split = [h.error > 0 ? `${n(h.error)} fail closed` : "", h.failedOpen > 0 ? `${n(h.failedOpen)} fail open` : ""]
        .filter(Boolean)
        .join(", ");
      return `Last checked ${h.lastTs != null ? ago(h.lastTs, now) : "—"} · ${win}: ${n(h.noVerdict)} of ${n(h.checked)} checks got no verdict (${pct}%: ${split})${since}`;
    }
  }
}

// ── key age (2026-10-18) ─────────────────────────────────────────────────────
// A vendor key expires or is revoked on the vendor's side with no warning here (Cato's, 2026-10-13). The age is a
// nudge to check it, not a claim that it expired: no vendor here tells us a key's lifetime.
export const KEY_AGE_WARN_DAYS = 90;

export interface KeyAge {
  days: number;
  atLeast: boolean; // saved before dates were kept: `days` is a floor (from the config's last save)
  stale: boolean; // days ≥ KEY_AGE_WARN_DAYS
}

export function keyAge(savedAt: number | null | undefined, noLaterThan: number | null | undefined, now: number): KeyAge | null {
  const from = savedAt ?? noLaterThan;
  if (from == null) return null; // no key, or an older Worker
  const days = Math.max(0, Math.floor((now - from) / 86_400_000));
  return { days, atLeast: savedAt == null, stale: days >= KEY_AGE_WARN_DAYS };
}

export function keyAgeText(a: KeyAge): string {
  const d = a.days === 0 ? "today" : `${a.days} d ago`;
  return a.atLeast ? (a.days === 0 ? "saved today or earlier" : `saved ≥ ${a.days} d ago`) : `saved ${d}`;
}
