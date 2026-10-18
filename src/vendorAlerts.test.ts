// Vendor outage alerts (#17). Hand-computed thresholds; an alert only on a change; nothing but names and counts leaves;
// the webhook is called only when set to an https URL, and a failed read changes no state.
import { describe, expect, it } from "vitest";
import type { VendorStats } from "./guardrailAnalytics";
import {
  ALERT_MIN_CHECKS,
  alertText,
  evaluate,
  keyRejected,
  runVendorAlerts,
  transitions,
  webhookUrl,
  type AlertState,
} from "./vendorAlerts";
import type { Env, ExternalGuardrailProvider } from "./types";

const stat = (provider: ExternalGuardrailProvider, dir: "prompt" | "reply", checked: number, error: number, failedOpen = 0) =>
  ({ provider, dir, checked, error, failedOpen }) as VendorStats;

describe("evaluate", () => {
  it("adds prompt and reply checks; down at ≥ 50% no verdict with ≥ 3 checks; unknown below 3", () => {
    const c = evaluate([
      stat("lakera-guard", "prompt", 2, 1),
      stat("lakera-guard", "reply", 2, 0, 1), // 4 checks, 2 without a verdict → exactly 50% → down
      stat("cato-ai-security", "prompt", 4, 1), // 25% → ok
      stat("prisma-airs", "prompt", 2, 2), // 100% but only 2 checks → unknown, never "down" on two calls
    ]);
    expect(c).toEqual([
      { provider: "lakera-guard", checked: 4, noVerdict: 2, authFailed: 0, state: "down" },
      { provider: "cato-ai-security", checked: 4, noVerdict: 1, authFailed: 0, state: "ok" },
      { provider: "prisma-airs", checked: 2, noVerdict: 2, authFailed: 0, state: "unknown" },
    ]);
    expect(ALERT_MIN_CHECKS).toBe(3);
  });
});

describe("transitions", () => {
  const prev = new Map<ExternalGuardrailProvider, AlertState>([
    ["lakera-guard", "ok"],
    ["cato-ai-security", "down"],
    ["prisma-airs", "down"],
  ]);
  it("alerts on ok → down and down → ok; a first sighting only when already down; unknown and no change are silent", () => {
    const t = transitions(prev, [
      { provider: "lakera-guard", checked: 4, noVerdict: 3, authFailed: 0, state: "down" },
      { provider: "cato-ai-security", checked: 5, noVerdict: 0, authFailed: 0, state: "ok" },
      { provider: "prisma-airs", checked: 1, noVerdict: 1, authFailed: 0, state: "unknown" },
      { provider: "cisco-ai-defense", checked: 6, noVerdict: 0, authFailed: 0, state: "ok" }, // first seen, healthy
      { provider: "datadog-ai-guard", checked: 3, noVerdict: 3, authFailed: 0, state: "down" }, // first seen, down
    ]);
    expect(t.map((x) => [x.provider, x.from, x.to])).toEqual([
      ["lakera-guard", "ok", "down"],
      ["cato-ai-security", "down", "ok"],
      ["datadog-ai-guard", null, "down"],
    ]);
  });
});

describe("alertText and webhookUrl", () => {
  it("names the vendor, the counts and the window — nothing else", () => {
    const t = alertText([
      { provider: "lakera-guard", from: "ok", to: "down", checked: 4, noVerdict: 3, authFailed: 0 },
      { provider: "cato-ai-security", from: "down", to: "ok", checked: 10, noVerdict: 0, authFailed: 0 },
    ]);
    expect(t).toContain("Check Point Lakera Guard looks DOWN: 3 of 4 checks (75%) got no verdict in the last 1h.");
    expect(t).toContain("Cato Networks AI Security recovered: 0 of 10 checks without a verdict in the last 1h.");
  });
  it("accepts only an https URL to a public host", () => {
    expect(webhookUrl("https://hooks.slack.com/services/T/B/x")?.hostname).toBe("hooks.slack.com");
    for (const bad of [undefined, "", "http://hooks.slack.com/x", "https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.1/x", "https://[::1]/x", "not a url"]) {
      expect(webhookUrl(bad), String(bad)).toBeNull();
    }
  });
});

// A stand-in D1 holding guardrail_alert_state in memory — enough for the SELECT and the upsert batch.
function fakeDb(initial: Record<string, { state: AlertState; since: number }>) {
  const rows = new Map(Object.entries(initial).map(([p, v]) => [p, { ...v, updated_at: 0 }]));
  const db = {
    rows,
    prepare: (sql: string) => {
      const stmt = {
        args: [] as unknown[],
        bind: (...a: unknown[]) => ({ ...stmt, args: a }),
        all: async () => ({ results: [...rows.entries()].map(([provider, r]) => ({ provider, state: r.state, since: r.since, updated_at: r.updated_at })) }),
        sql,
      };
      return stmt;
    },
    batch: async (stmts: { args: unknown[] }[]) => {
      for (const s of stmts) {
        const [provider, state, since, updated] = s.args as [string, AlertState, number, number];
        const old = rows.get(provider);
        rows.set(provider, { state, since: old && old.state === state ? old.since : since, updated_at: updated });
      }
      return [];
    },
  };
  return db;
}

const NOW = Date.parse("2026-10-12T10:17:00Z");
const aeRow = (provider: string, outcome: string) => ({
  ts: "2026-10-12 09:50:00", si: 1, src: "scheduled", dir: "prompt", provider, outcome, detected: "", ray: "", scan_id: "",
  mode: "parallel", action: "", expect: "", ms: 100, status: 200, alerts: 0, redaction: 0, incomplete: 0, decided: 0, applied: 0,
});

describe("runVendorAlerts", () => {
  function env(db: ReturnType<typeof fakeDb>, webhook?: string) {
    return { CF_ANALYTICS_TOKEN: "t", CF_ACCOUNT_ID: "a", DB: db, ALERT_WEBHOOK_URL: webhook } as unknown as Env;
  }
  // Lakera: 3 of 4 with no verdict (down). Cato: 4 allows (ok).
  const rows = [
    aeRow("lakera-guard", "error"), aeRow("lakera-guard", "failed_open"), aeRow("lakera-guard", "failed_open"), aeRow("lakera-guard", "allow"),
    aeRow("cato-ai-security", "allow"), aeRow("cato-ai-security", "allow"), aeRow("cato-ai-security", "allow"), aeRow("cato-ai-security", "block"),
  ];
  const fetchWith = (calls: { url: string; body?: string }[], ae = rows, hook = 200) =>
    (async (url: string, init?: RequestInit) => {
      calls.push({ url, body: typeof init?.body === "string" ? init.body : undefined });
      if (url.includes("analytics_engine")) return Response.json({ data: ae });
      return new Response("ok", { status: hook });
    }) as typeof fetch;

  it("posts one message for the vendor that went down, stores both states, and never repeats it", async () => {
    const db = fakeDb({ "lakera-guard": { state: "ok", since: 1 } });
    const calls: { url: string; body?: string }[] = [];
    const s = await runVendorAlerts(env(db, "https://hooks.example.com/x"), { fetchImpl: fetchWith(calls), now: NOW, log: () => {} });
    expect(s).toMatchObject({ alerts: 1, delivered: "webhook" });
    const hook = calls.filter((c) => c.url === "https://hooks.example.com/x");
    expect(hook).toHaveLength(1);
    const payload = JSON.parse(hook[0].body!);
    expect(payload.alerts).toEqual([
      { provider: "lakera-guard", from: "ok", to: "down", checked: 4, noVerdict: 3, authFailed: 0, label: "Check Point Lakera Guard" },
    ]);
    expect(db.rows.get("lakera-guard")).toMatchObject({ state: "down", since: NOW });
    expect(db.rows.get("cato-ai-security")).toMatchObject({ state: "ok" }); // first seen healthy: stored, not announced
    // The next hour, same data: no message.
    const again: { url: string }[] = [];
    const s2 = await runVendorAlerts(env(db, "https://hooks.example.com/x"), { fetchImpl: fetchWith(again), now: NOW + 3_600_000, log: () => {} });
    expect(s2.alerts).toBe(0);
    expect(again.filter((c) => !c.url.includes("analytics_engine"))).toEqual([]);
    expect(db.rows.get("lakera-guard")!.since).toBe(NOW); // still down since the first hour
  });

  it("with no webhook set, only logs — nothing is sent anywhere but the AE read", async () => {
    const calls: { url: string }[] = [];
    const lines: Record<string, unknown>[] = [];
    const s = await runVendorAlerts(env(fakeDb({})), { fetchImpl: fetchWith(calls), now: NOW, log: (l) => lines.push(l as Record<string, unknown>) });
    expect(s).toMatchObject({ alerts: 1, delivered: "log" });
    expect(calls.every((c) => c.url.includes("analytics_engine"))).toBe(true);
    expect(lines.some((l) => l.event === "guardrail_alert" && String(l.note).includes("not set"))).toBe(true);
  });

  it("an invalid webhook is not called, and the log never carries its value", async () => {
    const calls: { url: string }[] = [];
    const lines: unknown[] = [];
    await runVendorAlerts(env(fakeDb({}), "http://hooks.example.com/secret-path"), { fetchImpl: fetchWith(calls), now: NOW, log: (l) => lines.push(l) });
    expect(calls.every((c) => c.url.includes("analytics_engine"))).toBe(true);
    expect(JSON.stringify(lines)).not.toContain("secret-path");
  });

  it("a failed Analytics Engine read is not an alert and changes no state", async () => {
    const db = fakeDb({ "lakera-guard": { state: "down", since: 5 } });
    const failing = (async () => new Response("no", { status: 500 })) as typeof fetch;
    const s = await runVendorAlerts(env(db, "https://hooks.example.com/x"), { fetchImpl: failing, now: NOW, log: () => {} });
    expect(s).toMatchObject({ alerts: 0, skipped: "Analytics Engine returned HTTP 500" });
    expect(db.rows.get("lakera-guard")).toMatchObject({ state: "down", since: 5 });
  });

  it("a failing webhook is reported as failed, not delivered", async () => {
    const calls: { url: string }[] = [];
    const s = await runVendorAlerts(env(fakeDb({}), "https://hooks.example.com/x"), { fetchImpl: fetchWith(calls, rows, 500), now: NOW, log: () => {} });
    expect(s.delivered).toBe("failed");
  });
});

// 2026-10-18: a vendor that rejects the key is named as such — the fix is a new key, not a wait.
describe("rejected keys", () => {
  it("says the key was rejected when most checks without a verdict were 401/403", () => {
    expect(keyRejected({ noVerdict: 4, authFailed: 3 })).toBe(true);
    expect(keyRejected({ noVerdict: 4, authFailed: 2 })).toBe(false); // half: the outage reads as an outage
    expect(keyRejected({ noVerdict: 0, authFailed: 0 })).toBe(false);
    const t = alertText([{ provider: "cato-ai-security", from: "ok", to: "down", checked: 12, noVerdict: 12, authFailed: 12 }]);
    expect(t).toContain("Cato Networks AI Security REJECTED THE KEY: 12 of 12 checks got HTTP 401/403 in the last 1h.");
    expect(t).toContain("Settings → Cato Networks AI Security");
    expect(alertText([{ provider: "cato-ai-security", from: "ok", to: "down", checked: 12, noVerdict: 12, authFailed: 2 }])).toContain("looks DOWN");
  });
  it("reads 401s from Analytics Engine into the message", async () => {
    const ae = Array.from({ length: 4 }, () => ({
      ts: "2026-10-12 09:50:00", si: 1, src: "scheduled", dir: "prompt", provider: "cato-ai-security", outcome: "failed_open",
      detected: "", ray: "", scan_id: "", mode: "parallel", action: "", expect: "", ms: 300, status: 401, alerts: 0,
      redaction: 0, incomplete: 0, decided: 0, applied: 0,
    }));
    const lines: Record<string, unknown>[] = [];
    const db = {
      prepare: () => ({ bind: () => ({}), all: async () => ({ results: [{ provider: "cato-ai-security", state: "ok" }] }) }),
      batch: async () => [],
    };
    const s = await runVendorAlerts({ CF_ANALYTICS_TOKEN: "t", CF_ACCOUNT_ID: "a", DB: db } as unknown as Env, {
      fetchImpl: (async () => Response.json({ data: ae })) as unknown as typeof fetch,
      now: Date.parse("2026-10-12T10:17:00Z"),
      log: (l) => lines.push(l as Record<string, unknown>),
    });
    expect(s.vendors).toEqual([{ provider: "cato-ai-security", state: "down", checked: 4, noVerdict: 4, authFailed: 4 }]);
    expect(String(lines.find((l) => l.event === "guardrail_alert")?.text)).toContain("REJECTED THE KEY");
  });
});
