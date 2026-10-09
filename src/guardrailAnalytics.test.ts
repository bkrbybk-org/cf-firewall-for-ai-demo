// Tests for /api/guardrail-analytics (src/guardrailAnalytics.ts). Every expected number below was worked out by
// hand from the fixture, so a passing test means the aggregation computes what the page claims — not just that
// it runs (CLAUDE.md: "running is not correct"). Also pinned: nothing a caller types reaches the SQL; a row of
// unknown shape is dropped, never counted; sampling and caps are reported; no data is never 0 ms; and an
// Analytics Engine error passes on its status only.
import { describe, expect, it } from "vitest";
import { ROW_CAP, aggregate, buildSql, handleGuardrailAnalytics, parseAeTime, parseRow, type VerdictRow } from "./guardrailAnalytics";
import type { Env } from "./types";

const NOW = Date.parse("2026-10-09T12:00:00Z");
// AE's DateTime, as the SQL API returns it: "YYYY-MM-DD HH:MM:SS" in UTC.
const at = (iso: string) => new Date(iso).toISOString().slice(0, 19).replace("T", " ");

// Raw rows as the AE SQL API returns them (numbers may come back as numbers or strings).
function raw(over: Record<string, unknown>) {
  return {
    ts: at("2026-10-09T10:15:00Z"), si: 1, src: "chat", dir: "prompt", provider: "prisma-airs", outcome: "allow",
    detected: "", ray: "", scan_id: "", action: "", ms: 100, status: 200, alerts: 0, redaction: 0, incomplete: 0, decided: 0,
    ...over,
  };
}
const rows = (list: Record<string, unknown>[]) => list.map((r) => parseRow(raw(r))).filter((r): r is VerdictRow => r != null);

// Three turns. A: AIRS blocks, Lakera allows with an alert → a disagreement. B: both allow, Cato errors (fail
// closed) → no disagreement (an error is not a verdict). C: AIRS fails open, Lakera blocks → no disagreement
// (only one real verdict); C's reply: AIRS allows with a redaction.
const FIXTURE = [
  { ray: "aaa", provider: "prisma-airs", outcome: "block", ms: 100, decided: 1, ts: at("2026-10-09T10:15:00Z") },
  { ray: "aaa", provider: "lakera-guard", outcome: "allow", ms: 20, alerts: 1, detected: "pii", ts: at("2026-10-09T10:15:00Z") },
  { ray: "aaa", provider: "cato-ai-security", outcome: "not_run", ms: -1, status: 0, ts: at("2026-10-09T10:15:00Z") },
  { ray: "bbb", provider: "prisma-airs", outcome: "allow", ms: 300, ts: at("2026-10-09T11:05:00Z") },
  { ray: "bbb", provider: "lakera-guard", outcome: "allow", ms: 40, detected: "pii", ts: at("2026-10-09T11:05:00Z") },
  { ray: "bbb", provider: "cato-ai-security", outcome: "error", ms: 5000, detected: "SSN", ts: at("2026-10-09T11:05:00Z") },
  { ray: "ccc", provider: "prisma-airs", outcome: "failed_open", ms: 5000, ts: at("2026-10-09T11:40:00Z") },
  { ray: "ccc", provider: "lakera-guard", outcome: "block", ms: 60, decided: 1, detected: "prompt_attack", ts: at("2026-10-09T11:40:00Z") },
  { ray: "ccc", dir: "reply", provider: "prisma-airs", outcome: "allow", ms: 200, redaction: 1, ts: at("2026-10-09T11:41:00Z") },
];

describe("buildSql", () => {
  it("reads our schema's rows in the window, with the source filter, capped", () => {
    const sql = buildSql(24, "chat");
    expect(sql).toContain("FROM cf_ai_waf_demo_guardrail_verdicts");
    expect(sql).toContain("WHERE blob1 = 'gv1' AND timestamp > NOW() - INTERVAL '24' HOUR AND blob2 = 'chat'");
    expect(sql).toContain(`LIMIT ${ROW_CAP}`);
    expect(buildSql(168, "all")).not.toContain("blob2 =");
  });
  it("refuses anything but the fixed hours and sources — nothing typed reaches the SQL", () => {
    expect(() => buildSql(2 as never, "chat")).toThrow();
    expect(() => buildSql(24, "chat' OR 1=1 --" as never)).toThrow();
  });
});

describe("parseRow", () => {
  it("drops a row of unknown shape instead of guessing", () => {
    for (const bad of [{ provider: "acme" }, { outcome: "monitor" }, { dir: "both" }, { src: "scanner" }, { ts: "x" }]) {
      expect(parseRow(raw(bad)), JSON.stringify(bad)).toBeNull();
    }
    expect(parseRow(null)).toBeNull();
  });
  it("reads AE's UTC time strings, and nothing else as a time", () => {
    expect(parseAeTime("2026-10-09 08:34:31")).toBe(Date.parse("2026-10-09T08:34:31Z"));
    for (const bad of ["2026-10-09T08:34:31Z", 1791534871, "", null, "2026-10-09 08:34"]) expect(parseAeTime(bad)).toBeNaN();
  });
  it("reads numbers sent as strings, -1 latency as none, and refuses odd names and rays", () => {
    const r = parseRow(raw({ ts: at("2026-10-09T10:00:00Z"), ms: "87", si: "2", detected: "jailbreak,bad name!,us_ssn", ray: "abc<x>" }))!;
    expect(r).toMatchObject({ ts: Date.parse("2026-10-09T10:00:00Z"), ms: 87, si: 2, detected: ["jailbreak", "us_ssn"], ray: null });
    expect(parseRow(raw({ outcome: "not_run", ms: -1 }))!.ms).toBeNull();
    expect(parseRow(raw({ si: 0 }))!.si).toBe(1);
  });
});

describe("aggregate — hand-computed", () => {
  const out = aggregate(rows(FIXTURE), { hours: 24, now: NOW, source: "chat", rowsRead: FIXTURE.length, rowsDropped: 0 });
  const v = (provider: string, dir = "prompt") => out.vendors.find((x) => x.provider === provider && x.dir === dir)!;

  it("counts each vendor's verdicts by outcome", () => {
    expect(v("prisma-airs")).toMatchObject({ checked: 3, block: 1, allow: 1, failedOpen: 1, error: 0, notRun: 0, decided: 1 });
    expect(v("lakera-guard")).toMatchObject({ checked: 3, block: 1, allow: 2, alerts: 1, error: 0, decided: 1 });
    expect(v("cato-ai-security")).toMatchObject({ checked: 1, error: 1, notRun: 1, block: 0, allow: 0 });
    expect(v("prisma-airs", "reply")).toMatchObject({ checked: 1, allow: 1, redaction: 1 });
  });

  it("latency is nearest rank over the verdicts that ran: [100, 300, 5000] → p50 300, p95 5000", () => {
    expect(v("prisma-airs")).toMatchObject({ latencyN: 3, p50Ms: 300, p95Ms: 5000 });
    expect(v("lakera-guard")).toMatchObject({ latencyN: 3, p50Ms: 40, p95Ms: 60 });
    expect(v("cato-ai-security")).toMatchObject({ latencyN: 1, p50Ms: 5000, p95Ms: 5000 }); // not_run has no latency
  });

  it("top detections come from verdicts only — an error's names are not findings", () => {
    expect(v("lakera-guard").topDetections).toEqual([
      { name: "pii", count: 2 },
      { name: "prompt_attack", count: 1 },
    ]);
    expect(v("cato-ai-security").topDetections).toEqual([]);
  });

  it("totals: 3 turns, 8 verdicts (not_run excluded), 2 blocks, 1 alert, 1 error, 1 failed open", () => {
    expect(out.totals).toEqual({ turns: 3, verdicts: 8, block: 2, alerts: 1, error: 1, failedOpen: 1 });
    expect(out).toMatchObject({ sampled: false, capped: false, rangeHours: 24, source: "chat", bucket: "hour" });
  });

  it("vendors are in registry order, prompt before reply", () => {
    expect(out.vendors.map((x) => `${x.provider}:${x.dir}`)).toEqual([
      "prisma-airs:prompt",
      "prisma-airs:reply",
      "lakera-guard:prompt",
      "cato-ai-security:prompt",
    ]);
  });

  it("a disagreement needs a block AND an allow on the same text — errors and fail-opens are not verdicts", () => {
    expect(out.disagreements.count).toBe(1);
    expect(out.disagreements.latest[0]).toMatchObject({
      ray: "aaa",
      dir: "prompt",
      verdicts: [
        { provider: "prisma-airs", outcome: "block", alerts: false },
        { provider: "lakera-guard", outcome: "allow", alerts: true },
      ],
    });
  });

  it("series: every hour of the window prefilled, verdicts in their bucket, alerts apart from clean allows", () => {
    expect(out.series).toHaveLength(25); // 12:00 yesterday … 12:00 today, inclusive
    const at10 = out.series.find((p) => p.t === "2026-10-09T10:00:00.000Z")!;
    const at11 = out.series.find((p) => p.t === "2026-10-09T11:00:00.000Z")!;
    expect(at10).toEqual({ t: "2026-10-09T10:00:00.000Z", block: 1, alerts: 1, allow: 0, error: 0 });
    expect(at11).toEqual({ t: "2026-10-09T11:00:00.000Z", block: 1, alerts: 0, allow: 3, error: 2 });
    const total = out.series.reduce((n, p) => n + p.block + p.alerts + p.allow + p.error, 0);
    expect(total).toBe(out.totals.verdicts);
  });
});

describe("aggregate — latency edge cases", () => {
  // Bug #24's shape: at n = 2 nearest rank gives p50 = the LOWER value; truncation gave the upper one.
  it("n = 2 → p50 is the lower value, p95 the upper (nearest rank, not truncation)", () => {
    const out = aggregate(rows([{ provider: "lakera-guard", ms: 200 }, { provider: "lakera-guard", ms: 100 }]), {
      hours: 1, now: NOW, source: "chat", rowsRead: 2, rowsDropped: 0,
    });
    expect(out.vendors[0]).toMatchObject({ latencyN: 2, p50Ms: 100, p95Ms: 200 });
  });
  it("a vendor that only ever 'did not run' has no latency — null, never 0 ms", () => {
    const out = aggregate(rows([{ provider: "cisco-ai-defense", dir: "reply", outcome: "not_run", ms: -1 }]), {
      hours: 1, now: NOW, source: "chat", rowsRead: 1, rowsDropped: 0,
    });
    expect(out.vendors[0]).toMatchObject({ checked: 0, notRun: 1, latencyN: 0, p50Ms: null, p95Ms: null });
  });
});

describe("aggregate — honesty flags", () => {
  it("weights counts by _sample_interval and says the result is sampled", () => {
    const out = aggregate(rows([{ provider: "lakera-guard", outcome: "block", si: 10 }, { provider: "lakera-guard", outcome: "allow" }]), {
      hours: 1, now: NOW, source: "all", rowsRead: 2, rowsDropped: 0,
    });
    expect(out.sampled).toBe(true);
    expect(out.vendors[0]).toMatchObject({ checked: 11, block: 10, allow: 1, latencyN: 2 });
    expect(out.bucket).toBe("5m");
  });
  it("a full read is capped (a floor); an empty window has no vendors, no latency, and zero verdicts", () => {
    expect(aggregate([], { hours: 24, now: NOW, source: "chat", rowsRead: ROW_CAP, rowsDropped: 0 }).capped).toBe(true);
    const empty = aggregate([], { hours: 24, now: NOW, source: "chat", rowsRead: 0, rowsDropped: 0 });
    expect(empty).toMatchObject({ capped: false, sampled: false, vendors: [], disagreements: { count: 0, latest: [] } });
    expect(empty.totals.verdicts).toBe(0);
  });
});

describe("handleGuardrailAnalytics", () => {
  const env = (over: Partial<Env> = {}) => ({ CF_ANALYTICS_TOKEN: "t", CF_ACCOUNT_ID: "acct", ...over }) as Env;
  const url = (q = "") => new URL(`https://x/api/guardrail-analytics${q}`);

  it("not configured without the token or account", async () => {
    expect(await (await handleGuardrailAnalytics(url(), env({ CF_ANALYTICS_TOKEN: undefined }))).json()).toEqual({ configured: false });
  });

  it("queries the account's AE SQL API with the token, clamps bad params, and aggregates", async () => {
    let seen: { url: string; body: string; auth: string } | null = null;
    const fetchImpl = (async (u: string, init?: RequestInit) => {
      seen = { url: u, body: String(init!.body), auth: (init!.headers as Record<string, string>).authorization };
      return Response.json({ data: [raw({ provider: "lakera-guard", outcome: "block", ts: at(new Date(Date.now() - 60_000).toISOString()) }), raw({ provider: "acme" })] });
    }) as typeof fetch;
    const j = (await (await handleGuardrailAnalytics(url("?hours=5&source=evil"), env(), fetchImpl)).json()) as Record<string, unknown>;
    expect(seen!.url).toBe("https://api.cloudflare.com/client/v4/accounts/acct/analytics_engine/sql");
    expect(seen!.auth).toBe("Bearer t");
    expect(seen!.body).toContain("INTERVAL '24' HOUR AND blob2 = 'chat'"); // both bad params fell back
    expect(j).toMatchObject({ configured: true, rowsRead: 2, rowsDropped: 1, totals: { block: 1 } });
  });

  it("an AE error passes on its status only — the SQL API's text can echo the statement", async () => {
    const fetchImpl = (async () => new Response("syntax error near SELECT blob4 …", { status: 400 })) as typeof fetch;
    const res = await handleGuardrailAnalytics(url(), env(), fetchImpl);
    expect(res.status).toBe(502);
    const j = (await res.json()) as { error: string };
    expect(j.error).toBe("Analytics Engine returned HTTP 400");
    const denied = await handleGuardrailAnalytics(url(), env(), (async () => new Response("no", { status: 403 })) as typeof fetch);
    expect(((await denied.json()) as { error: string }).error).toMatch(/Account Analytics: Read/);
  });
});
