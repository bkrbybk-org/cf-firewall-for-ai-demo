// Verdict changes on the scheduled prompts (2026-10-18). Pinned: a change is announced only after it holds for two runs
// in a row; an error is never a verdict and neither confirms nor clears; a first sighting is recorded, not announced;
// the message names vendor, prompt id and label only; and a missing table skips without failing the re-run.
import { describe, expect, it } from "vitest";
import type { Env, ExternalGuardrailResult, GuardrailPipelineResult } from "./types";
import { changeText, observedOf, runVerdictWatch, step, watchKey, type Observed, type Watched } from "./verdictWatch";

const T0 = Date.parse("2026-10-12T12:00:00Z");
const k = (w: Watched) => `${w.provider}|${w.promptId}`;
const obs = (outcome: "block" | "allow", promptId = "v1/han-600"): Observed => ({ provider: "lakera-guard", promptId, outcome });

describe("step", () => {
  it("records a first sighting without announcing it", () => {
    const r = step(new Map(), [obs("allow")], T0);
    expect(r.changes).toEqual([]);
    expect(r.writes).toEqual([{ provider: "lakera-guard", promptId: "v1/han-600", outcome: "allow", since: T0, pending: null }]);
  });

  it("holds a new verdict as pending on the first run, announces it on the second, with the old verdict's start", () => {
    let stored = new Map<string, Watched>();
    const apply = (o: Observed[], now: number) => {
      const r = step(stored, o, now);
      stored = new Map(r.writes.map((w) => [k(w), w]));
      return r;
    };
    apply([obs("allow")], T0);
    const first = apply([obs("block")], T0 + 6 * 3_600_000);
    expect(first.changes).toEqual([]);
    expect([...stored.values()][0]).toMatchObject({ outcome: "allow", pending: "block", since: T0 });
    const second = apply([obs("block")], T0 + 12 * 3_600_000);
    expect(second.changes).toEqual([{ provider: "lakera-guard", promptId: "v1/han-600", from: "allow", to: "block", heldSince: T0 }]);
    expect([...stored.values()][0]).toMatchObject({ outcome: "block", pending: null, since: T0 + 12 * 3_600_000 });
    // And it stays quiet while the new verdict holds.
    expect(apply([obs("block")], T0 + 18 * 3_600_000).changes).toEqual([]);
  });

  it("a return to the old verdict clears a pending one: one noisy answer is never an alert", () => {
    const s: Watched = { provider: "lakera-guard", promptId: "v1/han-600", outcome: "allow", since: T0, pending: "block" };
    const r = step(new Map([[k(s), s]]), [obs("allow")], T0 + 1);
    expect(r.changes).toEqual([]);
    expect(r.writes[0].pending).toBeNull();
  });

  it("a run without a verdict for the pair (an error) leaves it untouched — pending survives to the next verdict", () => {
    const s: Watched = { provider: "lakera-guard", promptId: "v1/han-600", outcome: "allow", since: T0, pending: "block" };
    const stored = new Map([[k(s), s]]);
    expect(step(stored, [], T0 + 1)).toEqual({ writes: [], changes: [] });
    expect(step(stored, [obs("block")], T0 + 2).changes).toHaveLength(1);
  });
});

describe("observedOf", () => {
  const pipe = (results: ExternalGuardrailResult[]): GuardrailPipelineResult => ({
    mode: "parallel", guardrailOnly: true, results, notRun: [], stoppedBy: null, latencyMs: 0,
  });
  it("keeps block and allow only, keyed by the set's version — an error or fail-open is not a verdict", () => {
    const o = observedOf([
      {
        id: "rt-03",
        pipeline: pipe([
          { provider: "prisma-airs", outcome: "block", latencyMs: 1 },
          { provider: "lakera-guard", outcome: "allow", latencyMs: 1 },
          { provider: "cato-ai-security", outcome: "error", failedOpen: true, latencyMs: 1 },
          { provider: "cisco-ai-defense", outcome: "error", latencyMs: 1 },
        ]),
      },
      { id: "han-0", pipeline: null },
    ]);
    expect(o).toEqual([
      { provider: "prisma-airs", promptId: "v1/rt-03", outcome: "block" },
      { provider: "lakera-guard", promptId: "v1/rt-03", outcome: "allow" },
    ]);
    expect(watchKey("han-600")).toBe("v1/han-600");
  });
});

describe("changeText", () => {
  it("says what each change means for the demo, by prompt id and label — never the prompt's text", () => {
    const t = changeText([
      { provider: "lakera-guard", promptId: "v1/han-600", from: "allow", to: "block", heldSince: T0 },
      { provider: "lakera-guard", promptId: "v1/rt-03", from: "allow", to: "block", heldSince: T0 },
      { provider: "cisco-ai-defense", promptId: "v1/rt-01", from: "block", to: "allow", heldSince: T0 },
      { provider: "prisma-airs", promptId: "v1/han-0", from: "block", to: "allow", heldSince: T0 },
    ]);
    expect(t).toContain("Check Point Lakera Guard now BLOCKS harmless prompt han-600 — a new false block (it had allowed it since 2026-10-12).");
    expect(t).toContain("Check Point Lakera Guard now catches attack rt-03");
    expect(t).toContain("Cisco AI Defense now ALLOWS attack rt-01 — a new miss (it had blocked it since 2026-10-12).");
    expect(t).toContain("Palo Alto Networks Prisma AIRS no longer blocks harmless prompt han-0");
    expect(t).toContain("held for 2 runs in a row");
    expect(t).not.toMatch(/[฀-๿]/); // no Thai prompt text
  });
});

// A fake D1 for this one table: SELECT returns the rows; batch applies the upserts.
function fakeDb(initial: Watched[] = [], missing = false) {
  const rows = new Map(initial.map((w) => [k(w), { ...w, updated_at: 0 }]));
  return {
    rows,
    prepare: (sql: string) => {
      const stmt = {
        args: [] as unknown[],
        bind: (...a: unknown[]) => ({ ...stmt, args: a }),
        all: async () => {
          if (missing) throw new Error("D1_ERROR: no such table: guardrail_prompt_verdicts");
          return { results: [...rows.values()].map((r) => ({ provider: r.provider, prompt_id: r.promptId, outcome: r.outcome, since: r.since, pending: r.pending })) };
        },
        sql,
      };
      return stmt;
    },
    batch: async (stmts: { args: unknown[] }[]) => {
      for (const s of stmts) {
        const [provider, promptId, outcome, since, pending, updated] = s.args as [Watched["provider"], string, "block" | "allow", number, null, number];
        rows.set(`${provider}|${promptId}`, { provider, promptId, outcome, since, pending, updated_at: updated });
      }
      return [];
    },
  };
}

describe("runVerdictWatch", () => {
  const run = (outcome: "block" | "allow") => [
    {
      id: "han-600",
      pipeline: { mode: "parallel", guardrailOnly: true, results: [{ provider: "lakera-guard", outcome, latencyMs: 1 }], notRun: [], stoppedBy: null, latencyMs: 0 } as GuardrailPipelineResult,
    },
  ];
  const env = (db: ReturnType<typeof fakeDb>, hook?: string) => ({ DB: db, ALERT_WEBHOOK_URL: hook }) as unknown as Env;

  it("stores the run, then posts one message on the confirming run", async () => {
    const db = fakeDb([{ provider: "lakera-guard", promptId: "v1/han-600", outcome: "allow", since: T0, pending: null }]);
    const calls: { url: string; body: string }[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      calls.push({ url, body: String(init?.body) });
      return new Response("ok");
    }) as typeof fetch;
    const s1 = await runVerdictWatch(env(db, "https://hooks.example.com/x"), run("block"), { fetchImpl, now: T0 + 1, log: () => {} });
    expect(s1).toMatchObject({ observed: 1, changes: 0, pending: 1, delivered: "none" });
    expect(calls).toEqual([]);
    const s2 = await runVerdictWatch(env(db, "https://hooks.example.com/x"), run("block"), { fetchImpl, now: T0 + 2, log: () => {} });
    expect(s2).toMatchObject({ changes: 1, pending: 0, delivered: "webhook" });
    expect(calls).toHaveLength(1);
    const payload = JSON.parse(calls[0].body);
    expect(payload.verdictChanges).toEqual([
      { provider: "lakera-guard", promptId: "v1/han-600", from: "allow", to: "block", heldSince: T0, label: "Check Point Lakera Guard" },
    ]);
    expect(db.rows.get("lakera-guard|v1/han-600")).toMatchObject({ outcome: "block", pending: null, since: T0 + 2 });
  });

  it("with no webhook, logs the change and calls nothing", async () => {
    const db = fakeDb([{ provider: "lakera-guard", promptId: "v1/han-600", outcome: "allow", since: T0, pending: "block" }]);
    const lines: Record<string, unknown>[] = [];
    let called = false;
    const s = await runVerdictWatch(env(db), run("block"), {
      fetchImpl: (async () => ((called = true), new Response("ok"))) as typeof fetch,
      now: T0 + 1,
      log: (l) => lines.push(l as Record<string, unknown>),
    });
    expect(s).toMatchObject({ changes: 1, delivered: "log" });
    expect(called).toBe(false);
    expect(lines.some((l) => l.event === "guardrail_verdict_change" && String(l.note).includes("not set"))).toBe(true);
  });

  it("skips, without throwing, when the table is missing or there is no verdict", async () => {
    expect(await runVerdictWatch(env(fakeDb([], true)), run("block"), { log: () => {} })).toMatchObject({ skipped: expect.stringContaining("0012") });
    expect(await runVerdictWatch(env(fakeDb()), [{ id: "han-0", pipeline: null }], { log: () => {} })).toMatchObject({ skipped: "no verdicts this run" });
  });
});

// 2026-10-19: the reply pairs are watched too, and named as replies.
describe("changeText — reply pairs", () => {
  it("names a reply as a reply: a withheld harmless reply is a false block, an allowed PII reply a miss", () => {
    const t = changeText([
      { provider: "prisma-airs", promptId: "v1/reply-benign", from: "allow", to: "block", heldSince: T0 },
      { provider: "crowdstrike-aidr", promptId: "v1/reply-pii", from: "allow", to: "block", heldSince: T0 },
      { provider: "lakera-guard", promptId: "v1/reply-pii", from: "block", to: "allow", heldSince: T0 },
    ]);
    expect(t).toContain("Palo Alto Networks Prisma AIRS now BLOCKS harmless reply reply-benign — a new false block");
    expect(t).toContain("CrowdStrike Falcon AIDR now catches the PII reply reply-pii");
    expect(t).toContain("Check Point Lakera Guard now ALLOWS the PII reply reply-pii — a new miss");
    expect(t).not.toContain("078-05-1120"); // ids only, never the reply's text
  });
});
