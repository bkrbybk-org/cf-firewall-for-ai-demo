// The smoke canary (2026-10-19, after Open bugs #32). Pinned: the smoke script sends exactly the prompt the re-run
// watches; a block is announced on the FIRST run that shows it (and a first sighting that is already a block too), a
// clear when it lifts, never an error; and the drift watch's counts leave the canary out.
import { describe, expect, it } from "vitest";
import smokeScript from "../scripts/prod-smoke.sh?raw";
import { CANARY_ID, SMOKE_PROMPT } from "./smokeCanary";
import type { Env, GuardrailPipelineResult } from "./types";
import { canaryStatus, canaryStep, canaryText, runCanaryWatch, watchStatus, type Watched } from "./verdictWatch";

const T0 = Date.parse("2026-10-19T06:00:00Z");
const row = (provider: Watched["provider"], outcome: "block" | "allow"): Watched => ({ provider, promptId: CANARY_ID, outcome, since: T0, pending: null });
const stored = (...rows: Watched[]) => new Map(rows.map((r) => [`${r.provider}|${CANARY_ID}`, r]));
const obs = (provider: Watched["provider"], outcome: "block" | "allow") => ({ provider, promptId: CANARY_ID, outcome });

describe("the smoke script and the canary", () => {
  it("send the same prompt — the script's copy is pinned to SMOKE_PROMPT", () => {
    const m = smokeScript.match(/^SMOKE_PROMPT="([^"]*)"$/m);
    expect(m?.[1]).toBe(SMOKE_PROMPT);
    // And checks [2] and [3] really send it, and really require a reply.
    expect(smokeScript.match(/\\"prompt\\":\\"\$\{SMOKE_PROMPT\}\\"/g)).toHaveLength(2);
    expect(smokeScript.match(/^replied "POST \/api\/chat \((direct|gateway)\)"/gm)).toHaveLength(2);
  });
});

describe("canaryStep", () => {
  it("announces a block on the first run that shows it — no second run awaited", () => {
    const r = canaryStep(stored(row("lakera-guard", "allow")), [obs("lakera-guard", "block")], T0 + 1);
    expect(r.changes).toEqual([{ provider: "lakera-guard", from: "allow", to: "block" }]);
    expect(r.writes[0]).toMatchObject({ outcome: "block", since: T0 + 1, pending: null });
  });
  it("announces a first sighting only when it is already a block", () => {
    const r = canaryStep(new Map(), [obs("lakera-guard", "block"), obs("prisma-airs", "allow")], T0);
    expect(r.changes).toEqual([{ provider: "lakera-guard", from: null, to: "block" }]);
    expect(r.writes).toHaveLength(2);
  });
  it("announces the clear, and stays quiet while nothing changes", () => {
    expect(canaryStep(stored(row("lakera-guard", "block")), [obs("lakera-guard", "allow")], T0 + 1).changes).toEqual([
      { provider: "lakera-guard", from: "block", to: "allow" },
    ]);
    const same = canaryStep(stored(row("lakera-guard", "block")), [obs("lakera-guard", "block")], T0 + 1);
    expect(same.changes).toEqual([]);
    expect(same.writes[0].since).toBe(T0); // still blocked since the first run
  });
  it("says what will break and where the prompt lives", () => {
    const t = canaryText([{ provider: "lakera-guard", from: "allow", to: "block" }]);
    expect(t).toContain("Check Point Lakera Guard now BLOCKS the smoke prompt — npm run smoke:prod checks [2] and [3] will fail");
    expect(t).toContain("src/smokeCanary.ts");
    expect(t).not.toContain(SMOKE_PROMPT); // names and counts only
  });
});

function fakeDb(rows: Watched[] = []) {
  const table = new Map(rows.map((r) => [`${r.provider}|${r.promptId}`, r]));
  return {
    table,
    prepare: (sql: string) => {
      const stmt = (args: unknown[]) => ({
        sql,
        args,
        bind: (...a: unknown[]) => stmt(a),
        all: async () => ({
          results: [...table.values()]
            .filter((r) => !/prompt_id = \?/.test(sql) || r.promptId === args[0])
            .map((r) => ({ provider: r.provider, prompt_id: r.promptId, outcome: r.outcome, since: r.since, pending: r.pending })),
        }),
        first: async () => {
          const drift = [...table.values()].filter((r) => r.promptId !== args[0]);
          return { tracked: drift.length, pending: drift.filter((r) => r.pending).length };
        },
      });
      return stmt([]);
    },
    batch: async (stmts: { args: unknown[] }[]) => {
      for (const s of stmts) {
        const [provider, promptId, outcome, since] = s.args as [Watched["provider"], string, "block" | "allow", number];
        table.set(`${provider}|${promptId}`, { provider, promptId, outcome, since, pending: null });
      }
      return [];
    },
  };
}

const pipe = (results: GuardrailPipelineResult["results"]): GuardrailPipelineResult => ({
  mode: "parallel", guardrailOnly: true, results, notRun: [], stoppedBy: null, latencyMs: 0,
});

describe("runCanaryWatch", () => {
  it("stores the canary's verdicts, ignores errors, and posts once when a vendor starts blocking it", async () => {
    const db = fakeDb([row("lakera-guard", "allow"), { ...row("prisma-airs", "allow"), promptId: "v1/rt-01" }]);
    const bodies: string[] = [];
    const fetchImpl = (async (_u: string, init?: RequestInit) => (bodies.push(String(init?.body)), new Response("ok"))) as typeof fetch;
    const env = { DB: db, ALERT_WEBHOOK_URL: "https://hooks.example.com/x" } as unknown as Env;
    const s = await runCanaryWatch(
      env,
      pipe([
        { provider: "lakera-guard", outcome: "block", latencyMs: 1 },
        { provider: "cato-ai-security", outcome: "error", failedOpen: true, latencyMs: 1 },
      ]),
      { fetchImpl, now: T0 + 1, log: () => {} },
    );
    expect(s).toMatchObject({ observed: 1, changes: 1, blockedBy: ["lakera-guard"], delivered: "webhook" });
    expect(JSON.parse(bodies[0]).canaryChanges).toEqual([{ provider: "lakera-guard", from: "allow", to: "block", label: "Check Point Lakera Guard" }]);
    expect(db.table.has(`cato-ai-security|${CANARY_ID}`)).toBe(false); // an error is not a verdict
    expect(await canaryStatus(db as unknown as D1Database)).toEqual({ checked: ["lakera-guard"], blockedBy: ["lakera-guard"] });
    // The drift watch's count leaves the canary out.
    expect(await watchStatus(db as unknown as D1Database)).toEqual({ tracked: 1, pending: 0 });
  });
  it("skips without a verdict, without throwing", async () => {
    const env = { DB: fakeDb() } as unknown as Env;
    expect(await runCanaryWatch(env, null, { log: () => {} })).toMatchObject({ skipped: "no verdicts this run" });
  });
});
