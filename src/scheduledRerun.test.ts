// The scheduled re-run (#15): what it sends, how it labels it, and that it never touches the model or the edge.
import { describe, expect, it } from "vitest";
import { encryptSecret } from "./externalGuardrails";
import { AE_SCHEMA } from "./guardrailLog";
import { SCHEDULED_PROMPTS } from "./scheduledCorpus";
import { RERUN_GAP_MS, runScheduledRerun, scheduledRunId } from "./scheduledRerun";
import type { Env } from "./types";

const SECRET = btoa(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i + 1)));

async function envWith(enabled: boolean, pipeline: Record<string, unknown> | null = null) {
  const points: AnalyticsEngineDataPoint[] = [];
  const row = {
    provider: "lakera-guard",
    enabled: enabled ? 1 : 0,
    region: "global",
    profile_name: "proj",
    fail_mode: "allow",
    api_key_enc: await encryptSecret("k", SECRET, "lakera-guard"),
    api_key_last4: "k",
    updated_at: 1,
  };
  const env = {
    GUARDRAIL_SECRET_KEY: SECRET,
    GUARDRAIL_VERDICTS: { writeDataPoint: (p: AnalyticsEngineDataPoint) => points.push(p) },
    DB: {
      prepare: (sql: string) => ({
        first: async () => (sql.includes("guardrail_pipeline") ? pipeline : null),
        all: async () => ({ results: enabled ? [row] : [] }),
      }),
    },
  } as unknown as Env;
  return { env, points };
}

describe("runScheduledRerun", () => {
  it("does nothing, and says so, with no external guardrail enabled", async () => {
    const { env, points } = await envWith(false);
    const lines: unknown[] = [];
    const s = await runScheduledRerun(env, { log: (l) => lines.push(l), sleep: async () => {} });
    expect(s).toMatchObject({ prompts: 0, vendors: 0, skipped: "no external guardrail enabled" });
    expect(points).toEqual([]);
    expect(lines).toHaveLength(1);
  });

  it("sends all 12 prompts to the vendors only — labelled, 'scheduled', parallel even when chat is sequential", async () => {
    const { env, points } = await envWith(true, { mode: "sequential", guardrail_only: 0, provider_order: "" });
    const urls: string[] = [];
    const fetchImpl = (async (url: string) => {
      urls.push(url);
      return Response.json({ flagged: false, metadata: { request_uuid: "u" } });
    }) as typeof fetch;
    const sleeps: number[] = [];
    const s = await runScheduledRerun(env, { fetchImpl, log: () => {}, sleep: async (ms) => void sleeps.push(ms) });
    expect(s).toMatchObject({ prompts: 12, vendors: 1, setVersion: 1 });
    // Only the vendor's host: no model, no edge, nothing else.
    expect(urls).toHaveLength(12);
    expect(urls.every((u) => u.startsWith("https://api.lakera.ai/"))).toBe(true);
    expect(sleeps).toEqual(Array(11).fill(RERUN_GAP_MS));
    // One data point per prompt (one vendor), in the AE schema: source "scheduled", mode "parallel", the label.
    expect(points).toHaveLength(12);
    const blobs = points.map((p) => p.blobs as string[]);
    expect(blobs.every((b) => b[0] === AE_SCHEMA && b[1] === "scheduled" && b[8] === "parallel")).toBe(true);
    expect(blobs.map((b) => b[10])).toEqual(SCHEDULED_PROMPTS.map((p) => p.expect));
    expect(blobs.filter((b) => b[10] === "attack")).toHaveLength(6);
    // A run id per prompt, never a real ray (those are hex only).
    const ids = blobs.map((b) => b[6]);
    expect(new Set(ids).size).toBe(12);
    expect(ids.every((id) => /^sch[0-9a-f]{13}$/.test(id))).toBe(true);
  });

  it("an outage is recorded as a verdict row (failed_open here), never a skipped prompt", async () => {
    const { env, points } = await envWith(true);
    const down = (async () => {
      throw new TypeError("down");
    }) as typeof fetch;
    await runScheduledRerun(env, { fetchImpl: down, log: () => {}, sleep: async () => {} });
    expect(points.map((p) => (p.blobs as string[])[4])).toEqual(Array(12).fill("failed_open"));
  });

  it("run ids start 'sch' and fit the ray column's shape", () => {
    expect(scheduledRunId()).toMatch(/^sch[0-9a-f]{13}$/);
  });
});
