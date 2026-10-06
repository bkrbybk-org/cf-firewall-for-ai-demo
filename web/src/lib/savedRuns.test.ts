import { describe, expect, it } from "vitest";
import { buildRunSaveRequest, summarizeDiff, toSavedRun, type RunContext } from "./savedRuns";
import { corpusFingerprint, diffRuns, type RedTeamAttack, type RtRunResult } from "./redteam";
import type { RedTeamResultRow, RedTeamRunRow } from "./types";

const A = (id: string, over: Partial<RedTeamAttack> = {}): RedTeamAttack => ({
  id,
  category: "Cat " + id,
  severity: "high",
  prompt: "prompt " + id,
  ...over,
});
const CORPUS = [A("rt-01"), A("rt-02"), A("rt-03")];

function ctx(over: Partial<RunContext> = {}): RunContext {
  return { corpusName: "AI Red Team Sample", corpus: CORPUS, fired: 3, route: "direct", delayMs: 0, ...over };
}
function results(entries: [string, RtRunResult["state"]][]): Map<string, RtRunResult> {
  return new Map(entries.map(([id, state]) => [id, { id, state, ray: "ray-" + id, ts: 1 }]));
}

describe("buildRunSaveRequest", () => {
  it("returns null when there is nothing to save", () => {
    expect(buildRunSaveRequest(ctx(), new Map())).toBeNull();
  });

  it("saves every scoreRun total, including external and skipped", () => {
    const r = results([
      ["rt-01", "allow"],
      ["rt-02", "external"],
      ["rt-03", "block"],
    ]);
    r.get("rt-01")!.modelSkipped = true;
    const req = buildRunSaveRequest(ctx(), r)!;
    expect(req).toMatchObject({ total: 3, scored: 2, reached: 1, stopped: 1, external: 1, skipped: 1, reachedPct: 50 });
  });

  it("fingerprints the attacks that have a result, and says when that is a subset", () => {
    const req = buildRunSaveRequest(ctx({ fired: 2 }), results([["rt-01", "allow"], ["rt-03", "block"]]))!;
    expect(req.corpusFingerprint).toBe(corpusFingerprint([CORPUS[0], CORPUS[2]]));
    expect(req.corpusFingerprint).not.toBe(corpusFingerprint(CORPUS));
    expect(req.corpusName).toBe("AI Red Team Sample (2 of 3)");
    expect(req.corpusSize).toBe(2);
  });

  it("never saves a harmless (expected=allow) row — it would be stored as a gap", () => {
    const corpus = [...CORPUS, A("csv-9", { expected: "allow" })];
    const req = buildRunSaveRequest(
      ctx({ corpus }),
      results([...CORPUS.map((a): [string, RtRunResult["state"]] => [a.id, "block"]), ["csv-9", "allow"]]),
    )!;
    expect(req.results.map((r) => r.attackId)).toEqual(["rt-01", "rt-02", "rt-03"]);
    expect(req).toMatchObject({ total: 3, reached: 0, stopped: 3 });
    // A full run of the attacks is not a "partial" one just because harmless rows existed.
    expect(req.corpusName).toBe("AI Red Team Sample");
    expect(req.corpusFingerprint).toBe(corpusFingerprint(CORPUS));
  });

  it("keeps the plain corpus name and fingerprint for a full run", () => {
    const req = buildRunSaveRequest(ctx(), results(CORPUS.map((a) => [a.id, "block"])))!;
    expect(req.corpusName).toBe("AI Red Team Sample");
    expect(req.corpusFingerprint).toBe(corpusFingerprint(CORPUS));
  });

  it("drops gateway-only fields on the direct route", () => {
    const req = buildRunSaveRequest(
      ctx({ route: "direct", gatewayId: "gw", guarded: true, dynamicRoute: "demo" }),
      results([["rt-01", "allow"]]),
    )!;
    expect(req).toMatchObject({ gatewayId: null, guarded: false, dynamicRoute: null });
  });

  it("sends the prompt for server-side redaction, with the attackKey join key", () => {
    const req = buildRunSaveRequest(ctx(), results([["rt-02", "log"]]))!;
    expect(req.results).toEqual([
      { attackKey: "rt-02", attackId: "rt-02", category: "Cat rt-02", severity: "high", state: "log", ray: "ray-rt-02", ts: 1, prompt: "prompt rt-02" },
    ]);
  });
});

describe("toSavedRun → diffRuns", () => {
  const row = (id: number, fp: string): RedTeamRunRow => ({
    id,
    ts: id,
    label: null,
    route: "direct",
    gatewayId: null,
    guarded: 0,
    model: null,
    dynamicRoute: null,
    corpusName: "x",
    corpusSize: 2,
    corpusFingerprint: fp,
    delayMs: 0,
    total: 2,
    scored: 2,
    reached: 0,
    stopped: 0,
    denied: 0,
    guardrails: 0,
    external: 0,
    skipped: 0,
    pending: 0,
    error: 0,
    reachedPct: 0,
  });
  const res = (key: string, state: string, severity: string | null = "high"): RedTeamResultRow => ({
    attackKey: key,
    attackId: key,
    category: "c",
    severity,
    state,
    ray: null,
    ts: null,
    promptPreview: null,
  });

  it("a saved before/after pair diffs on the shared attacks", () => {
    const before = toSavedRun(row(1, "f"), [res("a", "allow"), res("b", "allow")]);
    const after = toSavedRun(row(2, "f"), [res("a", "block"), res("b", "allow")]);
    const d = diffRuns(before, after);
    expect(d.comparable).toBe(true);
    expect(d.reachedDelta).toBe(-1);
  });

  it("summarizeDiff credits each closed gap to the control that closed it", () => {
    const before = toSavedRun(row(1, "f"), [res("a", "allow"), res("b", "log"), res("c", "allow"), res("d", "block")]);
    const after = toSavedRun(row(2, "f"), [res("a", "block"), res("b", "external"), res("c", "guardrails"), res("d", "allow")]);
    expect(summarizeDiff(diffRuns(before, after))).toEqual({
      closed: { edge: 1, external: 1, guardrails: 1 },
      closedTotal: 3,
      opened: 1,
      lostVerdict: 0,
      otherChanges: 0,
    });
  });

  it("a verdict that never resolved is not a fix, though reachedDelta drops", () => {
    const before = toSavedRun(row(1, "f"), [res("a", "allow"), res("b", "allow")]);
    const after = toSavedRun(row(2, "f"), [res("a", "pending"), res("b", "error")]);
    const d = diffRuns(before, after);
    expect(d.reachedDelta).toBe(-2); // the trap: reads like two fixes
    expect(summarizeDiff(d)).toMatchObject({ closedTotal: 0, lostVerdict: 2, opened: 0 });
  });

  it("stopped by one control, then another, is neither closed nor opened", () => {
    const before = toSavedRun(row(1, "f"), [res("a", "external"), res("b", "pending")]);
    const after = toSavedRun(row(2, "f"), [res("a", "block"), res("b", "block")]);
    expect(summarizeDiff(diffRuns(before, after))).toMatchObject({ closedTotal: 0, opened: 0, otherChanges: 2 });
  });

  it("an unknown severity becomes null, not a made-up label", () => {
    expect(toSavedRun(row(1, "f"), [res("a", "allow", "extreme")]).results[0].severity).toBeNull();
  });
});
