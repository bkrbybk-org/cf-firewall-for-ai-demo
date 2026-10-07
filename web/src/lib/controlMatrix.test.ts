import { describe, expect, it } from "vitest";
import { controlMatrix, type ControlMatrixInput } from "./controlMatrix";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "./types";

const R = (o: Partial<ExternalGuardrailResult> & Pick<ExternalGuardrailResult, "provider" | "outcome">): ExternalGuardrailResult => ({
  latencyMs: 100,
  ...o,
});
const P = (o: Partial<GuardrailPipelineResult>): GuardrailPipelineResult => ({
  mode: "sequential",
  guardrailOnly: false,
  results: [],
  notRun: [],
  stoppedBy: null,
  latencyMs: 100,
  ...o,
});
const m = (i: Partial<ControlMatrixInput> & Pick<ControlMatrixInput, "kind">) =>
  controlMatrix({ route: "direct", edge: "allow", ...i });
const byKey = (cells: ReturnType<typeof controlMatrix>) => Object.fromEntries(cells.map((c) => [c.key, c]));

describe("controlMatrix — the edge", () => {
  it("a 403 is a WAF block only once the edge verdict says so", () => {
    expect(byKey(m({ kind: "blocked", edge: "block" })).edge).toMatchObject({ state: "stopped", stateLabel: "stopped", decisive: true });
    expect(byKey(m({ kind: "blocked", edge: "pending" })).edge).toMatchObject({ state: "stopped", stateLabel: "refused (403)" });
    expect(byKey(m({ kind: "blocked", edge: "unavailable" })).edge.stateLabel).toBe("refused (403)");
    // No blocking WAF rule behind a 403: something else (Access) refused it.
    expect(byKey(m({ kind: "blocked", edge: "denied" })).edge.stateLabel).toBe("refused · not WAF");
  });

  it("a request that reached the Worker passed the edge — logged or not", () => {
    expect(byKey(m({ kind: "assistant", edge: "allow" })).edge).toMatchObject({ state: "passed", decisive: false });
    expect(byKey(m({ kind: "assistant", edge: "log" })).edge).toMatchObject({ state: "flagged", stateLabel: "logged · passed" });
    // The 200 is ground truth: even a verdict claiming "block" cannot make it a stop.
    expect(byKey(m({ kind: "external", edge: "block" })).edge.state).toBe("passed");
  });
});

describe("controlMatrix — nothing is credited past the point the prompt reached", () => {
  it("an edge refusal leaves every later layer not reached", () => {
    const c = byKey(m({ kind: "blocked", edge: "block", route: "gateway", guarded: true }));
    expect(c.ext.state).toBe("notReached");
    expect(c.aig.state).toBe("notReached");
    expect(c.model.state).toBe("notReached");
    expect(Object.values(c).filter((x) => x.decisive).map((x) => x.key)).toEqual(["edge"]);
  });

  it("an external block stops there; Gateway Guardrails and the model are not reached", () => {
    const pipeline = P({ results: [R({ provider: "prisma-airs", outcome: "block", detected: ["dlp"] })], stoppedBy: "prisma-airs" });
    const c = byKey(m({ kind: "external", pipeline, route: "gateway", guarded: true }));
    expect(c["ext:prisma-airs"]).toMatchObject({ state: "stopped", stateLabel: "blocked", decisive: true });
    expect(c["ext:prisma-airs"].detail).toContain("dlp");
    expect(c.aig.state).toBe("notReached");
    expect(c.model.state).toBe("notReached");
  });

  it("sequential notRun is 'did not run', parallel two-block marks both decisive", () => {
    const seq = byKey(
      m({
        kind: "external",
        pipeline: P({
          results: [R({ provider: "crowdstrike-aidr", outcome: "block" })],
          notRun: [{ provider: "prisma-airs", reason: "an earlier guardrail stopped the turn" }],
          stoppedBy: "crowdstrike-aidr",
        }),
      }),
    );
    expect(seq["ext:prisma-airs"]).toMatchObject({ state: "notReached", stateLabel: "did not run", decisive: false });
    const par = byKey(
      m({
        kind: "external",
        pipeline: P({
          mode: "parallel",
          results: [R({ provider: "crowdstrike-aidr", outcome: "block" }), R({ provider: "prisma-airs", outcome: "block" })],
          stoppedBy: "crowdstrike-aidr",
        }),
      }),
    );
    expect([par["ext:crowdstrike-aidr"].decisive, par["ext:prisma-airs"].decisive]).toEqual([true, true]);
  });
});

describe("controlMatrix — an error is never a verdict", () => {
  it("fail closed: unavailable and decisive, never 'blocked'", () => {
    const c = byKey(
      m({ kind: "external", pipeline: P({ results: [R({ provider: "prisma-airs", outcome: "error", detected: ["dlp"] })], stoppedBy: "prisma-airs" }) }),
    );
    expect(c["ext:prisma-airs"]).toMatchObject({ state: "unavailable", stateLabel: "no verdict · fail closed", decisive: true });
    expect(c["ext:prisma-airs"].detail).not.toContain("dlp");
  });

  it("fail open: unavailable, not decisive, and the turn went on", () => {
    const c = byKey(m({ kind: "assistant", pipeline: P({ results: [R({ provider: "prisma-airs", outcome: "error", failedOpen: true })] }) }));
    expect(c["ext:prisma-airs"]).toMatchObject({ state: "unavailable", decisive: false });
    expect(c.model.state).toBe("reached");
  });

  it("Detect-mode alerts are flagged, not passed and not stopped", () => {
    const c = byKey(m({ kind: "assistant", pipeline: P({ results: [R({ provider: "lakera-guard", outcome: "allow", detectOnly: true, detected: ["prompt_attack"] })] }) }));
    expect(c["ext:lakera-guard"]).toMatchObject({ state: "flagged", stateLabel: "alerts only", decisive: false });
  });
});

describe("controlMatrix — layers that were off", () => {
  it("direct route has no gateway; an unguarded gateway checked nothing; none enabled is off", () => {
    expect(byKey(m({ kind: "assistant", route: "direct" })).aig).toMatchObject({ state: "off", stateLabel: "n/a · direct" });
    expect(byKey(m({ kind: "assistant", route: "gateway", guarded: false })).aig.state).toBe("off");
    expect(byKey(m({ kind: "assistant", route: "gateway", guarded: true })).aig.state).toBe("passed");
    expect(byKey(m({ kind: "assistant" })).ext.state).toBe("off");
  });

  it("Gateway Guardrails: prompt block stops before the model; response block means the model answered", () => {
    const p = byKey(m({ kind: "guardrails", route: "gateway", guarded: true, guardrailsDirection: "prompt" }));
    expect(p.aig).toMatchObject({ state: "stopped", decisive: true });
    expect(p.model.state).toBe("notReached");
    const r = byKey(m({ kind: "guardrails", route: "gateway", guarded: true, guardrailsDirection: "response" }));
    expect(r.model).toMatchObject({ state: "reached", stateLabel: "answered · withheld" });
  });

  it("guardrail-only: the model is skipped, not reached and not answered", () => {
    const c = byKey(m({ kind: "guardrailOnly", pipeline: P({ guardrailOnly: true, results: [R({ provider: "prisma-airs", outcome: "allow" })] }) }));
    expect(c.model).toMatchObject({ state: "off", stateLabel: "skipped" });
    expect(c["ext:prisma-airs"].state).toBe("passed");
  });
});

describe("controlMatrix — the reply check (design J)", () => {
  const prompt = P({ results: [R({ provider: "prisma-airs", outcome: "allow" })] });
  const reply = P({
    direction: "reply",
    stoppedBy: "prisma-airs",
    results: [R({ provider: "prisma-airs", outcome: "block", detected: ["dlp"] })],
    notRun: [{ provider: "cato-ai-security", reason: "Not run: Cato Networks AI Security does not check replies here" }],
  });

  it("a withheld reply: the model answered, the reply check stopped it, and it is worded for the reply", () => {
    const c = byKey(m({ kind: "replyWithheld", pipeline: prompt, replyPipeline: reply }));
    expect(c["ext:prisma-airs"]).toMatchObject({ layer: "external", state: "passed", detail: "Prisma AIRS allowed the prompt." });
    expect(c.model).toMatchObject({ state: "reached", stateLabel: "answered · withheld" });
    expect(c["reply:prisma-airs"]).toMatchObject({
      layer: "replyCheck",
      label: "Prisma AIRS (reply)",
      state: "stopped",
      decisive: true,
      detail: "Prisma AIRS (reply) blocked the reply (dlp).",
    });
    // A guardrail that cannot check replies is "did not run", never a pass.
    expect(c["reply:cato-ai-security"]).toMatchObject({ state: "notReached", stateLabel: "did not run" });
    // The reply check comes after the model.
    const keys = m({ kind: "replyWithheld", pipeline: prompt, replyPipeline: reply }).map((x) => x.key);
    expect(keys.indexOf("reply:prisma-airs")).toBeGreaterThan(keys.indexOf("model"));
  });

  it("no reply check → no reply cells at all, never an empty pass", () => {
    expect(m({ kind: "assistant", pipeline: prompt }).some((x) => x.layer === "replyCheck")).toBe(false);
  });
});
