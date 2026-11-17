// Booth mode's architecture strip (2026-11-17): while waiting it may claim nothing about a layer; after the verdict
// it may claim only what the control strip does.
import { describe, expect, it } from "vitest";
import type { Msg } from "../hooks/useChat";
import { boothFlow } from "./boothFlow";
import type { GuardrailPipelineResult } from "./types";

const t = { ts: "12:00:00", tsMs: 0 };
const user = (route: "direct" | "gateway" | "fortiaigate" = "direct"): Msg => ({
  id: 1,
  kind: "user",
  text: "hi",
  ...t,
  cfg: { stream: false, multiTurn: false, route },
});
const P = (o: Partial<GuardrailPipelineResult>): GuardrailPipelineResult => ({
  mode: "sequential",
  guardrailOnly: false,
  results: [],
  notRun: [],
  stoppedBy: null,
  latencyMs: 10,
  ...o,
});
const states = (v: ReturnType<typeof boothFlow>) => Object.fromEntries(v.nodes.map((n) => [n.key, n.state]));

describe("boothFlow", () => {
  it("idle: the architecture for the selected route, nothing credited", () => {
    const v = boothFlow([], false, "gateway");
    expect(v.phase).toBe("idle");
    expect(v.nodes.map((n) => n.label)).toEqual(["You", "Cloudflare edge", "AI guardrails", "AI Gateway", "AI model"]);
    expect(v.to).toBeNull();
  });

  it("in flight: every layer is 'checking' together — no layer is shown as having answered", () => {
    const v = boothFlow([user("gateway")], true, "gateway");
    expect(v.phase).toBe("inFlight");
    expect(v.nodes.slice(1).every((n) => n.state === "pending")).toBe(true);
    expect(v.to).toBeNull();
  });

  it("in flight on the direct route: the gateway is off from the start, not 'checking'", () => {
    const v = boothFlow([user("direct")], true, "direct");
    expect(states(v).gatewayGuardrails).toBe("off");
  });

  it("uses the route the turn was SENT on, not the toggle's current position", () => {
    const v = boothFlow([user("fortiaigate")], true, "direct");
    expect(v.nodes.find((n) => n.key === "gatewayGuardrails")?.label).toBe("FortiAIGate");
  });

  it("streaming: the prompt got past every earlier layer ('through', not 'passed'), the model is answering", () => {
    const v = boothFlow([user(), { id: 2, kind: "assistant", text: "He", ...t, streaming: true, meta: {} }], true, "direct");
    expect(v.phase).toBe("answering");
    expect(states(v)).toMatchObject({ edge: "through", external: "through", model: "pending" });
    expect(v.to).toBe(4);
    expect(v.stopped).toBe(false);
  });

  it("edge block: travels to the edge and stops there; everything after is not reached", () => {
    const v = boothFlow([user(), { id: 2, kind: "blocked", raw: "{}", contentType: "application/json", detection: "injection", ...t }], false, "direct");
    expect(v.to).toBe(1);
    expect(v.stopped).toBe(true);
    expect(states(v)).toMatchObject({ edge: "stopped", external: "notReached", model: "notReached" });
    expect(v.caption).toBe("Blocked at the edge");
  });

  it("a fail-closed vendor stops the turn without a 'stopped' cell — still shown as stopped, at the vendors", () => {
    const p = P({ stoppedBy: "prisma-airs", results: [{ provider: "prisma-airs", outcome: "error", latencyMs: 1 }] });
    const v = boothFlow([user(), { id: 2, kind: "external", pipeline: p, ...t }], false, "direct");
    expect(states(v).external).toBe("unavailable");
    expect(v.to).toBe(2);
    expect(v.stopped).toBe(true);
  });

  it("FortiAIGate block: stops at FortiAIGate even though the model after it is 'unknown'", () => {
    const v = boothFlow([user("fortiaigate"), { id: 2, kind: "fortiaigate", by: "fortiaigate", ...t }], false, "fortiaigate");
    expect(states(v)).toMatchObject({ gatewayGuardrails: "stopped", model: "unavailable" });
    expect(v.to).toBe(3);
    expect(v.stopped).toBe(true);
  });

  it("a reply: travels to the model, not stopped", () => {
    const v = boothFlow([user(), { id: 2, kind: "assistant", text: "Hello", ...t, meta: {} }], false, "direct");
    expect(v.to).toBe(4);
    expect(v.stopped).toBe(false);
    expect(states(v).model).toBe("reached");
  });

  it("an error credits no layer and draws no path", () => {
    const v = boothFlow([user(), { id: 2, kind: "error", text: "boom", ...t }], false, "direct");
    expect(v.to).toBeNull();
    expect(v.nodes.slice(1).every((n) => n.state === "idle" || n.state === "off")).toBe(true);
  });

  it("describes the LATEST turn only", () => {
    const msgs: Msg[] = [
      user(),
      { id: 2, kind: "blocked", raw: "{}", contentType: "application/json", detection: "pii", ...t },
      { ...user(), id: 3 },
    ];
    expect(boothFlow(msgs, true, "direct").phase).toBe("inFlight");
  });
});
