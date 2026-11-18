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
    expect(v.nodes[v.to!].key).toBe("gatewayGuardrails");
    expect(v.stopped).toBe(true);
  });

  it("a reply: travels to the model, not stopped", () => {
    const p = P({ results: [{ provider: "prisma-airs", outcome: "allow", latencyMs: 1 }] });
    const v = boothFlow([user(), { id: 2, kind: "assistant", text: "Hello", ...t, meta: { externalGuardrails: p } }], false, "direct");
    expect(states(v).external).toBe("passed");
    expect(v.to).toBe(4);
    expect(v.stopped).toBe(false);
    expect(states(v).model).toBe("reached");
  });

  describe("every vendor disabled: no 'AI guardrails' node", () => {
    const keys = (v: ReturnType<typeof boothFlow>) => v.nodes.map((n) => n.key);
    const ran = P({ results: [{ provider: "prisma-airs", outcome: "allow", latencyMs: 1 }] });

    it("idle and in flight follow the settings read; unknown keeps the node", () => {
      expect(keys(boothFlow([], false, "gateway", undefined, false))).not.toContain("external");
      expect(keys(boothFlow([user()], true, "direct", undefined, false))).not.toContain("external");
      expect(keys(boothFlow([], false, "gateway", undefined, true))).toContain("external");
      expect(keys(boothFlow([], false, "gateway"))).toContain("external");
    });

    it("a reply that ran no vendor drops the node and still travels to the model", () => {
      const v = boothFlow([user(), { id: 2, kind: "assistant", text: "Hi", ...t, meta: {} }], false, "direct", undefined, true);
      expect(keys(v)).toEqual(["source", "edge", "gatewayGuardrails", "model"]);
      expect(v.to).toBe(3);
      // An empty pipeline (guardrail-only, edge-only test) also ran none — and the next prompt's diagram knows it.
      const e: Msg[] = [user(), { id: 2, kind: "guardrailOnly", pipeline: P({ guardrailOnly: true }), ...t }];
      expect(keys(boothFlow(e, false, "direct", undefined, true))).not.toContain("external");
      expect(keys(boothFlow([...e, { ...user(), id: 3 }], true, "direct", undefined, true))).not.toContain("external");
    });

    it("a finished turn outranks the settings read: it ran a vendor, so the node is drawn", () => {
      const msgs: Msg[] = [user(), { id: 2, kind: "assistant", text: "Hi", ...t, meta: { externalGuardrails: ran } }];
      expect(keys(boothFlow(msgs, false, "direct", undefined, false))).toContain("external");
      expect(keys(boothFlow([...msgs, { ...user(), id: 3 }], true, "direct", undefined, false))).toContain("external");
    });

    it("streaming with none enabled: 'to' is the model's own index", () => {
      const v = boothFlow([user(), { id: 2, kind: "assistant", text: "He", ...t, streaming: true, meta: {} }], true, "direct", undefined, false);
      expect(v.to).toBe(v.nodes.findIndex((n) => n.key === "model"));
      expect(v.to).toBe(3);
      // A reply still streaming has no meta yet: it must not read as "ran no vendor".
      const s = boothFlow([user(), { id: 2, kind: "assistant", text: "He", ...t, streaming: true, meta: {} }], true, "direct", undefined, true);
      expect(keys(s)).toContain("external");
    });

    it("an edge refusal says nothing about vendors: dropped only when the settings say none", () => {
      const b: Msg = { id: 2, kind: "blocked", raw: "{}", contentType: "application/json", detection: "pii", ...t };
      expect(keys(boothFlow([user(), b], false, "direct", undefined, false))).not.toContain("external");
      expect(keys(boothFlow([user(), b], false, "direct", undefined, true))).toContain("external");
      expect(boothFlow([user(), b], false, "direct", undefined, false).to).toBe(1);
    });
  });

  it("the gateway node says whether the selected gateway has Guardrails, instead of always claiming them", () => {
    const sub = (gw?: { id: string; label: string; guarded: boolean }) =>
      boothFlow([], false, "gateway", undefined, undefined, gw).nodes.find((n) => n.key === "gatewayGuardrails")?.sub;
    expect(sub({ id: "g", label: "g (Guardrails)", guarded: true })).toBe("Guardrails on");
    expect(sub({ id: "p", label: "p", guarded: false })).toBe("Guardrails off");
    expect(sub()).toBe("Guardrails");
    // The direct route has no gateway whichever one is selected.
    const d = boothFlow([], false, "direct", undefined, undefined, { id: "g", label: "g", guarded: true });
    expect(d.nodes.find((n) => n.key === "gatewayGuardrails")?.sub).toBe("not on this route");
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

  it("with the edge lookup: a log-only match flags the edge node; the turn still went to the model, not stopped", () => {
    const v = boothFlow([user(), { id: 2, kind: "assistant", text: "Hello", ...t, meta: {} }], false, "direct", "log");
    expect(states(v).edge).toBe("flagged");
    expect(v.nodes[v.to!].key).toBe("model");
    expect(v.stopped).toBe(false);
    expect(v.caption).toMatch(/logged, not blocked/);
  });
});
