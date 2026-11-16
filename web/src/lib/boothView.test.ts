// Booth mode (2026-11-16): the big banner must never claim more than the detailed view.
import { describe, expect, it } from "vitest";
import { boothBanner, boothStrip, type TurnMsg } from "./boothView";
import { pipelineView } from "./guardrailView";
import type { GuardrailPipelineResult } from "./types";

const t = { id: 1, ts: "12:00:00", tsMs: 0 };
const P = (o: Partial<GuardrailPipelineResult>): GuardrailPipelineResult => ({
  mode: "sequential",
  guardrailOnly: false,
  results: [],
  notRun: [],
  stoppedBy: null,
  latencyMs: 10,
  ...o,
});
const layer = (m: TurnMsg, route: "direct" | "gateway" | "fortiaigate", label: string) =>
  boothStrip(m, route).find((l) => l.label === label)?.state;

describe("boothBanner — credit only what the response proves", () => {
  it("a 403 is 'Blocked at the edge · Cloudflare AI Security' only when the response named the detection", () => {
    const named: TurnMsg = { ...t, kind: "blocked", raw: "{}", contentType: "application/json", detection: "injection" };
    expect(boothBanner(named, "direct")).toMatchObject({ tone: "edge", title: "Blocked at the edge", by: "Cloudflare AI Security for Apps", why: "Prompt injection detected" });
    const bare: TurnMsg = { ...t, kind: "blocked", raw: "<html>", contentType: "text/html" };
    expect(boothBanner(bare, "direct")).toMatchObject({ tone: "neutral", title: "Refused at the edge (HTTP 403)" });
    expect(boothBanner(bare, "direct")?.by).not.toMatch(/AI Security/);
  });

  it("an external block uses the detailed view's own headline (quorum votes included)", () => {
    const p = P({
      mode: "quorum",
      stoppedBy: "prisma-airs",
      quorum: { configured: 3, needed: 3, votes: 3, of: 3, clamped: false },
      results: [
        { provider: "prisma-airs", outcome: "block", latencyMs: 1 },
        { provider: "crowdstrike-aidr", outcome: "block", latencyMs: 1 },
        { provider: "cisco-ai-defense", outcome: "block", latencyMs: 1 },
      ],
    });
    const b = boothBanner({ ...t, kind: "external", pipeline: p }, "direct");
    expect(b?.title).toBe(pipelineView(p, "blocked").headline);
    expect(b?.title).toMatch(/3 of 3/);
  });

  it("FortiAIGate: its own block vs content_filter alone, and never a claim about prompt vs reply", () => {
    expect(boothBanner({ ...t, kind: "fortiaigate", by: "fortiaigate" }, "fortiaigate")?.title).toBe("Blocked by FortiAIGate");
    expect(boothBanner({ ...t, kind: "fortiaigate", by: "content_filter" }, "fortiaigate")?.title).toMatch(/content filter/);
  });

  it("a reply under observe-only says the vendors would have blocked it — it does not say nothing objected", () => {
    const p = P({ observeOnly: true, wouldHaveStopped: "prisma-airs", results: [{ provider: "prisma-airs", outcome: "block", latencyMs: 1 }] });
    const m: TurnMsg = { ...t, kind: "assistant", text: "Hello", meta: { externalGuardrails: p } };
    expect(boothBanner(m, "fortiaigate")).toMatchObject({ title: "Reached the model", by: "through FortiAIGate" });
    expect(boothBanner(m, "fortiaigate")?.why).toMatch(/would have blocked/);
    const clean: TurnMsg = { ...t, kind: "assistant", text: "Hello", meta: {} };
    expect(boothBanner(clean, "direct")?.why).toBe("No control stopped this prompt");
  });
});

describe("boothStrip — one state per layer, from the control strip", () => {
  it("an edge block lights Edge; nothing after it is credited", () => {
    const m: TurnMsg = { ...t, kind: "blocked", raw: "{}", contentType: "application/json", detection: "pii" };
    expect(layer(m, "direct", "Edge")).toBe("stopped");
    expect(layer(m, "direct", "Model")).toBe("notReached");
  });

  it("FortiAIGate takes the gateway slot; under observe-only a vendor block is a flag, not a stop", () => {
    const p = P({ observeOnly: true, wouldHaveStopped: "prisma-airs", results: [{ provider: "prisma-airs", outcome: "block", latencyMs: 1 }] });
    const m: TurnMsg = { ...t, kind: "fortiaigate", by: "fortiaigate", pipeline: p };
    expect(layer(m, "fortiaigate", "Vendors")).toBe("flagged");
    expect(layer(m, "fortiaigate", "FortiAIGate")).toBe("stopped");
    expect(layer(m, "fortiaigate", "Gateway")).toBeUndefined();
  });

  it("a plain reply: Edge passed, Model reached, no Vendors layer when none is enabled… shown as off", () => {
    const m: TurnMsg = { ...t, kind: "assistant", text: "Paris.", meta: {} };
    expect(layer(m, "direct", "Edge")).toBe("passed");
    expect(layer(m, "direct", "Model")).toBe("reached");
    expect(layer(m, "direct", "Vendors")).toBe("off");
  });
});
