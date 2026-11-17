// Booth mode's words, kept apart from the component so they can be tested (components/BoothTurn.tsx renders them).
// It decides nothing new. Every banner and every strip state comes from what the detailed view already uses:
//   - an external-guardrail headline is pipelineView()'s (votes, fail-closed, outvoted…);
//   - the layer strip is controlMatrix()'s cells, folded to one state per layer;
//   - an edge 403 is credited to Cloudflare AI Security only when the response said so (`detection`), as the
//     detailed card does — a bare 403 can be Cloudflare Access, and is said that way.
import type { Msg, Route } from "../hooks/useChat";
import { controlMatrix, type CellState, type ControlMatrixInput, type MatrixCell } from "./controlMatrix";
import { pipelineView } from "./guardrailView";

export type BoothTone = "edge" | "vendor" | "inline" | "reached" | "neutral" | "error";
export type BoothIcon = "blocked" | "refused" | "passed" | "reached" | "error";
export type TurnMsg = Exclude<Msg, { kind: "user" }>;

export interface BoothBanner {
  tone: BoothTone;
  icon: BoothIcon;
  title: string;
  by: string;
  why?: string;
}

const EDGE_DETECTION: Record<string, string> = {
  pii: "Personal data detected in the prompt",
  injection: "Prompt injection detected",
  unsafe_topic: "Unsafe topic detected",
  waf: "Blocked by a WAF rule",
};

// The control-strip input for a turn. The edge is known only from the response here: a turn that reached the Worker
// passed the edge ("unavailable" detail is fine — the strip shows "passed"); a 403 is an edge block only when the
// response named the detection.
export function boothInput(m: TurnMsg, route: Route): ControlMatrixInput | null {
  switch (m.kind) {
    case "assistant":
      return { kind: "assistant", route, edge: "unavailable", pipeline: m.meta.externalGuardrails, replyPipeline: m.meta.replyGuardrails, guarded: m.meta.gateway?.guarded };
    case "blocked":
      return { kind: "blocked", route, edge: m.detection ? "block" : "unavailable" };
    case "external":
      return { kind: "external", route, edge: "unavailable", pipeline: m.pipeline };
    case "guardrails":
      return { kind: "guardrails", route: "gateway", edge: "unavailable", guarded: m.guarded, guardrailsDirection: m.direction, pipeline: m.pipeline };
    case "fortiaigate":
      return { kind: "fortiaigate", route: "fortiaigate", edge: "unavailable", fortiaigateBy: m.by, pipeline: m.pipeline };
    case "guardrailOnly":
      return { kind: "guardrailOnly", route, edge: "unavailable", pipeline: m.pipeline };
    case "replyWithheld":
      return { kind: "replyWithheld", route, edge: "unavailable", pipeline: m.pipeline, replyPipeline: m.replyPipeline, guarded: m.gateway?.guarded };
    default:
      return null;
  }
}

export function boothBanner(m: TurnMsg, route: Route): BoothBanner | null {
  switch (m.kind) {
    case "blocked":
      return m.detection
        ? { tone: "edge", icon: "blocked", title: "Blocked at the edge", by: "Cloudflare AI Security for Apps", why: EDGE_DETECTION[m.detection] ?? m.reason }
        : { tone: "neutral", icon: "refused", title: "Refused at the edge (HTTP 403)", by: "Cloudflare", why: "The response does not attribute it to an AI Security rule" };
    case "external":
      return { tone: "vendor", icon: "blocked", title: pipelineView(m.pipeline, "blocked").headline, by: "External AI guardrails" };
    case "guardrails":
      return m.direction === "response"
        ? { tone: "inline", icon: "blocked", title: "Reply blocked by AI Gateway Guardrails", by: "Cloudflare AI Gateway", why: "The model answered; the reply was withheld" }
        : { tone: "inline", icon: "blocked", title: "Blocked by AI Gateway Guardrails", by: "Cloudflare AI Gateway", why: "Stopped before the model" };
    case "fortiaigate":
      return {
        tone: "inline",
        icon: "blocked",
        title: m.by === "content_filter" ? "Stopped by a content filter behind FortiAIGate" : "Blocked by FortiAIGate",
        by: "Fortinet FortiAIGate",
        why: "FortiAIGate does not say whether it stopped the prompt or the reply",
      };
    case "replyWithheld":
      return { tone: "vendor", icon: "blocked", title: pipelineView(m.replyPipeline, "blocked").headline, by: "External AI guardrails", why: "The model answered; the reply was not shown" };
    case "guardrailOnly":
      return { tone: "neutral", icon: "passed", title: "Passed every check", by: "Guardrail-only mode", why: "The model was not called, on purpose" };
    case "assistant": {
      const p = m.meta.externalGuardrails;
      return {
        tone: "reached",
        icon: "reached",
        title: "Reached the model",
        by: route === "fortiaigate" ? "through FortiAIGate" : route === "gateway" ? "through AI Gateway" : "Workers AI",
        why:
          p?.observeOnly && p.wouldHaveStopped
            ? "External guardrails would have blocked it, but only observe on this route"
            : "No control stopped this prompt",
      };
    }
    case "error":
      return { tone: "error", icon: "error", title: "Something went wrong", by: "", why: m.text };
    default:
      return null;
  }
}

// One state per layer, the strongest first: what a visitor needs is which layer acted.
const RANK: CellState[] = ["stopped", "flagged", "unavailable", "reached", "passed", "pending", "notReached", "off"];

export interface BoothLayer {
  layer: MatrixCell["layer"];
  label: string;
  state: CellState;
  title: string; // every cell's own sentence, for the tooltip
}

export function boothLayers(cells: MatrixCell[]): BoothLayer[] {
  const groups: { key: MatrixCell["layer"]; label: (c: MatrixCell[]) => string }[] = [
    { key: "edge", label: () => "Edge" },
    { key: "external", label: () => "Vendors" },
    { key: "gatewayGuardrails", label: (c) => (c[0]?.label === "FortiAIGate" ? "FortiAIGate" : "Gateway") },
    { key: "model", label: () => "Model" },
    { key: "replyCheck", label: () => "Reply check" },
  ];
  return groups.flatMap((g) => {
    const of = cells.filter((c) => c.layer === g.key);
    if (of.length === 0) return [];
    const state = RANK.find((s) => of.some((c) => c.state === s)) ?? "off";
    return [{ layer: g.key, label: g.label(of), state, title: of.map((c) => `${c.label}: ${c.detail}`).join("\n") }];
  });
}

export function boothStrip(m: TurnMsg, route: Route): BoothLayer[] {
  const input = boothInput(m, route);
  return input ? boothLayers(controlMatrix(input)) : [];
}
