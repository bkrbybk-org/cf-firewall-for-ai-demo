// Booth mode's words, kept apart from the component so they can be tested (components/BoothTurn.tsx renders them).
// It decides nothing new. Every banner and every strip state comes from what the detailed view already uses:
//   - an external-guardrail headline is pipelineView()'s (votes, fail-closed, outvoted…);
//   - the layer strip is controlMatrix()'s cells, folded to one state per layer;
//   - an edge 403 is credited to Cloudflare AI Security only when the response said so (`detection`), as the
//     detailed card does — a bare 403 can be Cloudflare Access, and is said that way.
import type { Msg, Route } from "../hooks/useChat";
import { controlMatrix, type CellState, type ControlMatrixInput, type EdgeKnowledge, type MatrixCell } from "./controlMatrix";
import { pipelineView } from "./guardrailView";

export type BoothTone = "edge" | "detected" | "vendor" | "inline" | "reached" | "neutral" | "error";
export type BoothIcon = "blocked" | "detected" | "refused" | "passed" | "reached" | "error";
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

// The ray a turn can be looked up by in the edge log, when the response carried one.
export function rayOf(m: TurnMsg): string | undefined {
  if (m.kind === "assistant") return m.meta.ray ?? m.ray ?? undefined;
  return "ray" in m ? m.ray : undefined;
}

// A turn that reached the Worker passed the edge; whether a log-only rule matched is known only from the edge log,
// looked up in the background (lib/boothTally.ts publishes it to lib/verdictStore.ts). Booth never shows "checking":
// until the lookup lands the edge is plainly "passed".
function passedEdge(edge: EdgeKnowledge | undefined): EdgeKnowledge {
  return !edge || edge === "pending" ? "unavailable" : edge;
}

// The control-strip input for a turn. A 403 is an edge block only when the response named the detection; for every
// other turn the edge is passed, with the background lookup's finding when it has one.
export function boothInput(m: TurnMsg, route: Route, edge?: EdgeKnowledge): ControlMatrixInput | null {
  const e = passedEdge(edge);
  switch (m.kind) {
    case "assistant":
      return { kind: "assistant", route, edge: e, pipeline: m.meta.externalGuardrails, replyPipeline: m.meta.replyGuardrails, guarded: m.meta.gateway?.guarded };
    case "blocked":
      return { kind: "blocked", route, edge: m.detection ? "block" : "unavailable" };
    case "external":
      return { kind: "external", route, edge: e, pipeline: m.pipeline };
    case "guardrails":
      return { kind: "guardrails", route: "gateway", edge: e, guarded: m.guarded, guardrailsDirection: m.direction, pipeline: m.pipeline };
    case "fortiaigate":
      return { kind: "fortiaigate", route: "fortiaigate", edge: e, fortiaigateBy: m.by, pipeline: m.pipeline };
    case "guardrailOnly":
      return { kind: "guardrailOnly", route, edge: e, pipeline: m.pipeline };
    case "replyWithheld":
      return { kind: "replyWithheld", route, edge: e, pipeline: m.pipeline, replyPipeline: m.replyPipeline, guarded: m.gateway?.guarded };
    default:
      return null;
  }
}

// A log-only edge match, from the background lookup. Worded as the detailed strip words it ("A WAF rule matched in log
// mode — detected, not blocked"): not credited to AI Security by name, since a log-mode match can be any WAF rule.
const LOGGED = { tone: "detected", icon: "detected", title: "Detected at the edge — logged, not blocked", by: "Cloudflare WAF, log-only rule" } as const;

export function boothBanner(m: TurnMsg, route: Route, edge?: EdgeKnowledge): BoothBanner | null {
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
      if (edge === "log") return { ...LOGGED, why: "Guardrail-only mode: the model was not called, on purpose" };
      return { tone: "neutral", icon: "passed", title: "Passed every check", by: "Guardrail-only mode", why: "The model was not called, on purpose" };
    case "assistant": {
      const p = m.meta.externalGuardrails;
      const observed = p?.observeOnly && p.wouldHaveStopped;
      if (edge === "log") {
        return {
          ...LOGGED,
          why: observed
            ? "The model answered. External guardrails would have blocked it too, but only observe on this route"
            : "The rule only logs, so the policy let it reach the model",
        };
      }
      return {
        tone: "reached",
        icon: "reached",
        title: "Reached the model",
        by: route === "fortiaigate" ? "through FortiAIGate" : route === "gateway" ? "through AI Gateway" : "Workers AI",
        why:
          observed
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

export function boothStrip(m: TurnMsg, route: Route, edge?: EdgeKnowledge): BoothLayer[] {
  const input = boothInput(m, route, edge);
  return input ? boothLayers(controlMatrix(input)) : [];
}
