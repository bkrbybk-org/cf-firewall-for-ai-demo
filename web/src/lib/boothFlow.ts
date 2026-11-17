// Booth mode's architecture strip (components/BoothFlow.tsx): the path every prompt takes, drawn once at the top of
// the chat, animated while a turn is in flight and then lit with where the latest turn ended.
//
// The honesty rule for the animation: the browser sends ONE request and gets ONE answer back. While it waits it does
// not know which layer is working, so the in-flight state is deliberately indeterminate — a sweep across the whole
// path, never a sequence that lights the edge, then the vendors, then the gateway as if it had heard from each.
// Two things are known before the end and are said:
//   - a streamed reply has started → everything before the model let it through (a guarded gateway, a reply check
//     and FortiAIGate are never streamed — useChat's NotStreamedReason — so a stream means the prompt is past them);
//   - the verdict → each node's state is boothStrip()'s, which is controlMatrix()'s, so the diagram can never say
//     more than the detailed view's control strip.
import type { Msg, Route } from "../hooks/useChat";
import type { CellState, MatrixLayer } from "./controlMatrix";
import { boothBanner, boothStrip, type TurnMsg } from "./boothView";

export type FlowPhase = "idle" | "inFlight" | "answering" | "done";
// "through": a streamed reply proves the prompt got past this node, but not what the node said (observe-only on the
// FortiAIGate route still lets a "would have blocked" through), so it is not painted as a pass.
export type FlowNodeState = CellState | "idle" | "through";

export interface FlowNode {
  key: "source" | MatrixLayer;
  label: string;
  sub: string;
  state: FlowNodeState;
  title: string;
}

export interface FlowView {
  phase: FlowPhase;
  nodes: FlowNode[];
  // The node the prompt travelled to (an index into nodes), when known. `stopped` says whether it ended there
  // because a control stopped it, rather than because it reached the end of the path.
  to: number | null;
  stopped: boolean;
  caption: string;
  // The message the view describes — a React key, so the replay animation restarts on each new verdict.
  turnId: number | null;
}

const SOURCE: FlowNode = { key: "source", label: "You", sub: "browser", state: "idle", title: "The prompt, as typed" };

function nodeFor(layer: MatrixLayer, route: Route): Omit<FlowNode, "state" | "title"> {
  switch (layer) {
    case "edge":
      return { key: "edge", label: "Cloudflare edge", sub: "AI Security for Apps" };
    case "external":
      return { key: "external", label: "AI guardrails", sub: "partner vendors" };
    case "gatewayGuardrails":
      return route === "fortiaigate"
        ? { key: "gatewayGuardrails", label: "FortiAIGate", sub: "Fortinet" }
        : { key: "gatewayGuardrails", label: "AI Gateway", sub: route === "direct" ? "not on this route" : "Guardrails" };
    case "model":
      return { key: "model", label: "AI model", sub: route === "fortiaigate" ? "Amazon Bedrock" : "Workers AI" };
    case "replyCheck":
      return { key: "replyCheck", label: "Reply check", sub: "guardrails again" };
  }
}

const TEMPLATE: MatrixLayer[] = ["edge", "external", "gatewayGuardrails", "model"];

function template(route: Route, state: (layer: MatrixLayer) => FlowNodeState, title: string): FlowNode[] {
  return [
    SOURCE,
    ...TEMPLATE.map((l) => ({
      ...nodeFor(l, route),
      // A direct route has no gateway whatever happens: say so from the start rather than animate through it.
      state: l === "gatewayGuardrails" && route === "direct" ? ("off" as const) : state(l),
      title: l === "gatewayGuardrails" && route === "direct" ? "Direct Workers AI route — there is no gateway on this turn." : title,
    })),
  ];
}

// Reached and acted on, or reached and let through: the states the prompt was actually seen in.
const SEEN: FlowNodeState[] = ["stopped", "flagged", "unavailable", "reached", "passed"];

export function boothFlow(messages: Msg[], busy: boolean, currentRoute: Route): FlowView {
  // The turn in question: the last user message and whatever answered it.
  let u = -1;
  for (let i = messages.length - 1; i >= 0; i--) if (messages[i].kind === "user") { u = i; break; }
  const user = u >= 0 ? (messages[u] as Extract<Msg, { kind: "user" }>) : undefined;
  const route = user?.cfg?.route ?? currentRoute;
  const answer = u >= 0 ? (messages.slice(u + 1).find((m) => m.kind !== "user") as TurnMsg | undefined) : undefined;

  if (!user) {
    return {
      phase: "idle",
      nodes: template(currentRoute, () => "idle", ""),
      to: null,
      stopped: false,
      caption: "Every prompt passes these layers before the model can answer it",
      turnId: null,
    };
  }

  if (answer?.kind === "assistant" && answer.streaming) {
    return {
      phase: "answering",
      nodes: template(route, (l) => (l === "model" ? "pending" : "through"), "The reply is streaming, so the prompt got past this layer."),
      to: 4,
      stopped: false,
      caption: "Reached the model — it is answering",
      turnId: answer.id,
    };
  }

  if (!answer || busy) {
    return {
      phase: "inFlight",
      nodes: template(route, () => "pending", "Waiting for the answer — the verdict comes back in one response."),
      to: null,
      stopped: false,
      caption: "Inspecting the prompt…",
      turnId: user.id,
    };
  }

  const strip = boothStrip(answer, route);
  const banner = boothBanner(answer, route);
  if (strip.length === 0) {
    // An error: no layer can be credited with anything.
    return {
      phase: "done",
      nodes: template(route, () => "idle", "The request failed, so no layer's verdict is known."),
      to: null,
      stopped: false,
      caption: banner?.title ?? "Something went wrong",
      turnId: answer.id,
    };
  }
  const nodes: FlowNode[] = [SOURCE, ...strip.map((s) => ({ ...nodeFor(s.layer, route), state: s.state as FlowNodeState, title: s.title }))];
  // Where the prompt got to: the first layer that stopped it; otherwise the last layer that saw it. FortiAIGate's
  // block leaves the model "unknown" (unavailable) after a stop, which is why a stop wins over "last seen".
  const stopIdx = nodes.findIndex((n) => n.state === "stopped");
  let lastSeen = -1;
  nodes.forEach((n, i) => {
    if (SEEN.includes(n.state)) lastSeen = i;
  });
  const to = stopIdx >= 0 ? stopIdx : lastSeen >= 0 ? lastSeen : 0;
  // Stopped = the turn did not get the model's answer to the visitor. A fail-closed vendor stops a turn without a
  // "stopped" cell (an error is never a verdict), so this comes from the banner, not from the cell states.
  const stopped = banner ? banner.icon === "blocked" || banner.icon === "refused" : stopIdx >= 0;
  return { phase: "done", nodes, to, stopped, caption: banner?.title ?? "", turnId: answer.id };
}
