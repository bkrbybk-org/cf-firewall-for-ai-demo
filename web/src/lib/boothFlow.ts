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
import type { CellState, EdgeKnowledge, MatrixLayer } from "./controlMatrix";
import { boothBanner, boothStrip, type TurnMsg } from "./boothView";
import type { GatewayOption } from "./types";

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

// `gateway`: the AI Gateway the chat sends through (booth's own choice, lib/boothGateway.ts), when known. Its
// Guardrails flag is the same one the detailed view's purple badge uses — the REST API does not report it, so it comes
// from CF_AI_GATEWAY_GUARDED_ID — and the sub-label says it instead of always claiming "Guardrails".
function nodeFor(layer: MatrixLayer, route: Route, gateway?: GatewayOption): Omit<FlowNode, "state" | "title"> {
  switch (layer) {
    case "edge":
      return { key: "edge", label: "Cloudflare edge", sub: "AI Security for Apps" };
    case "external":
      return { key: "external", label: "AI guardrails", sub: "partner vendors" };
    case "gatewayGuardrails":
      return route === "fortiaigate"
        ? { key: "gatewayGuardrails", label: "FortiAIGate", sub: "Fortinet" }
        : {
            key: "gatewayGuardrails",
            label: "AI Gateway",
            sub: route === "direct" ? "not on this route" : !gateway ? "Guardrails" : gateway.guarded ? "Guardrails on" : "Guardrails off",
          };
    case "model":
      return { key: "model", label: "AI model", sub: route === "fortiaigate" ? "Amazon Bedrock" : "Workers AI" };
    case "replyCheck":
      return { key: "replyCheck", label: "Reply check", sub: "guardrails again" };
  }
}

const TEMPLATE: MatrixLayer[] = ["edge", "external", "gatewayGuardrails", "model"];

// `vendors`: whether any external guardrail is enabled. false drops the "AI guardrails" node, so a booth with every
// vendor off never draws a layer that cannot act; undefined (not known yet) keeps it.
function template(
  route: Route,
  state: (layer: MatrixLayer) => FlowNodeState,
  title: string,
  vendors?: boolean,
  gateway?: GatewayOption,
): FlowNode[] {
  return [
    SOURCE,
    ...TEMPLATE.filter((l) => l !== "external" || vendors !== false).map((l) => ({
      ...nodeFor(l, route, gateway),
      // A direct route has no gateway whatever happens: say so from the start rather than animate through it.
      state: l === "gatewayGuardrails" && route === "direct" ? ("off" as const) : state(l),
      title: l === "gatewayGuardrails" && route === "direct" ? "Direct Workers AI route — there is no gateway on this turn." : title,
    })),
  ];
}

// Whether vendors are enabled, from the newest finished turn that says: a turn that reached the Worker carries the
// pipeline it ran (empty = none enabled). An edge refusal or an error never reached it and says nothing, nor does a
// reply still streaming (its meta arrives last). Newer than a settings fetch made before it, so it wins.
function vendorsFromTurns(messages: Msg[]): boolean | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m.kind === "user" || m.kind === "blocked" || m.kind === "error") continue;
    if (m.kind === "assistant" && m.streaming) continue;
    const p = m.kind === "assistant" ? m.meta.externalGuardrails : "pipeline" in m ? m.pipeline : undefined;
    return !!p && p.results.length + p.notRun.length > 0;
  }
  return undefined;
}

// Reached and acted on, or reached and let through: the states the prompt was actually seen in.
const SEEN: FlowNodeState[] = ["stopped", "flagged", "unavailable", "reached", "passed"];

// `edge`: the latest turn's background edge lookup (lib/boothTally.ts), when it has landed — a log-only match then
// shows on the edge node as "flagged", exactly as the turn's own strip shows it.
// `vendorsEnabled`: from the guardrail settings (GET /api/external-guardrails), once fetched; a finished turn overrides it.
export function boothFlow(
  messages: Msg[],
  busy: boolean,
  currentRoute: Route,
  edge?: EdgeKnowledge,
  vendorsEnabled?: boolean,
  gateway?: GatewayOption,
): FlowView {
  const vendors = vendorsFromTurns(messages) ?? vendorsEnabled;
  // The turn in question: the last user message and whatever answered it.
  let u = -1;
  for (let i = messages.length - 1; i >= 0; i--) if (messages[i].kind === "user") { u = i; break; }
  const user = u >= 0 ? (messages[u] as Extract<Msg, { kind: "user" }>) : undefined;
  const route = user?.cfg?.route ?? currentRoute;
  const answer = u >= 0 ? (messages.slice(u + 1).find((m) => m.kind !== "user") as TurnMsg | undefined) : undefined;

  if (!user) {
    return {
      phase: "idle",
      nodes: template(currentRoute, () => "idle", "", vendors, gateway),
      to: null,
      stopped: false,
      caption: "Every prompt passes these layers before the model can answer it",
      turnId: null,
    };
  }

  if (answer?.kind === "assistant" && answer.streaming) {
    const nodes = template(route, (l) => (l === "model" ? "pending" : "through"), "The reply is streaming, so the prompt got past this layer.", vendors, gateway);
    return {
      phase: "answering",
      nodes,
      to: nodes.findIndex((n) => n.key === "model"),
      stopped: false,
      caption: "Reached the model — it is answering",
      turnId: answer.id,
    };
  }

  if (!answer || busy) {
    return {
      phase: "inFlight",
      nodes: template(route, () => "pending", "Waiting for the answer — the verdict comes back in one response.", vendors, gateway),
      to: null,
      stopped: false,
      caption: "Inspecting the prompt…",
      turnId: user.id,
    };
  }

  const strip = boothStrip(answer, route, edge);
  const banner = boothBanner(answer, route, edge);
  if (strip.length === 0) {
    // An error: no layer can be credited with anything.
    return {
      phase: "done",
      nodes: template(route, () => "idle", "The request failed, so no layer's verdict is known.", vendors, gateway),
      to: null,
      stopped: false,
      caption: banner?.title ?? "Something went wrong",
      turnId: answer.id,
    };
  }
  // The vendor layer is dropped when this turn ran none ("off"), or when the edge refused it ("not reached") while
  // none is enabled: drawing a layer that could not have acted would suggest one more check than there was.
  const shown = strip.filter(
    (s) => s.layer !== "external" || !(s.state === "off" || (s.state === "notReached" && vendors === false)),
  );
  const nodes: FlowNode[] = [SOURCE, ...shown.map((s) => ({ ...nodeFor(s.layer, route, gateway), state: s.state as FlowNodeState, title: s.title }))];
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

// The answer to the latest prompt, when it has one — what the component looks the edge up for.
export function latestAnswer(messages: Msg[]): TurnMsg | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].kind === "user") return messages.slice(i + 1).find((m) => m.kind !== "user") as TurnMsg | undefined;
  }
  return undefined;
}
