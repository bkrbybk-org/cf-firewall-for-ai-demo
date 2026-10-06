// One chat turn as a row of controls: edge WAF → each external guardrail → AI
// Gateway Guardrails → the model. Pure, so the attribution rules are tested here
// rather than re-decided in JSX.
//
// What this must never do — the credibility of the demo:
//   - credit a layer with something it did not see. A prompt the edge refused
//     never reached the Worker, so every later cell is "not reached", not "passed".
//   - call a bare 403 a WAF block. Until the edge verdict names a rule, a 403 is
//     "refused at the edge" — Cloudflare Access answers 403 too.
//   - read an error as a verdict. An unreachable guardrail is "unavailable", even
//     when (fail closed) it is what stopped the turn.
//   - read "passed" into a layer that was off. A direct-route turn has no AI
//     Gateway; a gateway without Guardrails did not check anything.
import { noVerdictReason, providerLabel } from "./guardrailView";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "./types";
import type { Outcome } from "./verdict";

export type MatrixLayer = "edge" | "external" | "gatewayGuardrails" | "model";

export type CellState =
  | "stopped" // this layer ended the turn
  | "passed" // it looked and let the prompt through
  | "flagged" // it detected something but its rule only logs / alerts
  | "unavailable" // it could not be consulted — not a verdict
  | "notReached" // the prompt never got this far
  | "off" // the layer does not exist for this turn (direct route, Guardrails off, none enabled)
  | "pending" // the edge verdict is still being looked up
  | "reached"; // the model answered (neutral: that is the goal for a benign prompt)

export interface MatrixCell {
  key: string; // stable React key
  layer: MatrixLayer;
  label: string; // "Edge WAF", "Prisma AIRS", "AI Gateway Guardrails", "Model"
  state: CellState;
  stateLabel: string; // short word(s) for the cell
  detail: string; // one sentence for the tooltip / screen reader
  // The cell that ended the turn (several in a parallel multi-block). At most the
  // layers that actually stopped it; never a layer that only passed or was off.
  decisive: boolean;
}

export type EdgeKnowledge = Outcome | "pending" | "unavailable";

export interface ControlMatrixInput {
  // Which chat message ended the turn.
  kind: "assistant" | "blocked" | "guardrails" | "external" | "guardrailOnly";
  route: "direct" | "gateway";
  // The edge verdict for this ray, when the lookup has finished; "pending" while it
  // runs; "unavailable" when it cannot be had (no ray, analytics off, expired).
  edge: EdgeKnowledge;
  pipeline?: GuardrailPipelineResult;
  guarded?: boolean; // gateway route: this gateway has Guardrails on
  guardrailsDirection?: "prompt" | "response"; // kind "guardrails" only
}

const STATE_LABEL: Record<CellState, string> = {
  stopped: "stopped",
  passed: "passed",
  flagged: "flagged",
  unavailable: "unavailable",
  notReached: "not reached",
  off: "off",
  pending: "checking…",
  reached: "answered",
};

function cell(
  key: string,
  layer: MatrixLayer,
  label: string,
  state: CellState,
  detail: string,
  decisive = false,
  stateLabel = STATE_LABEL[state],
): MatrixCell {
  return { key, layer, label, state, stateLabel, detail, decisive };
}

function edgeCell(i: ControlMatrixInput): MatrixCell {
  const L = "Edge WAF";
  if (i.kind === "blocked") {
    if (i.edge === "block") return cell("edge", "edge", L, "stopped", "A WAF rule blocked the request at the Cloudflare edge.", true);
    if (i.edge === "challenge") return cell("edge", "edge", L, "stopped", "A WAF rule challenged the request at the edge.", true, "challenged");
    if (i.edge === "denied" || i.edge === "log" || i.edge === "allow") {
      // The edge log shows no blocking WAF rule for a 403: another layer refused it.
      return cell("edge", "edge", L, "stopped", "Refused at the edge (HTTP 403), but not by a WAF rule — e.g. Cloudflare Access.", true, "refused · not WAF");
    }
    return cell(
      "edge",
      "edge",
      L,
      "stopped",
      i.edge === "pending"
        ? "Refused at the edge (HTTP 403). Which rule did it is still being looked up."
        : "Refused at the edge (HTTP 403). The edge log is not available, so which layer did it is not confirmed.",
      true,
      "refused (403)",
    );
  }
  // Every other kind reached the Worker: the edge let it through.
  if (i.edge === "log") return cell("edge", "edge", L, "flagged", "A WAF rule matched in log mode — detected, not blocked.", false, "logged · passed");
  if (i.edge === "pending") return cell("edge", "edge", L, "passed", "Passed the edge. Whether a log-only rule matched is still being looked up.", false, "passed · checking");
  if (i.edge === "unavailable") return cell("edge", "edge", L, "passed", "Passed the edge. The edge log is not available for rule detail.");
  return cell("edge", "edge", L, "passed", "Passed the edge: no rule blocked it.");
}

function vendorCell(r: ExternalGuardrailResult, p: GuardrailPipelineResult, multiBlock: boolean): MatrixCell {
  const name = providerLabel(r.provider);
  const key = `ext:${r.provider}`;
  if (r.outcome === "block") {
    const why = r.detected?.length ? ` (${r.detected.join(", ")})` : "";
    const decisive = multiBlock || p.stoppedBy === r.provider;
    return cell(key, "external", name, "stopped", `${name} blocked the prompt${why}.`, decisive, "blocked");
  }
  if (r.outcome === "allow") {
    if (r.detectOnly) {
      // Lakera's Detect mode, or Cato's null required_action — named generically here.
      return cell(key, "external", name, "flagged", `${name} detected ${r.detected?.join(", ") || "something"} but only alerted — it did not block.`, false, "alerts only");
    }
    if (r.incomplete || r.transformed) {
      return cell(key, "external", name, "passed", `${name} allowed it, but ${r.incomplete ? "not every detection service ran" : "its redaction was not applied"}.`, false, "passed · partial");
    }
    return cell(key, "external", name, "passed", `${name} allowed the prompt.`);
  }
  // An error is never a verdict.
  if (r.failedOpen) {
    const why = noVerdictReason(r);
    return cell(key, "external", name, "unavailable", `${name}: ${why.charAt(0).toLowerCase() + why.slice(1)}; fail open, so the prompt went on without its verdict.`, false, "no verdict · fail open");
  }
  const why = noVerdictReason(r);
  return cell(
    key,
    "external",
    name,
    "unavailable",
    `${name}: ${why.charAt(0).toLowerCase() + why.slice(1)}; fail closed${p.stoppedBy === r.provider ? ", so the turn stopped here" : ""}. Not a verdict.`,
    p.stoppedBy === r.provider,
    "no verdict · fail closed",
  );
}

function externalCells(i: ControlMatrixInput): MatrixCell[] {
  if (i.kind === "blocked") {
    return [cell("ext", "external", "External guardrails", "notReached", "The edge refused the request, so it never reached the Worker.")];
  }
  const p = i.pipeline;
  if (!p || (p.results.length === 0 && p.notRun.length === 0)) {
    return [cell("ext", "external", "External guardrails", "off", "No external guardrail is enabled.")];
  }
  // Parallel with two or more blocks: each would have stopped it alone (same rule
  // as the chat card's "blocked independently").
  const multiBlock = p.mode === "parallel" && p.results.filter((r) => r.outcome === "block").length >= 2;
  return [
    ...p.results.map((r) => vendorCell(r, p, multiBlock)),
    ...p.notRun.map((n) =>
      cell(`ext:${n.provider}`, "external", providerLabel(n.provider), "notReached", `Did not run: ${n.reason}.`, false, "did not run"),
    ),
  ];
}

function gatewayGuardrailsCell(i: ControlMatrixInput): MatrixCell {
  const L = "AI Gateway Guardrails";
  if (i.route === "direct") return cell("aig", "gatewayGuardrails", L, "off", "Direct Workers AI route — there is no gateway on this turn.", false, "n/a · direct");
  if (i.kind === "guardrails") {
    return i.guardrailsDirection === "response"
      ? cell("aig", "gatewayGuardrails", L, "stopped", "Guardrails blocked the model's response (2017).", true, "blocked reply")
      : cell("aig", "gatewayGuardrails", L, "stopped", "Guardrails blocked the prompt before the model (2016).", true, "blocked prompt");
  }
  if (i.kind !== "assistant") {
    const why = i.kind === "guardrailOnly" ? "Guardrail-only mode skips the model call, and Guardrails with it." : "The model call never started.";
    return cell("aig", "gatewayGuardrails", L, "notReached", why);
  }
  if (!i.guarded) return cell("aig", "gatewayGuardrails", L, "off", "This gateway has Guardrails off, so nothing was checked here.", false, "off");
  return cell("aig", "gatewayGuardrails", L, "passed", "Guardrails checked the prompt and the reply and let both through.");
}

function modelCell(i: ControlMatrixInput): MatrixCell {
  const L = "Model";
  if (i.kind === "assistant") return cell("model", "model", L, "reached", "The model answered.");
  if (i.kind === "guardrailOnly") return cell("model", "model", L, "off", "Guardrail-only mode: the model was deliberately not called.", false, "skipped");
  if (i.kind === "guardrails" && i.guardrailsDirection === "response") {
    return cell("model", "model", L, "reached", "The model answered, but Guardrails withheld the reply.", false, "answered · withheld");
  }
  return cell("model", "model", L, "notReached", "The prompt was stopped before the model.");
}

export function controlMatrix(i: ControlMatrixInput): MatrixCell[] {
  return [edgeCell(i), ...externalCells(i), gatewayGuardrailsCell(i), modelCell(i)];
}
