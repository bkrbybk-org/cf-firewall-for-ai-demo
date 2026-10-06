// The strip under a chat turn: the controls a prompt passed through, left to right. It renders the
// cells controlMatrix() (lib/controlMatrix.ts) hands it and decides nothing about verdicts.
//
// Colour is the point: a layer's identity colour (edge red, external amber, Gateway Guardrails
// purple) appears only when that layer stopped or flagged, so a glance at a blocked turn says which
// control did it. Passed is green, the model answering is neutral, and "unavailable" is a dashed
// amber outline that never fills — an outage is not a verdict, even when fail-closed made it decisive.
import { Fragment } from "react";
import { ChevronRight, Loader2 } from "lucide-react";
import type { CellState, MatrixCell, MatrixLayer } from "../lib/controlMatrix";

// Full class strings, never built from a variable: Tailwind only emits what it can read.
const STOPPED: Record<MatrixLayer, string> = {
  edge: "border-cf-red/60 bg-cf-red/10 text-cf-red",
  external: "border-cf-amber/60 bg-cf-amber/10 text-cf-amber",
  gatewayGuardrails: "border-cf-purple/60 bg-cf-purple/10 text-cf-purple",
  model: "border-line bg-surface-2 text-text",
};
const STOPPED_RING: Record<MatrixLayer, string> = {
  edge: "border-cf-red ring-1 ring-cf-red/40",
  external: "border-cf-amber ring-1 ring-cf-amber/40",
  gatewayGuardrails: "border-cf-purple ring-1 ring-cf-purple/40",
  model: "",
};
// Detected, not blocked: dashed and unfilled so it cannot be mistaken for a block.
const FLAGGED: Record<MatrixLayer, string> = {
  edge: "border-dashed border-cf-red/60 text-cf-red",
  external: "border-dashed border-cf-amber/60 text-cf-amber",
  gatewayGuardrails: "border-dashed border-cf-purple/60 text-cf-purple",
  model: "border-dashed border-line text-text",
};

function cellClass(c: MatrixCell): string {
  const base = "min-w-0 rounded-lg border px-2 py-1 text-[10.5px] leading-tight";
  let tone: string;
  switch (c.state as CellState) {
    case "stopped":
      tone = `${STOPPED[c.layer]} ${c.decisive ? `${STOPPED_RING[c.layer]} font-bold` : ""}`;
      break;
    case "flagged":
      tone = FLAGGED[c.layer];
      break;
    case "passed":
      tone = "border-cf-green/50 bg-cf-green/5 text-cf-green";
      break;
    case "reached":
      tone = "border-line bg-surface-2 text-text";
      break;
    case "unavailable":
      // Dashed, no fill. A decisive outage still ended the turn, so it keeps the ring.
      tone = `border-dashed border-cf-amber/60 text-cf-amber ${c.decisive ? "ring-1 ring-cf-amber/40" : ""}`;
      break;
    case "pending":
      tone = "border-dashed border-line text-muted";
      break;
    default: // notReached, off
      tone = "border-dashed border-line text-subtle";
  }
  return `${base} ${tone}`;
}

// Consecutive cells of one layer sit together: the external guardrails are one group.
function groupByLayer(cells: MatrixCell[]): MatrixCell[][] {
  const groups: MatrixCell[][] = [];
  for (const c of cells) {
    const last = groups[groups.length - 1];
    if (last && last[0].layer === c.layer) last.push(c);
    else groups.push([c]);
  }
  return groups;
}

export function ControlMatrix({ cells }: { cells: MatrixCell[] }) {
  if (cells.length === 0) return null;
  const groups = groupByLayer(cells);
  return (
    <ol aria-label="Controls this prompt passed through" className="flex flex-wrap items-center gap-1">
      {groups.map((group, i) => (
        <Fragment key={group.map((c) => c.key).join("|")}>
          <li className="flex min-w-0 max-w-full flex-wrap items-center gap-1">
            {i > 0 && <ChevronRight aria-hidden="true" size={12} className="shrink-0 text-subtle" />}
            <ul className="flex min-w-0 flex-wrap gap-1">
              {group.map((c) => (
                <li key={c.key} title={c.detail} className={cellClass(c)}>
                  <div className="text-[10.5px] font-normal text-muted">{c.label}</div>
                  <div className="flex items-center gap-1 text-[11px] font-bold">
                    {c.state === "pending" && <Loader2 aria-hidden="true" size={10} className="animate-spin" />}
                    {c.stateLabel}
                  </div>
                  <span className="sr-only">{c.detail}</span>
                </li>
              ))}
            </ul>
          </li>
        </Fragment>
      ))}
    </ol>
  );
}
