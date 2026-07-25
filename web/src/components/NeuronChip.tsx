import { Zap } from "lucide-react";
import type { NeuronState } from "../hooks/useNeurons";

export function NeuronChip({ state }: { state: NeuronState }) {
  const d = state.data;
  const stamp = state.fetchedAt ? ` · ${state.fetchedAt}` : "";

  let tone = "border-line text-muted";
  let body = "Neuron monitor: –";

  if (d) {
    if (!d.configured) {
      body = "Neuron monitor: off";
    } else if (d.error) {
      tone = "border-cf-amber text-cf-amber";
      body = "Neuron monitor: error";
    } else {
      const pct = d.pctUsed ?? 0;
      if (pct >= 100) tone = "border-cf-red text-cf-red";
      else if (pct >= 80) tone = "border-cf-amber text-cf-amber";
      body = `${Math.round(d.totalNeurons ?? 0).toLocaleString()} / ${(d.freeLimit ?? 0).toLocaleString()} (${pct.toFixed(1)}%)`;
    }
  }

  return (
    <span
      title={d?.error ?? (d?.resetsAt ? `Free daily Neurons · resets ${d.resetsAt}` : "Workers AI Neuron usage today")}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border bg-surface-2 px-3 py-1.5 text-xs ${tone}`}
    >
      <Zap size={13} className="shrink-0" />
      <span className="font-mono">{body}</span>
      <span className="text-subtle">{stamp}</span>
    </span>
  );
}
