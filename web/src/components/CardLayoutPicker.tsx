// "Chat card layout": how the chat shows a turn an external guardrail stopped (or a
// guardrail-only turn). A per-viewer presentation preference stored in this browser
// (lib/cardLayout.ts) — unlike the traffic flow above it, it changes nothing on the
// server and nothing anyone else sees.
import { useState } from "react";
import { useGuardrailCardLayout } from "../hooks/useGuardrailCardLayout";
import type { CardLayout } from "../lib/cardLayout";

const OPTIONS: { id: CardLayout; label: string; hint: string }[] = [
  { id: "columns", label: "Columns", hint: "one card per guardrail — findings, notes, details" },
  { id: "compact", label: "Compact", hint: "one row per guardrail — ids and config behind Details" },
  { id: "table", label: "Table", hint: "one column per guardrail — verdict, detections, policy, id side by side" },
];

export function CardLayoutPicker() {
  const [layout, setLayout] = useGuardrailCardLayout();
  // null until a choice is made here; false when storage refused it (private window).
  const [saved, setSaved] = useState<boolean | null>(null);
  const current = OPTIONS.find((o) => o.id === layout) ?? OPTIONS[0];
  return (
    <section className="rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 className="text-[13px] font-bold text-text">Chat card layout</h2>
        <div
          role="group"
          aria-label="Chat card layout"
          className="inline-flex overflow-hidden rounded-full border border-line"
        >
          {OPTIONS.map((o) => (
            <button
              key={o.id}
              type="button"
              aria-pressed={layout === o.id}
              onClick={() => setSaved(setLayout(o.id))}
              className={`px-3 py-1.5 text-[12.5px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                layout === o.id ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <span className="text-[12px] text-muted">{current.hint}</span>
      </div>
      <p aria-live="polite" className="mt-1.5 text-[11.5px] text-subtle">
        {saved === false
          ? "This browser would not save the choice — it applies until you reload."
          : "How the chat shows a turn an external guardrail stopped. Saved in this browser only; it changes nothing for anyone else."}
      </p>
    </section>
  );
}
