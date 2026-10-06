// "Chat card layout": how the chat shows a turn an external guardrail stopped (or a
// guardrail-only turn). A per-viewer presentation preference stored in this browser
// (lib/cardLayout.ts) — unlike the traffic flow above it, it changes nothing on the
// server and nothing anyone else sees.
import { useId, useState } from "react";
import { useGuardrailCardLayout } from "../hooks/useGuardrailCardLayout";
import { useShowRawResponses } from "../hooks/useShowRawResponses";
import { useShowTurnDetails } from "../hooks/useShowTurnDetails";
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
      <ViewerSwitch
        title="Turn details"
        labels={["Hidden", "Shown"]}
        flag={useShowTurnDetails}
        hint="the control strip and the edge-verdict line under each chat turn"
        note="Shown by default — the strip says which control stopped or passed each prompt, and the verdict line looks up what the edge WAF did. Hiding them also stops that lookup for new turns. Saved in this browser only; the prompt log's verdict column is unaffected."
      />
      {/* The raw-response debug view: off by default; the warning is part of the control, not a footnote. */}
      <ViewerSwitch
        title="Raw vendor responses"
        labels={["Off", "On"]}
        flag={useShowRawResponses}
        hint={'a "Raw responses" panel under each chat turn the guardrails scanned'}
        note="Each vendor's response body as it came back — it can include your prompt and anything the vendor detected. Only your own chat asks for it; it is not stored, logged or exported. Not available on streamed replies (no JSON body to carry it)."
      />
    </section>
  );
}

// One per-viewer on/off preference (hooks/useViewerFlag.ts), as a two-button group.
function ViewerSwitch({
  title,
  labels,
  flag,
  hint,
  note,
}: {
  title: string;
  labels: [off: string, on: string];
  flag: () => [boolean, (on: boolean) => boolean];
  hint: string;
  note: string;
}) {
  const [on, setOn] = flag();
  const [saved, setSaved] = useState<boolean | null>(null);
  const labelId = useId();
  return (
    <div className="mt-3 border-t border-line pt-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 id={labelId} className="text-[13px] font-bold text-text">
          {title}
        </h2>
        <div role="group" aria-labelledby={labelId} className="inline-flex overflow-hidden rounded-full border border-line">
          {[false, true].map((v) => (
            <button
              key={String(v)}
              type="button"
              aria-pressed={on === v}
              onClick={() => setSaved(setOn(v))}
              className={`px-3 py-1.5 text-[12.5px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                on === v ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {v ? labels[1] : labels[0]}
            </button>
          ))}
        </div>
        <span className="text-[12px] text-muted">{hint}</span>
      </div>
      <p aria-live="polite" className="mt-1.5 text-[11.5px] text-subtle">
        {saved === false ? "This browser would not save the choice — it applies until you reload." : note}
      </p>
    </div>
  );
}
