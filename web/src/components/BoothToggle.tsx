// Header switch for booth mode (hooks/useBoothMode.ts). A pressed-state button, labelled in words, so a presenter
// finds it under pressure and a screen reader announces the state.
import { Presentation } from "lucide-react";
import { useBoothMode } from "../hooks/useBoothMode";

export function BoothToggle() {
  const [on, setOn] = useBoothMode();
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={() => setOn(!on)}
      title={on ? "Booth mode is on: one big verdict per turn, details hidden. Click to show everything." : "Booth mode: one big verdict per turn, details hidden"}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        on ? "border-accent bg-accent/15 text-accent-ink" : "border-line bg-surface-2 text-muted hover:text-text"
      }`}
    >
      <Presentation size={14} /> Booth mode{on ? " · on" : ""}
    </button>
  );
}
