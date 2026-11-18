// Header switch for booth mode (hooks/useBoothMode.ts). A pressed-state button, labelled in words, so a presenter
// finds it under pressure and a screen reader announces the state.
//
// Turning booth mode ON is one click. Turning it OFF is the presenter's alone: a visitor at an unattended booth must
// not tap their way into the detailed view (and from there the nav and Settings). So while it is on the button
// needs a press-and-hold of EXIT_HOLD_MS, or the shortcut Ctrl+Shift+B (⌘⇧B on a Mac) — a quick tap only says so.
import { useEffect, useRef, useState } from "react";
import { Presentation } from "lucide-react";
import { useBoothMode } from "../hooks/useBoothMode";

export const EXIT_HOLD_MS = 1500;

// The shortcut both ways: Ctrl/⌘ + Shift + B. Not typeable by accident in the prompt box (it needs two modifiers).
export function isBoothShortcut(e: Pick<KeyboardEvent, "key" | "shiftKey" | "ctrlKey" | "metaKey" | "altKey">): boolean {
  return e.shiftKey && (e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "b";
}

export function BoothToggle() {
  const [on, setOn] = useBoothMode();
  const [holding, setHolding] = useState(false);
  const [hint, setHint] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!isBoothShortcut(e)) return;
      e.preventDefault();
      setOn(!on);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [on, setOn]);

  useEffect(() => () => void (timer.current && window.clearTimeout(timer.current)), []);

  function cancelHold() {
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = null;
    setHolding(false);
  }

  if (!on) {
    return (
      <button
        type="button"
        aria-pressed={false}
        onClick={() => setOn(true)}
        title="Booth mode: one big verdict per turn, details and navigation hidden (Ctrl+Shift+B)"
        className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] font-semibold text-muted transition hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Presentation size={14} /> Booth mode
      </button>
    );
  }

  return (
    <button
      type="button"
      aria-pressed
      // Attract mode must not read the presenter's hold as a visitor walking up.
      data-attract-control
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        setHint(false);
        setHolding(true);
        timer.current = window.setTimeout(() => {
          timer.current = null;
          setHolding(false);
          setOn(false);
        }, EXIT_HOLD_MS);
      }}
      onPointerUp={() => {
        if (timer.current) setHint(true); // released early: a tap, not a hold
        cancelHold();
      }}
      onPointerLeave={cancelHold}
      onPointerCancel={cancelHold}
      onClick={(e) => e.preventDefault()}
      title="Booth mode is on. Press and hold to show everything again (or Ctrl+Shift+B)."
      className="relative inline-flex items-center gap-1.5 overflow-hidden rounded-full border border-accent bg-accent/15 px-3 py-1.5 text-[12.5px] font-semibold text-accent-ink transition select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      {/* The hold's progress, filling left to right. `relative` on the button contains it (house rule). */}
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 bg-accent/30"
        style={{ width: holding ? "100%" : "0%", transition: holding ? `width ${EXIT_HOLD_MS}ms linear` : "none" }}
      />
      <span className="relative inline-flex items-center gap-1.5">
        <Presentation size={14} /> {holding ? "Hold to exit…" : hint ? "Hold to exit" : "Booth mode · on"}
      </span>
    </button>
  );
}
