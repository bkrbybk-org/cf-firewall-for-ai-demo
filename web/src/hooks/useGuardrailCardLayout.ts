import { useCallback, useSyncExternalStore } from "react";
import { readCardLayout, writeCardLayout, CARD_LAYOUT_KEY, type CardLayout } from "../lib/cardLayout";

// `localStorage` itself can throw on access (blocked site data), not only its methods.
function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

// In-memory copy so a choice still applies for this page's lifetime when storage
// refuses the write; seeded from storage once, on first read.
let current: CardLayout | null = null;
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  // Another tab changed the choice: follow it, so two windows of the demo agree.
  const onStorage = (e: StorageEvent) => {
    if (e.key !== CARD_LAYOUT_KEY && e.key !== null) return;
    current = readCardLayout(storage());
    emit();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

function getSnapshot(): CardLayout {
  if (current === null) current = readCardLayout(storage());
  return current;
}

// The setter returns whether the choice was saved; when it was not, it still applies
// until the page reloads.
export function useGuardrailCardLayout(): [CardLayout, (layout: CardLayout) => boolean] {
  const layout = useSyncExternalStore(subscribe, getSnapshot);
  const setLayout = useCallback((next: CardLayout) => {
    const saved = writeCardLayout(storage(), next);
    current = next;
    emit();
    return saved;
  }, []);
  return [layout, setLayout];
}
