import { useCallback, useSyncExternalStore } from "react";
import { RAW_RESPONSES_KEY, readShowRaw, writeShowRaw } from "../lib/rawResponses";

// Same shape as useGuardrailCardLayout: an in-memory copy (so a refused write still applies
// until reload), following changes made in another tab.
function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

let current: boolean | null = null;
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const onStorage = (e: StorageEvent) => {
    if (e.key !== RAW_RESPONSES_KEY && e.key !== null) return;
    current = readShowRaw(storage());
    emit();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

// Also read outside React, at send time (useChat), so a toggle takes effect on the next prompt.
export function showRawResponses(): boolean {
  if (current === null) current = readShowRaw(storage());
  return current;
}

export function useShowRawResponses(): [boolean, (on: boolean) => boolean] {
  const on = useSyncExternalStore(subscribe, showRawResponses);
  const set = useCallback((next: boolean) => {
    const saved = writeShowRaw(storage(), next);
    current = next;
    emit();
    return saved;
  }, []);
  return [on, set];
}
