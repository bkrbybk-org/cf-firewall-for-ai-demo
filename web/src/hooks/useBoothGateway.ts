import { useCallback, useSyncExternalStore } from "react";
import { BOOTH_FORTI_MODEL_KEY, BOOTH_GATEWAY_KEY, BOOTH_MODEL_KEY } from "../lib/boothGateway";

// Booth's own choices (lib/boothGateway.ts): an id, or "" for "same as the chat page". Same storage contract as
// hooks/useViewerFlag.ts — storage can be missing or throw (private window, blocked site data), so a refused write
// still applies until reload, and a change made in another tab (Settings open beside the booth) is followed.
function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function createStringPref(key: string): () => [string, (v: string) => boolean] {
  const read = (): string => {
    try {
      // Bounded: a stored value is never trusted to be sane. Every id here is far shorter.
      return (storage()?.getItem(key) ?? "").slice(0, 128);
    } catch {
      return "";
    }
  };
  let current: string | null = null;
  const listeners = new Set<() => void>();
  const emit = () => {
    for (const l of listeners) l();
  };
  const subscribe = (listener: () => void) => {
    listeners.add(listener);
    const onStorage = (e: StorageEvent) => {
      if (e.key !== key && e.key !== null) return;
      current = read();
      emit();
    };
    window.addEventListener("storage", onStorage);
    return () => {
      listeners.delete(listener);
      window.removeEventListener("storage", onStorage);
    };
  };
  const get = (): string => {
    if (current === null) current = read();
    return current;
  };
  // The setter returns whether the choice was saved.
  const set = (v: string): boolean => {
    let saved = false;
    try {
      const s = storage();
      if (s) {
        if (v) s.setItem(key, v);
        else s.removeItem(key);
        saved = true;
      }
    } catch {
      saved = false;
    }
    current = v;
    emit();
    return saved;
  };
  return function use() {
    const value = useSyncExternalStore(subscribe, get);
    return [value, useCallback((v: string) => set(v), [])];
  };
}

export const useBoothGateway = createStringPref(BOOTH_GATEWAY_KEY);
export const useBoothModel = createStringPref(BOOTH_MODEL_KEY);
export const useBoothFortiModel = createStringPref(BOOTH_FORTI_MODEL_KEY);
