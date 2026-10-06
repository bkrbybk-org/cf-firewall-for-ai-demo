import { useCallback, useSyncExternalStore } from "react";

// A per-viewer on/off preference kept in this browser's storage: the raw-responses debug
// switch, the turn-details switch. Same contract as useGuardrailCardLayout — storage can
// be missing or throw (private window, blocked site data), so a refused write still
// applies until reload, and a change made in another tab is followed.
//
// `parse` decides the default from whatever is stored, so each flag states its own safe
// direction: raw responses are on only for the exact word "on"; turn details are hidden
// only for the exact word "off".
export interface ViewerFlag {
  use(): [boolean, (on: boolean) => boolean];
  get(): boolean; // for code outside React (useChat reads it at send time)
}

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function createViewerFlag(key: string, parse: (raw: string | null) => boolean): ViewerFlag {
  let current: boolean | null = null;
  const listeners = new Set<() => void>();
  const read = (): boolean => {
    try {
      return parse(storage()?.getItem(key) ?? null);
    } catch {
      return parse(null);
    }
  };
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
  const get = (): boolean => {
    if (current === null) current = read();
    return current;
  };
  const set = (on: boolean): boolean => {
    let saved = false;
    try {
      const s = storage();
      if (s) {
        s.setItem(key, on ? "on" : "off");
        saved = true;
      }
    } catch {
      saved = false;
    }
    current = on;
    emit();
    return saved;
  };
  return {
    get,
    use() {
      const value = useSyncExternalStore(subscribe, get);
      const setter = useCallback((on: boolean) => set(on), []);
      return [value, setter];
    },
  };
}
