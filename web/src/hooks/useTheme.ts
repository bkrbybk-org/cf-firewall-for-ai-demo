import { useCallback, useSyncExternalStore } from "react";

export type Theme = "light" | "dark";

// The theme lives on <html data-theme>, set before first paint by index.html from
// localStorage. Every useTheme() subscribes to that one source, so the header
// toggle and Settings → Appearance can never disagree about which is active.
const listeners = new Set<() => void>();

function readTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function subscribe(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function applyTheme(next: Theme) {
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("cf-demo-theme", next);
  } catch {
    /* storage blocked — applies for this session only */
  }
  listeners.forEach((fn) => fn());
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, readTheme);
  const toggle = useCallback(() => applyTheme(readTheme() === "dark" ? "light" : "dark"), []);
  const set = useCallback((next: Theme) => applyTheme(next), []);
  return { theme, toggle, set };
}
