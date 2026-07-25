// Tiny in-memory stores for state that must outlive route changes.
//
// Why module scope: the module is evaluated once per page load and is never
// re-evaluated when the client-side router swaps pages, so state kept here
// survives tab switches. A full browser refresh reloads the bundle and the
// store starts empty again. That is exactly the lifetime we want for demo
// chat history — keep it while the presenter moves between tabs, drop it when
// they refresh to start a clean demo.
//
// Deliberately NOT sessionStorage or localStorage: both survive a refresh.
import { useSyncExternalStore } from "react";

export interface Store<T> {
  get: () => T;
  set: (next: T | ((prev: T) => T)) => void;
  subscribe: (fn: () => void) => () => void;
}

export function createStore<T>(initial: T): Store<T> {
  let value = initial;
  const subs = new Set<() => void>();
  return {
    get: () => value,
    set: (next) => {
      value = typeof next === "function" ? (next as (prev: T) => T)(value) : next;
      subs.forEach((fn) => fn());
    },
    subscribe: (fn) => {
      subs.add(fn);
      return () => {
        subs.delete(fn);
      };
    },
  };
}

export function useStore<T>(store: Store<T>): T {
  return useSyncExternalStore(store.subscribe, store.get, store.get);
}

// Message ids, unique for the lifetime of the page load.
let idSeq = 0;
export const nextMsgId = () => ++idSeq;
