// What the edge verdict lookup has learned per ray, shared between the Verdict card
// (which polls GraphQL for it) and the per-turn control strip (which only reads it).
// One lookup per ray: the strip must not start a second poll of the same request.
import { useSyncExternalStore } from "react";
import type { EdgeKnowledge } from "./controlMatrix";

const known = new Map<string, EdgeKnowledge>();
const listeners = new Set<() => void>();

export function publishEdge(ray: string, k: EdgeKnowledge): void {
  if (known.get(ray) === k) return;
  known.set(ray, k);
  for (const l of listeners) l();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

// No ray (local dev, a response without one) can never be looked up: "unavailable",
// not "pending" — a spinner that can never finish would claim work nobody is doing.
export function useEdgeKnowledge(ray: string | undefined | null): EdgeKnowledge {
  return useSyncExternalStore(subscribe, () => (ray ? (known.get(ray) ?? "pending") : "unavailable"));
}
