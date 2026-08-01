// The zone's WAF custom rules, fetched once per page load and shared by every
// consumer (the flow trace and the analytics rule split).
//
// Falls back to the static ZONE_RULES mirror in lib/data.ts when the live
// lookup is unavailable — but reports WHICH it is via `source`, so the UI can
// label a stale mirror as a mirror. Presenting hand-maintained data as live
// zone state is the failure this feature exists to remove; swapping one silent
// source for another would not be an improvement.
import { useEffect } from "react";
import { getZoneRules } from "../lib/api";
import { ZONE_RULES, isLlmRule } from "../lib/data";
import { createStore, useStore } from "../lib/sessionStore";

// The shape both sources agree on. `detail` is the real rule expression when
// live and the mirror's hand-written hint when not.
export interface UiZoneRule {
  name: string;
  action: string;
  detail?: string;
  enabled: boolean;
  llm: boolean;
}

export type ZoneRuleSource = "live" | "fallback";

export interface ZoneRulesState {
  rules: UiZoneRule[];
  source: ZoneRuleSource;
}

// Every rule in the static mirror is an AI Security rule and is assumed
// enabled — that assumption is exactly what the live path removes.
const FALLBACK: ZoneRulesState = {
  rules: ZONE_RULES.map((r) => ({
    name: r.name,
    action: r.action,
    detail: r.summary,
    enabled: true,
    llm: true,
  })),
  source: "fallback",
};

const store = createStore<ZoneRulesState>(FALLBACK);
// One fetch per page load, shared by every mounted consumer.
let inflight: Promise<void> | null = null;

function load(): Promise<void> {
  if (inflight) return inflight;
  inflight = getZoneRules()
    .then((res) => {
      // An empty live list means the zone genuinely has no custom rules; that
      // is real information, so it replaces the mirror rather than being
      // treated as a failed lookup.
      if (res.source === "live" && Array.isArray(res.rules)) {
        store.set({
          rules: res.rules.map((r) => ({
            name: r.name,
            action: r.action,
            detail: r.expression,
            enabled: r.enabled,
            llm: r.llm,
          })),
          source: "live",
        });
      }
    })
    .catch(() => {
      /* keep the fallback already in the store */
    });
  return inflight;
}

export function useZoneRules(): ZoneRulesState {
  const state = useStore(store);
  useEffect(() => {
    void load();
  }, []);
  return state;
}

// Is a fired rule (known only by name, from firewallEventsAdaptive) one of the
// zone's AI Security rules? Live data answers by expression — ground truth, so
// a renamed rule stays classified. Only rules absent from the list fall through
// to the name heuristic in data.ts.
export function classifyRule(name: string, state: ZoneRulesState): boolean {
  const hit = state.rules.find((r) => r.name.toLowerCase() === name.trim().toLowerCase());
  if (hit) return hit.llm;
  return isLlmRule(name);
}
