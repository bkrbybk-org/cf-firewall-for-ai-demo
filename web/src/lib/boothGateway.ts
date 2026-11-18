// Which AI Gateway and which model booth mode sends with (Settings → Your preferences → Booth gateway / Booth model).
// Per-browser choices, so a booth screen can be pinned to, say, the Guardrails gateway and a given model while the
// presenter's own laptop keeps the defaults.
//
// Booth hides the detailed view's gateway and model dropdowns, and their values are in-memory page state that a reload
// resets to the Worker's defaults (CF_AI_GATEWAY_ID, DEFAULT_MODEL). Without these a booth screen silently used
// whatever those held.
import type { GatewayOption } from "./types";

export const BOOTH_GATEWAY_KEY = "boothGateway";
export const BOOTH_MODEL_KEY = "boothModel";
export const BOOTH_FORTI_MODEL_KEY = "boothFortiModel";

export interface BoothChoice {
  id: string;
  // "booth": the preference picked it. "chat": no preference, or the preferred id is not in the current list
  // (deleted, renamed, or the list has not loaded) — the chat page's value is used instead, never an unknown id.
  source: "booth" | "chat";
  // A preference is stored but is not in the list: Settings says so rather than pretend it applies.
  missing: boolean;
}

export function resolveBoothChoice(pref: string, ids: readonly string[], chatValue: string): BoothChoice {
  if (!pref) return { id: chatValue, source: "chat", missing: false };
  if (ids.includes(pref)) return { id: pref, source: "booth", missing: false };
  // An empty list means it has not loaded (or could not be read): not evidence the id is gone.
  return { id: chatValue, source: "chat", missing: ids.length > 0 };
}

export function resolveBoothGateway(pref: string, gateways: GatewayOption[], chatGatewayId: string): BoothChoice {
  return resolveBoothChoice(pref, gateways.map((g) => g.id), chatGatewayId);
}
