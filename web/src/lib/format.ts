import { UNSAFE_TOPICS } from "./data";

export function fmtTime(d?: Date): string {
  return (d ?? new Date()).toLocaleTimeString("en-GB", { hour12: false });
}

// USD cost → short "~$" string, or null when unknown.
export function fmtCost(c?: number | null): string | null {
  if (c == null) return null;
  if (c === 0) return "~$0";
  if (c < 0.01) return "~$" + c.toFixed(6);
  return "~$" + c.toFixed(4);
}

// Unsafe-topic code → "S2 (Non-violent crimes)".
export function topicLabel(code: string): string {
  return UNSAFE_TOPICS[code] ? `${code} (${UNSAFE_TOPICS[code]})` : code;
}
