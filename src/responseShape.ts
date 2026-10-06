// The SHAPE of a vendor's JSON response — field names and types, never text.
//
// Why it exists: a new guardrail stays unverified until its parser has been checked
// against a real payload (CLAUDE.md — both earlier vendors' docs were wrong
// somewhere). The admin presses *Test connection* in their own browser; this shape
// is what they can hand back for that check without handing over anything the
// response says.
//
// What it may carry, and why that is safe:
//   - keys (schema field names; for map-like objects such as AIDR's detectors, the
//     detector names — vendor vocabulary, not prompt text), capped per object;
//   - types, and array lengths;
//   - booleans AS VALUES — `is_safe: false`, `flagged: true` are the verdict fields
//     being verified, and a boolean cannot leak prompt content;
//   - never a string's content or a number's value: strings can echo the prompt
//     (explanations, matched spans), numbers can be ids.

export type Shape = string | boolean | Shape[] | { [k: string]: Shape };

const MAX_DEPTH = 6;
const MAX_KEYS = 40;
const MAX_KEY_LEN = 60;

export function shapeOf(v: unknown, depth = 0): Shape {
  if (v === null) return "null";
  if (typeof v === "boolean") return v;
  if (typeof v === "string") return "string";
  if (typeof v === "number") return "number";
  if (depth >= MAX_DEPTH) return Array.isArray(v) ? "array(…)" : "object(…)";
  if (Array.isArray(v)) {
    // The first element stands for the rest; the length says how many.
    return v.length === 0 ? ["empty"] : [`length ${v.length}`, shapeOf(v[0], depth + 1)];
  }
  if (typeof v === "object") {
    const out: Record<string, Shape> = {};
    const keys = Object.keys(v as object);
    for (const k of keys.slice(0, MAX_KEYS)) {
      const key = k.length > MAX_KEY_LEN ? k.slice(0, MAX_KEY_LEN) + "…" : k;
      out[key] = shapeOf((v as Record<string, unknown>)[k], depth + 1);
    }
    if (keys.length > MAX_KEYS) out["…"] = `${keys.length - MAX_KEYS} more keys`;
    return out;
  }
  return typeof v;
}
