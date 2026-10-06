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
//     (explanations, matched spans), numbers can be ids;
//   - the ONE exception: a verdict that is a string, not a boolean (Cato's
//     `required_action.action_type`, documented only as "block_action"). Its allow
//     value is unknown, and without seeing it the parser cannot be verified. Such a
//     field is named per provider (`reveal`, an exact dotted path) and its value is
//     shown only when it is a bare lowercase token — `^[a-z][a-z0-9_]{0,39}$`, no
//     spaces, digits-only or punctuation — which an enum value is and an echoed
//     sentence, SSN or id is not. Anything else at that path is still just "string".

export type Shape = string | boolean | Shape[] | { [k: string]: Shape };

const MAX_DEPTH = 6;
const MAX_KEYS = 40;
const MAX_KEY_LEN = 60;
const REVEALABLE = /^[a-z][a-z0-9_]{0,39}$/;

export interface ShapeOptions {
  // Exact dotted paths from the root, array elements adding no segment
  // (`a.b` matches `{a: {b}}` and `{a: [{b}]}`).
  reveal?: readonly string[];
}

export function shapeOf(v: unknown, opts: ShapeOptions = {}, depth = 0, path = ""): Shape {
  if (v === null) return "null";
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    return opts.reveal?.includes(path) && REVEALABLE.test(v) ? `string = ${v}` : "string";
  }
  if (typeof v === "number") return "number";
  if (depth >= MAX_DEPTH) return Array.isArray(v) ? "array(…)" : "object(…)";
  if (Array.isArray(v)) {
    // The first element stands for the rest; the length says how many.
    return v.length === 0 ? ["empty"] : [`length ${v.length}`, shapeOf(v[0], opts, depth + 1, path)];
  }
  if (typeof v === "object") {
    const out: Record<string, Shape> = {};
    const keys = Object.keys(v as object);
    for (const k of keys.slice(0, MAX_KEYS)) {
      const key = k.length > MAX_KEY_LEN ? k.slice(0, MAX_KEY_LEN) + "…" : k;
      out[key] = shapeOf((v as Record<string, unknown>)[k], opts, depth + 1, path ? `${path}.${k}` : k);
    }
    if (keys.length > MAX_KEYS) out["…"] = `${keys.length - MAX_KEYS} more keys`;
    return out;
  }
  return typeof v;
}
