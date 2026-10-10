// Reads the body of a 403 from the Cloudflare edge into what the red card says.
//
// Two shapes are structured:
//  - the one this app's docs first proposed: {"blocked": true, "detection": "pii", "reason": "…"};
//  - the one the deployed zone's WAF rules actually return (Custom JSON, seen on prod 2026-08-03):
//    {"error": "request_blocked", "reason_code": "LLM_PII_BLOCKED", "message": "…", "detail": "…"}.
// Anything else — Cloudflare's HTML block page, Access, an empty body — is unstructured,
// and the card must not claim to know who refused the request.
//
// Honesty rule: a reason_code is mapped to a detection type ONLY when that exact code
// has been seen on the live zone. An unrecognised code still shows the rule's own
// message and code (the rule identified itself), but no detection label is invented
// from the code's spelling — the edge verdict under the card names the rule that fired.

export type EdgeDetection = "pii" | "injection" | "unsafe_topic" | "waf";

// Every entry here was observed in a real prod response; add one only from a payload.
export const REASON_CODE_DETECTIONS: Record<string, EdgeDetection> = {
  LLM_PII_BLOCKED: "pii", // prod, 2026-08-03 (PROGRESS Open bug #4)
};

const LEGACY_DETECTIONS = new Set<string>(["pii", "injection", "unsafe_topic", "waf"]);

// ── a reason code, read against the live rule definitions ─────────────────────
// REASON_CODE_DETECTIONS holds only codes seen in a real response. For any other code, the zone's own rules say
// which rule answers with it (each block rule's Custom JSON, read by /api/zone-rules) and the rule's EXPRESSION says
// what it detects. That is the rule as written now, not proof of what fired: the card says "per the rule's
// definition", and claims nothing when the rules disagree.
//
// Rules are matched whether or not they are on: a block response carrying a code proves a rule answered at the
// time, and the zone's AI block rules are kept off on purpose between demos (Open bugs #28), so requiring
// "enabled" would drop exactly the rules that block when switched on.
export interface ReasonCodeRule {
  name: string; // the rule's description — one name only, when every candidate shares it
  rulesets: string[]; // the custom rulesets holding a rule with this code (names repeat across Monitor / Protection)
  detection?: EdgeDetection; // only when every candidate's expression detects the same one thing
}

export function detectionOfExpression(expr: string | undefined): EdgeDetection | undefined {
  if (!expr) return undefined;
  const kinds = new Set<EdgeDetection>();
  if (/\bcf\.llm\.prompt\.injection_score\b/.test(expr)) kinds.add("injection");
  if (/\bcf\.llm\.prompt\.pii_(?:detected|categories)\b/.test(expr)) kinds.add("pii");
  if (/\bcf\.llm\.prompt\.unsafe_topic_(?:detected|categories)\b/.test(expr)) kinds.add("unsafe_topic");
  return kinds.size === 1 ? [...kinds][0] : undefined;
}

export function ruleForReasonCode(
  code: string | undefined,
  rules: readonly { name: string; action: string; detail?: string; ruleset?: string; reasonCode?: string }[],
): ReasonCodeRule | null {
  if (!code) return null;
  const hits = rules.filter((r) => r.action === "block" && r.reasonCode === code);
  if (hits.length === 0) return null;
  const names = new Set(hits.map((r) => r.name));
  const dets = new Set(hits.map((r) => detectionOfExpression(r.detail)));
  return {
    name: names.size === 1 ? hits[0].name : `${names.size} rules`,
    rulesets: [...new Set(hits.flatMap((r) => (r.ruleset ? [r.ruleset] : [])))],
    ...(dets.size === 1 && [...dets][0] ? { detection: [...dets][0] } : {}),
  };
}

export interface EdgeBlock {
  structured: boolean; // the body identified itself as a rule's response
  detection?: EdgeDetection; // only when known for certain
  reason?: string; // the rule's own human-readable message
  code?: string; // the rule's reason_code, shown as-is
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

export function parseEdgeBlock(data: unknown): EdgeBlock {
  if (!data || typeof data !== "object" || Array.isArray(data)) return { structured: false };
  const d = data as Record<string, unknown>;

  if (d.blocked === true) {
    const det = str(d.detection);
    return {
      structured: true,
      detection: det && LEGACY_DETECTIONS.has(det) ? (det as EdgeDetection) : undefined,
      reason: str(d.reason),
    };
  }

  const code = str(d.reason_code);
  if (code) {
    const message = str(d.message);
    const detail = str(d.detail);
    return {
      structured: true,
      detection: Object.hasOwn(REASON_CODE_DETECTIONS, code) ? REASON_CODE_DETECTIONS[code] : undefined,
      reason: message && detail ? `${message} ${detail}` : (message ?? detail),
      code,
    };
  }

  return { structured: false };
}
