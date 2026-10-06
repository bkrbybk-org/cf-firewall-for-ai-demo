// Whether the chat shows the per-turn details under each answer: the control strip
// (Edge WAF → external guardrails → AI Gateway Guardrails → Model) and the edge-verdict
// line ("checking Cloudflare edge log…", which polls /api/verdict for that ray).
//
// A per-viewer presentation choice, stored in this browser. Shown unless the stored value
// is exactly "off": these are the demo's evidence of which control did what, so a missing
// or unreadable value must not hide them. Hiding changes nothing on the server and
// nothing anyone else sees; the prompt log's own verdict column is unaffected.
export const TURN_DETAILS_KEY = "chatTurnDetails";

export function parseShowTurnDetails(raw: string | null | undefined): boolean {
  return raw !== "off";
}
