// Custom metadata for AI Gateway requests, shared by the input panel (which
// previews the parsed pairs) and the send pipeline (which transmits them), so
// what the user sees is exactly what gets sent.

// AI Gateway keeps only the first five entries per request and drops the rest
// without an error — mirrored from src/config.ts MAX_METADATA_ENTRIES.
export const MAX_METADATA_ENTRIES = 5;

// "plan=paid, orgId=acme" → { plan: "paid", orgId: "acme" }.
// Malformed pairs are dropped; entries past the cap are discarded here so the
// truncation is visible in the preview rather than happening silently upstream.
export function parseMetadata(raw: string): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const pair of raw.split(",")) {
    const i = pair.indexOf("=");
    if (i < 1) continue;
    const k = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (k && v && Object.keys(out).length < MAX_METADATA_ENTRIES) out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}
