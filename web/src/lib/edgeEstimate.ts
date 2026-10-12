// How an edge estimate reads on a tile (Analytics → AI Security (edge), when the 500-row read is capped). The numbers
// come from Cloudflare's grouped firewall dataset (src/cloudflare.ts edgeEstimateFrom): uncapped, but sampled — so
// an estimate is always marked "≈" and is never shown as a count (bug #23's rule), and a 95% interval is shown only
// where the server got one from a single group.
import type { EstimateCi } from "./types";

export function estValue(e: EstimateCi): string {
  return `≈${Math.round(e.estimate).toLocaleString("en-US")}`;
}

export function estRate(e: EstimateCi, level: number): string {
  return e.lower != null && e.upper != null
    ? `${Math.round(level * 100)}% CI ${Math.round(e.lower).toLocaleString("en-US")}–${Math.round(e.upper).toLocaleString("en-US")} · estimated`
    : "estimated (sampled data)";
}
