import { createViewerFlag } from "./useViewerFlag";

// Booth mode: the chat page as a visitor at a booth should see it — one large verdict per turn, the technical
// detail (side panels, ray ids, tokens, cost, flow trace, raw responses) hidden. A per-browser presentation choice
// (src: Settings → Your preferences, or the header toggle); it changes nothing on the server or for anyone else.
// Off unless the stored value is exactly "on": the detailed view is the demo's evidence and stays the default.
export const BOOTH_MODE_KEY = "boothMode";

export function parseBoothMode(raw: string | null | undefined): boolean {
  return raw === "on";
}

export const boothMode = createViewerFlag(BOOTH_MODE_KEY, parseBoothMode);
export const useBoothMode = boothMode.use;
