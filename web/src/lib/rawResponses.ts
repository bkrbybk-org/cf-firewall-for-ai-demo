// Whether this viewer's chat asks for each guardrail vendor's RAW response (`includeRaw`).
//
// A per-viewer debug switch, so it lives in this browser's storage like the card layout
// (lib/cardLayout.ts): it changes only what this viewer's own /api/chat calls ask for.
// Off unless the stored value is exactly "on" — a raw body can quote the prompt and
// whatever the vendor detected, so nothing but an explicit choice turns it on, and
// storage that is missing, blocked or throws reads as off.
export const RAW_RESPONSES_KEY = "guardrailRawResponses";

type StorageLike = Pick<Storage, "getItem" | "setItem">;

export function parseShowRaw(raw: string | null | undefined): boolean {
  return raw === "on";
}

export function readShowRaw(storage: StorageLike | null | undefined): boolean {
  try {
    return parseShowRaw(storage?.getItem(RAW_RESPONSES_KEY));
  } catch {
    return false;
  }
}

// Returns whether the choice was persisted; when it was not, the caller still applies it
// for this page's lifetime.
export function writeShowRaw(storage: StorageLike | null | undefined, on: boolean): boolean {
  try {
    if (!storage) return false;
    storage.setItem(RAW_RESPONSES_KEY, on ? "on" : "off");
    return true;
  } catch {
    return false;
  }
}
