// Which layout the chat's external guardrail card uses: "columns" (one mini card per
// vendor, option B), "compact" (one row per vendor, option A) or "table" (one column
// per vendor, one row per field — the vendors read side by side).
//
// A per-viewer presentation preference, so it lives in this browser's storage, not
// in D1: two people watching the same demo may each want their own, and nothing on
// the server depends on it. Storage can be absent or throw (private window, blocked
// site data, previews), so every read and write is guarded and the default —
// columns — is what renders when nothing can be read.
export const CARD_LAYOUTS = ["columns", "compact", "table"] as const;
export type CardLayout = (typeof CARD_LAYOUTS)[number];

export const CARD_LAYOUT_KEY = "guardrailCardLayout";
export const DEFAULT_CARD_LAYOUT: CardLayout = "columns";

// Only an exact layout name — a missing key, an old value, a hand edit all fall back
// to the default rather than to whichever layout happens to be last.
export function parseCardLayout(raw: string | null | undefined): CardLayout {
  return (CARD_LAYOUTS as readonly string[]).includes(raw ?? "") ? (raw as CardLayout) : DEFAULT_CARD_LAYOUT;
}

type StorageLike = Pick<Storage, "getItem" | "setItem">;

export function readCardLayout(storage: StorageLike | null | undefined): CardLayout {
  try {
    return parseCardLayout(storage?.getItem(CARD_LAYOUT_KEY));
  } catch {
    return DEFAULT_CARD_LAYOUT;
  }
}

// Returns whether the choice was persisted. When it was not, the caller still applies
// it for this page's lifetime — the switch must not look broken in a private window.
export function writeCardLayout(storage: StorageLike | null | undefined, layout: CardLayout): boolean {
  try {
    if (!storage) return false;
    storage.setItem(CARD_LAYOUT_KEY, layout);
    return true;
  } catch {
    return false;
  }
}
