// Whether this viewer's chat asks for each guardrail vendor's RAW response (`includeRaw`).
//
// A per-viewer debug switch, stored in this browser (hooks/useViewerFlag.ts): it changes
// only what this viewer's own /api/chat calls ask for. Off unless the stored value is
// exactly "on" — a raw body can quote the prompt and whatever the vendor detected, so
// nothing but an explicit choice turns it on, and storage that is missing, blocked or
// throws reads as off.
export const RAW_RESPONSES_KEY = "guardrailRawResponses";

export function parseShowRaw(raw: string | null | undefined): boolean {
  return raw === "on";
}
