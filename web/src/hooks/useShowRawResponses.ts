import { createViewerFlag } from "./useViewerFlag";
import { RAW_RESPONSES_KEY, parseShowRaw } from "../lib/rawResponses";

// Off unless explicitly on: a raw body can quote the prompt (lib/rawResponses.ts).
const flag = createViewerFlag(RAW_RESPONSES_KEY, parseShowRaw);

// Also read outside React, at send time (useChat), so a toggle takes effect on the next prompt.
export const showRawResponses = flag.get;
export const useShowRawResponses = flag.use;
