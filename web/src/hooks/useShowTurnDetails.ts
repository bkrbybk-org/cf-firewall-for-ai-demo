import { createViewerFlag } from "./useViewerFlag";
import { TURN_DETAILS_KEY, parseShowTurnDetails } from "../lib/turnDetails";

// Shown unless explicitly hidden (lib/turnDetails.ts).
export const useShowTurnDetails = createViewerFlag(TURN_DETAILS_KEY, parseShowTurnDetails).use;
