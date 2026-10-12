// #13: each vendor's live false-block rate, from the Red Team's own labels (Analytics → External guardrails).
//
// The Red Team page says, per prompt, whether it is harmless or an attack (an `x-demo-expect` header the Worker keeps
// only on Red Team turns — src/guardrailLog.ts). A block on a harmless prompt is a FALSE block; on an attack, a catch.
// The rules this view keeps:
//   - The denominator is VERDICTS (block + allow). An error is not a verdict, so it is neither a false block nor a
//     pass — counting it either way would move the rate with a vendor's outages.
//   - No verdicts → "—", never 0 %: nothing was measured.
//   - A small sample says so: under MIN_FOR_RATE verdicts the rate is shown with its counts and flagged, because 1 of
//     2 reads as "50 %" and means almost nothing.
//   - Labels exist from 2026-10-12 on; older Red Team verdicts carry none and are not in these numbers.
import type { ExternalGuardrailProvider, GuardrailVendorStats } from "./types";

export const MIN_FOR_RATE = 10;

export interface RateCell {
  verdicts: number;
  block: number;
  rate: string; // "12 %" | "—"
  small: boolean; // verdicts > 0 but below MIN_FOR_RATE
}

export interface LabelledRow {
  provider: ExternalGuardrailProvider;
  dir: "prompt" | "reply";
  falseBlocks: RateCell; // on harmless prompts
  catches: RateCell; // on attacks
}

function cell(c: { verdicts: number; block: number } | undefined): RateCell {
  const verdicts = c?.verdicts ?? 0;
  const block = c?.block ?? 0;
  return {
    verdicts,
    block,
    rate: verdicts > 0 ? `${Math.round((block / verdicts) * 100)} %` : "—",
    small: verdicts > 0 && verdicts < MIN_FOR_RATE,
  };
}

// One row per vendor and check that has at least one labelled verdict; [] when none does (an older Worker sends no
// `labelled`, which reads the same: nothing labelled).
export function labelledRows(vendors: GuardrailVendorStats[]): LabelledRow[] {
  return vendors
    .filter((v) => (v.labelled?.benign.verdicts ?? 0) + (v.labelled?.attack.verdicts ?? 0) > 0)
    .map((v) => ({
      provider: v.provider,
      dir: v.dir,
      falseBlocks: cell(v.labelled?.benign),
      catches: cell(v.labelled?.attack),
    }));
}
