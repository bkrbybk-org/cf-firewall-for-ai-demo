// Which time buckets a capped read actually covers (PROGRESS bug #23).
//
// /api/analytics and /api/gateway-analytics read the NEWEST N rows of a window,
// then bucket them. When the cap is hit, every bucket older than the oldest row
// read was simply never looked at — but the bucket scaffold pre-fills it with
// zeros, so the chart drew "no activity" where the truth is "not read". Measured
// on prod: 24 h view, 18 of 25 hourly buckets drawn as zero; 7 d view, 6 of 8
// days. That breaks the house rule that "no data" is never rendered as zero.
//
// The fix keeps the exact rows (the Groups datasets are uncapped but SAMPLED,
// per Cloudflare's docs — estimates, not counts) and says which buckets they
// cover:
//   read: "none"    — the bucket ends before the oldest row read: nothing known.
//   read: "partial" — the bucket holding the oldest row read: older rows in the
//                     same bucket may be missing, so its count is a floor.
//   (absent)        — fully read.
// Nothing is tagged when the read was not capped.

export type ReadCoverage = "partial" | "none";

export function markReadCoverage<T extends { t: string; read?: ReadCoverage }>(
  series: T[],
  capped: boolean,
  oldestReadIso: string | null,
  stepMs: number,
): T[] {
  if (!capped) return series;
  // Capped with no rows at all cannot happen for a real cap (it means N rows
  // were read); treat a missing timestamp as "nothing known" rather than
  // silently claiming full coverage.
  const oldest = oldestReadIso ? Date.parse(oldestReadIso) : NaN;
  return series.map((row) => {
    const start = Date.parse(row.t);
    if (Number.isNaN(oldest)) return { ...row, read: "none" as const };
    if (start + stepMs <= oldest) return { ...row, read: "none" as const };
    if (start <= oldest) return { ...row, read: "partial" as const };
    return row;
  });
}
