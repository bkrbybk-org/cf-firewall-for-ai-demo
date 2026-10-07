// Nearest-rank percentile, the browser's copy of src/percentile.ts (the web tree
// cannot import from the Worker's). Same rule, same reason: the value at 1-based
// rank ⌈n · pct / 100⌉ of the sorted values. Truncating instead of ceiling once
// under-reported every p50/p95 for a month (PROGRESS bug #24); percentile.test.ts
// pins this copy to the same real rows that caught it, so the two cannot drift.
export function nearestRank(n: number, pct: number): number {
  return Math.floor((n * pct + 99) / 100);
}

// p-th percentile of `values` (any order), or null for none — never 0 for "no data".
export function percentile(values: number[], pct: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[nearestRank(sorted.length, pct) - 1];
}
