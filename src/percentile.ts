// Nearest-rank percentile: the value at 1-based rank ⌈n · pct / 100⌉ of the
// sorted rows. One rule, used by both the JS tests and the SQL that computes the
// prompt-log latency rollup, so the two cannot drift.
//
// Why this exists (PROGRESS bug #24): the rollup used CAST(n * 0.95 AS INTEGER),
// which TRUNCATES. Nearest-rank needs a ceiling. On real rows
// [77, 115, 800, 900, 1200, 1313, 2500] that reported p95 = 1313 instead of 2500
// and p50 = 800 instead of 900; at n = 2 "p95" was the minimum. It under-reported
// every p50/p95 for a month, worst at the small n this demo actually has.
//
// Integer arithmetic on purpose: (n·pct + 99) / 100 with integer division IS the
// ceiling for integer n and pct, needs no floating point, and needs no SQLite
// math functions (CEIL is not guaranteed to be compiled into D1's SQLite).
// For n ≥ 1 the rank is always ≥ 1, so no MAX(1, …) guard is needed.

export function nearestRank(n: number, pct: number): number {
  if (!Number.isInteger(n) || n < 1) throw new Error(`nearestRank: n must be a positive integer (got ${n})`);
  if (!Number.isInteger(pct) || pct < 1 || pct > 100) throw new Error(`nearestRank: pct must be an integer 1–100 (got ${pct})`);
  return Math.floor((n * pct + 99) / 100);
}

// The same rule as a SQL expression over an integer column (SQLite's `/` on two
// integers is integer division). `pct` is interpolated, so it is checked here —
// it is always a literal in this codebase, never input.
export function nearestRankSql(nColumn: string, pct: number): string {
  if (!Number.isInteger(pct) || pct < 1 || pct > 100) throw new Error(`nearestRankSql: bad pct ${pct}`);
  if (!/^[a-z_][a-z0-9_]*$/i.test(nColumn)) throw new Error(`nearestRankSql: bad column ${nColumn}`);
  return `((${nColumn} * ${pct} + 99) / 100)`;
}
