// Wilson score interval for a rate k/n — the benchmark's margin of error. Chosen over
// the textbook ±1.96·√(p(1−p)/n) because that collapses to a zero-width interval at
// 0/n and n/n, and the benchmark lives exactly there: "3 of 3 caught" is not a
// certainty, and Wilson says so (it gives roughly 44–100%). Well behaved at small n.
export const Z95 = 1.96;

export interface Interval {
  lo: number; // percent, 0–100
  hi: number;
}

export function wilson(k: number, n: number, z: number = Z95): Interval | null {
  if (!Number.isFinite(k) || !Number.isFinite(n) || n <= 0 || k < 0 || k > n) return null;
  const p = k / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { lo: Math.max(0, (centre - half) * 100), hi: Math.min(100, (centre + half) * 100) };
}

// "44–100%", rounded outward so the printed range never looks tighter than it is.
export function fmtInterval(i: Interval | null): string {
  if (!i) return "—";
  return `${Math.floor(i.lo)}–${Math.ceil(i.hi)}%`;
}
