// Red Team: how long each guardrail took — the cost side of "who is good". Pure;
// components/redteam/VendorScorecard.tsx renders it next to the catch rate.
//
// What these numbers are, and are not:
//  - A guardrail's latency is its own call as the Worker timed it (fetch start →
//    parsed response): Cloudflare-colo-to-vendor network plus the vendor's work.
//    It depends on the region chosen and where the colo is, so two vendors in
//    different regions are not on equal footing — the UI says so.
//  - Only real verdicts count (block / allow / alerts). An error is excluded:
//    a timeout "takes" our 5-second cap, which measures us, not the vendor; a
//    connection refused takes ~0 ms. Either would bend the percentiles. They are
//    counted beside the stats instead, never silently dropped.
//  - The edge has no latency here: its scan runs before the Worker is invoked and
//    is not exposed to it. That is "not measurable", never 0 ms.
//  - The STAGE latency is what the guardrails added to a prompt before the model:
//    in parallel mode the slowest call, in sequential the sum. It is reported per
//    pipeline mode, because the two are different quantities.
//  - Percentiles are nearest rank (lib/percentile.ts) — at small n, p95 is usually
//    the maximum, which is why n is always shown beside them.
import { percentile } from "./percentile";
import type { RtRunResult } from "./redteam";

export interface LatencyStat {
  n: number; // calls with a verdict and a timing
  p50: number | null;
  p95: number | null;
  max: number | null;
  errorsExcluded: number; // calls that errored — their time is not in the stats
  untimed: number; // verdicts with no timing (runs saved before latency was recorded)
}

const VERDICTS = new Set(["block", "allow", "alerts"]);

function stat(values: number[], errorsExcluded: number, untimed: number): LatencyStat {
  return {
    n: values.length,
    p50: percentile(values, 50),
    p95: percentile(values, 95),
    max: values.length ? Math.max(...values) : null,
    errorsExcluded,
    untimed,
  };
}

// One guardrail across a run.
export function vendorLatency(results: RtRunResult[], provider: string): LatencyStat {
  const values: number[] = [];
  let errors = 0;
  let untimed = 0;
  for (const r of results) {
    const v = r.vendors?.find((x) => x.provider === provider);
    if (!v) continue;
    if (v.verdict === "error") errors++;
    else if (VERDICTS.has(v.verdict)) {
      if (typeof v.latencyMs === "number" && Number.isFinite(v.latencyMs) && v.latencyMs >= 0) values.push(v.latencyMs);
      else untimed++;
    }
  }
  return stat(values, errors, untimed);
}

export interface StageLatency {
  mode: "parallel" | "sequential";
  stat: LatencyStat;
}

// The whole guardrail stage per prompt, split by mode. A stage in which a guardrail
// errored is excluded for the same reason as above — it would time our timeout.
export function stageLatency(results: RtRunResult[]): StageLatency[] {
  const out: StageLatency[] = [];
  for (const mode of ["parallel", "sequential"] as const) {
    const rs = results.filter((r) => r.pipelineMode === mode && r.vendors && r.vendors.length > 0);
    if (rs.length === 0) continue;
    const values: number[] = [];
    let errors = 0;
    let untimed = 0;
    for (const r of rs) {
      if (r.vendors!.some((v) => v.verdict === "error")) errors++;
      else if (typeof r.pipelineLatencyMs === "number" && Number.isFinite(r.pipelineLatencyMs) && r.pipelineLatencyMs >= 0) {
        values.push(r.pipelineLatencyMs);
      } else untimed++;
    }
    out.push({ mode, stat: stat(values, errors, untimed) });
  }
  return out;
}

// "840 ms" / "1.2 s" — coarse on purpose; a single run's latency is not precise to the ms.
export function fmtMs(ms: number | null): string {
  if (ms == null) return "—";
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}
