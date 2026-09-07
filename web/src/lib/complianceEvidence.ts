// Resolves a compliance-page Evidence descriptor (compliance.ts) into a
// rendered value, using the two analytics payloads the app already fetches —
// Analytics (GET /api/analytics) and PromptAnalytics (GET /api/prompt-analytics).
// No fetching happens here: this is a pure function of data already in hand,
// so it is unit-testable without a network or a Worker.
//
// Honesty rules (companion to the ones in compliance.ts's header):
//  - "Not configured" and "no traffic in the window" are never rendered as a
//    bare 0. A 0 must always mean a genuine, measured zero — e.g. prompts
//    WERE scored and NONE were blocked — never "nobody sent anything, so the
//    counter never moved." The three are distinct EvidenceStatus values and
//    the caller must render them distinctly, not just numerically.
//  - Every "ok" result carries the window it was measured over. A number
//    with no stated window is a lie by omission — see CompliancePage, which
//    always renders windowLabel next to the headline.
//  - Analytics.truncated means the 500-row dataset cap was hit, so every
//    count derived from that payload in this window is a floor, not a total
//    (mirrors EdgeTab's treatment in components/analytics/EdgeTab.tsx). The
//    `floor` flag is set whenever that's true, and headline text is prefixed
//    "at least" — never presented as an exact number.
//  - PromptAnalytics has no `truncated` field (it's a D1 SQL rollup, not a
//    capped GraphQL query), so redaction/log counts are never marked as a
//    floor.
import type { Analytics, PromptAnalytics } from "./types";
import type { Evidence } from "./compliance";

export type EvidenceStatus = "unconfigured" | "no-data" | "ok";

export interface EvidenceResult {
  status: EvidenceStatus;
  // Always set, even for "unconfigured" — callers that skip rendering the
  // chip entirely on "unconfigured" (as CompliancePage does) can ignore it.
  windowLabel: string;
  // Set for "ok" only. Pre-formatted, e.g. "1,204 prompts scored · 38 blocked".
  headline?: string;
  // True when headline's numbers are a floor (Analytics.truncated) rather
  // than an exact total.
  floor?: boolean;
}

const fmt = (n: number): string => n.toLocaleString("en-US");
const plural = (n: number, word: string): string => `${fmt(n)} ${word}${n === 1 ? "" : "s"}`;

function windowLabel(hours: number): string {
  if (hours > 0 && hours % 24 === 0) {
    const days = hours / 24;
    return `last ${days} day${days === 1 ? "" : "s"}`;
  }
  return `last ${hours}h`;
}

// Same block/drop classification EdgeTab and GatewayTab use (see
// components/analytics/EdgeTab.tsx classifyAction) — re-declared locally
// rather than imported, since lib/ has no dependency on the analytics
// components and this is a two-line regex, not shared state.
function blockedCount(actions: Record<string, number> | undefined): number {
  return Object.entries(actions ?? {})
    .filter(([name]) => /block|drop/i.test(name))
    .reduce((n, [, c]) => n + c, 0);
}

function unconfigured(win: string): EvidenceResult {
  return { status: "unconfigured", windowLabel: win };
}
function noData(win: string): EvidenceResult {
  return { status: "no-data", windowLabel: win };
}

export function resolveEvidence(
  evidence: Evidence,
  analytics: Analytics | null,
  promptAnalytics: PromptAnalytics | null,
  hours: number,
): EvidenceResult {
  const win = windowLabel(hours);

  switch (evidence.metric) {
    // MEASURE 2.7 — count of scored requests + blocked count. `aiScored` is
    // the denominator: zero means nothing was scored in the window (no-data),
    // never "zero blocked" (a real, and good, outcome once scoring happened).
    case "injection-scoring": {
      if (!analytics || analytics.configured === false) return unconfigured(win);
      const scored = analytics.aiScored ?? 0;
      if (scored === 0) return noData(win);
      const floor = analytics.truncated === true;
      const at = floor ? "at least " : "";
      const blocked = blockedCount(analytics.actions);
      return {
        status: "ok",
        windowLabel: win,
        headline: `${at}${plural(scored, "prompt")} scored · ${at}${fmt(blocked)} blocked`,
        floor,
      };
    }

    // MEASURE 2.10 — PII detections at the edge + prompt-log redaction count.
    // The two sources are independent (edge scanning vs. D1 rollup of what
    // actually reached the Worker), so each is only reported when it has its
    // own denominator > 0; "no-data" only fires when BOTH are silent.
    case "pii-detection": {
      const edgeOk = !!analytics && analytics.configured !== false;
      const logOk = !!promptAnalytics && promptAnalytics.configured !== false;
      if (!edgeOk && !logOk) return unconfigured(win);
      const scored = edgeOk ? (analytics!.aiScored ?? 0) : 0;
      const logged = logOk ? (promptAnalytics!.total ?? 0) : 0;
      if (scored === 0 && logged === 0) return noData(win);
      const floor = edgeOk && analytics!.truncated === true;
      const at = floor ? "at least " : "";
      const parts: string[] = [];
      if (edgeOk && scored > 0) {
        const pii = analytics!.piiRequests ?? 0;
        parts.push(`${at}${fmt(pii)} of ${at}${plural(scored, "scored prompt")} flagged PII at the edge`);
      }
      if (logOk && logged > 0) {
        const red = promptAnalytics!.redactions ?? 0;
        parts.push(`${plural(red, "redaction")} in the prompt log`);
      }
      return { status: "ok", windowLabel: win, headline: parts.join(" · "), floor };
    }

    // MEASURE 2.6 — unsafe-topic category event counts. Same no-data
    // reasoning as injection-scoring: `aiScored` is the denominator, not the
    // topic count itself (which is legitimately 0 once scoring is active).
    case "unsafe-topics": {
      if (!analytics || analytics.configured === false) return unconfigured(win);
      const scored = analytics.aiScored ?? 0;
      if (scored === 0) return noData(win);
      const floor = analytics.truncated === true;
      const at = floor ? "at least " : "";
      const topics = analytics.unsafeTopics ?? [];
      const total = topics.reduce((n, t) => n + t.count, 0);
      const cats = topics.length;
      const catWord = cats === 1 ? "category" : "categories";
      return {
        status: "ok",
        windowLabel: win,
        headline: `${at}${plural(total, "hit")} across ${fmt(cats)} ${catWord}`,
        floor,
      };
    }

    // MEASURE 3.1 — the window actually covered and its event volume. There
    // is no separate denominator here (totalEvents IS the metric), so an
    // empty window and a "genuine zero" are the same observable state: no
    // security events were recorded, full stop.
    case "risk-window": {
      if (!analytics || analytics.configured === false) return unconfigured(win);
      const total = analytics.totalEvents ?? 0;
      if (total === 0) return noData(win);
      const floor = analytics.truncated === true;
      const at = floor ? "at least " : "";
      return { status: "ok", windowLabel: win, headline: `${at}${plural(total, "event")} recorded`, floor };
    }
  }
}
