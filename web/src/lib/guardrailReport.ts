// The External guardrails tab as a file: a Markdown report to hand to someone, and the same numbers as JSON to
// re-check. Built from exactly what the tab shows (GET /api/guardrail-analytics), so the file can never claim more
// than the page — and it carries the page's honesty marks: the window and traffic it covers, "≈" when Analytics
// Engine sampled, "≥" when the read was capped, "—" for a latency nobody measured.
//
// The data holds no prompt or reply text (src/guardrailLog.ts), only names. Names still go through mdText — a
// vendor's detector name is text this app did not write, and must not be able to break a table or open a link.
import { mdText } from "./benchmarkReport";
import type { ExternalGuardrailProvider, GuardrailAnalytics } from "./types";

export const GUARDRAIL_REPORT_SCHEMA = "cf-ai-guardrail-verdicts/1";

export interface GuardrailReport {
  schema: typeof GUARDRAIL_REPORT_SCHEMA;
  generatedAt: string; // ISO, UTC
  window: { hours: number; since: string; until: string; traffic: "chat" | "redteam" | "all" };
  // How far the numbers can be trusted — the same flags the page shows as a banner.
  quality: { sampled: boolean; capped: boolean; rowsRead: number; rowsDropped: number };
  totals: GuardrailAnalytics["totals"];
  vendors: (GuardrailAnalytics["vendors"][number] & { label: string })[];
  disagreements: {
    count: number;
    latest: { at: string; ray: string; check: "prompt" | "reply"; verdicts: { vendor: string; outcome: "block" | "allow"; alerts: boolean }[] }[];
  };
  series: GuardrailAnalytics["series"];
  bucket: GuardrailAnalytics["bucket"];
}

export function buildGuardrailReport(
  d: GuardrailAnalytics,
  label: (provider: ExternalGuardrailProvider) => string,
  now: Date = new Date(),
): GuardrailReport {
  return {
    schema: GUARDRAIL_REPORT_SCHEMA,
    generatedAt: now.toISOString(),
    window: { hours: d.rangeHours, since: d.since, until: d.until, traffic: d.source },
    quality: { sampled: d.sampled, capped: d.capped, rowsRead: d.rowsRead, rowsDropped: d.rowsDropped },
    totals: d.totals,
    vendors: d.vendors.map((v) => ({ ...v, label: label(v.provider) })),
    disagreements: {
      count: d.disagreements.count,
      latest: d.disagreements.latest.map((x) => ({
        at: new Date(x.ts).toISOString(),
        ray: x.ray,
        check: x.dir,
        verdicts: x.verdicts.map((v) => ({ vendor: label(v.provider), outcome: v.outcome, alerts: v.alerts })),
      })),
    },
    series: d.series,
    bucket: d.bucket,
  };
}

const TRAFFIC: Record<GuardrailReport["window"]["traffic"], string> = {
  chat: "chat traffic (Red Team runs excluded)",
  redteam: "Red Team runs only",
  all: "all traffic (chat and Red Team runs)",
};

function table(head: string[], rows: string[][], right: number[] = []): string[] {
  return [
    `| ${head.join(" | ")} |`,
    `| ${head.map((_, i) => (right.includes(i) ? "---:" : "---")).join(" | ")} |`,
    ...rows.map((r) => `| ${r.join(" | ")} |`),
  ];
}

export function guardrailReportToMarkdown(r: GuardrailReport, detectionLabel: (name: string) => string = (n) => n): string {
  const mark = r.quality.sampled ? "≈" : r.quality.capped ? "≥" : "";
  const n = (v: number) => `${mark}${Math.round(v).toLocaleString("en-US")}`;
  const ms = (v: number | null) => (v == null ? "—" : `${Math.round(v)} ms`);
  const det = (name: string) =>
    mdText(name.startsWith("prompt:") ? `${detectionLabel(name.slice(7))} (prompt)` : detectionLabel(name));
  const t = r.totals;
  const L: string[] = [];

  L.push(`# External guardrail verdicts — last ${r.window.hours === 168 ? "7 days" : `${r.window.hours}h`}`, "");
  L.push(
    `- **Window:** ${r.window.since} → ${r.window.until} (UTC)`,
    `- **Traffic:** ${TRAFFIC[r.window.traffic]}`,
    `- **Report generated:** ${r.generatedAt} (UTC)`,
    `- **Source:** Workers Analytics Engine, one data point per vendor per check — vendor names, outcomes and detector names only; no prompt or reply text`,
    "",
  );
  if (r.quality.sampled) {
    L.push(
      `> **Estimated.** Analytics Engine sampled some verdicts in this window, so counts are estimates (≈). Latency and disagreements cover the stored rows only.`,
      "",
    );
  }
  if (r.quality.capped) {
    L.push(`> **A floor, not a total.** The read stopped at ${r.quality.rowsRead.toLocaleString("en-US")} rows, so counts are at least what is shown (≥).`, "");
  }
  if (r.quality.rowsDropped > 0) {
    L.push(`> ${r.quality.rowsDropped} row(s) of an unknown shape were skipped, not counted.`, "");
  }

  L.push("## Summary", "");
  L.push(
    `- **Vendor verdicts:** ${n(t.verdicts)} across ${t.turns} turn(s)`,
    `- **Blocks:** ${n(t.block)}`,
    `- **Allowed with alerts:** ${n(t.alerts)} (the vendor saw something and did not block)`,
    `- **No verdict:** ${n(t.error + t.failedOpen)} — ${n(t.error)} fail closed (the turn stopped), ${n(t.failedOpen)} fail open (the turn went on unchecked)`,
    "",
  );

  L.push("## Verdicts per vendor", "");
  if (r.vendors.length === 0) {
    L.push("No external guardrail checked anything in this window.", "");
  } else {
    L.push(
      ...table(
        ["Vendor", "Check", "Checked", "Block", "Allow", "of which alerts", "No verdict (closed / open)", "Not run", "p50 / p95", "Top detections"],
        r.vendors.map((v) => [
          mdText(v.label),
          v.dir,
          n(v.checked),
          n(v.block),
          n(v.allow),
          n(v.alerts),
          `${n(v.error + v.failedOpen)} (${n(v.error)} / ${n(v.failedOpen)})`,
          n(v.notRun),
          `${ms(v.p50Ms)} / ${ms(v.p95Ms)}${v.latencyN ? ` (n=${v.latencyN})` : ""}`,
          v.topDetections.length ? v.topDetections.map((x) => `${det(x.name)} ${n(x.count)}`).join(", ") : "—",
        ]),
        [2, 3, 4, 5, 6, 7],
      ),
      "",
      "*Allow* counts every allow; allows with alerts and with a redaction requested (not applied) are inside it. *No verdict* is an error: the operator's fail mode decided. *Not run* is skipped — an earlier vendor stopped the turn, or the vendor does not check replies. Latency is nearest rank over the checks that ran.",
      "",
    );
  }

  L.push("## Where the vendors disagreed", "");
  L.push(`${r.disagreements.count} turn(s) where one vendor blocked and another allowed the same text (errors are not counted as verdicts)${r.quality.sampled ? " — over stored rows only" : ""}.`, "");
  if (r.disagreements.latest.length) {
    L.push(
      ...table(
        ["When (UTC)", "Ray", "Check", "Verdicts"],
        r.disagreements.latest.map((x) => [
          x.at,
          mdText(x.ray),
          x.check,
          x.verdicts.map((v) => `${mdText(v.vendor)}: ${v.outcome}${v.outcome === "allow" && v.alerts ? " (alerts)" : ""}`).join("; "),
        ]),
      ),
      "",
    );
    if (r.disagreements.count > r.disagreements.latest.length) {
      L.push(`The latest ${r.disagreements.latest.length} are listed.`, "");
    }
  }
  return L.join("\n");
}

export function guardrailReportFilename(r: GuardrailReport, ext: "md" | "json"): string {
  const stamp = r.generatedAt.slice(0, 16).replace(/[-:]/g, "").replace("T", "-");
  return `guardrail-verdicts-${r.window.hours}h-${r.window.traffic}-${stamp}.${ext}`;
}
