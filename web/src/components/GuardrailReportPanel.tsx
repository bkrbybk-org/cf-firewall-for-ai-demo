// "Vendor report": Prisma AIRS's own per-detection breakdown for one scan,
// fetched on demand from /api/external-guardrails/report.
//
// Collapsed by default and fetched only when opened: it costs a call to PANW,
// and most turns never need it. What it shows was allowlisted by the Worker —
// detector names, verdicts, actions, categories and counts, never the prompt's
// own content (src/prismaAirsReport.ts).
//
// Two honesty rules:
//  - verdict and action are separate columns. "malicious" + "allow" is a real,
//    common state (the profile only alerts on that detector) and must be visible.
//  - "pending" (PANW has no report under this id yet) is neither an error nor
//    "nothing detected"; it gets a retry, never an empty "clean" panel.
import { useState } from "react";
import { ChevronDown, ChevronRight, FileSearch, Loader2, RotateCw } from "lucide-react";
import { getGuardrailReport } from "../lib/api";
import type { GuardrailPipelineResult, GuardrailReport, GuardrailReportResponse } from "../lib/types";

// Service names mapped to plain words; any other value is shown as-is rather
// than hidden. The LIVE report does not use the spec's names: a real report
// (prod, 2026-10-05) carried agent_security, dlp, pi, source_code, tc,
// topic_guardrails, uf, malicious_code. The spec's spellings are kept too in
// case other tenants or versions return them.
const SERVICE_LABELS: Record<string, string> = {
  dlp: "Sensitive data (DLP)",
  uf: "URL filtering",
  urlf: "URL filtering",
  url_cats: "URL filtering",
  pi: "Prompt injection",
  injection: "Prompt injection",
  "prompt injection": "Prompt injection",
  tc: "Toxic content",
  toxic_content: "Toxic content",
  malicious_code: "Malicious code",
  source_code: "Source code",
  agent_security: "Agent threat",
  agent: "Agent threat",
  topic_guardrails: "Topic guardrails",
  topic_violation: "Topic guardrails",
  db_security: "Database security",
  ungrounded: "Contextual grounding",
};

// Labelled ("verdict malicious", "action block") rather than column-headed: the
// chat column is narrow, and a three-column grid crushed into word-per-line
// details. The label also keeps the two facts unmistakable on their own.
function Pill({ value, kind }: { value: string | null; kind: "verdict" | "action" }) {
  const v = (value ?? "").toLowerCase();
  // Amber for anything a detector flagged or a profile blocks — the external
  // guardrail's colour, never the WAF's red. Neutral otherwise.
  const hot = kind === "verdict" ? v === "malicious" : v === "block";
  return (
    <span
      title={kind === "verdict" ? "What the detector concluded" : "What the AI security profile does about it"}
      className={`rounded-full border px-1.5 py-px text-[10.5px] whitespace-nowrap ${
        hot ? "border-cf-amber/60 bg-cf-amber/10 text-cf-amber" : "border-line bg-surface text-muted"
      }`}
    >
      {kind} <b className="font-mono">{value ?? "—"}</b>
    </span>
  );
}

function ReportBody({ report }: { report: GuardrailReport }) {
  if (report.detections.length === 0) {
    return <div className="text-[11.5px] text-muted">The report lists no detection results for this scan.</div>;
  }
  return (
    <div className="flex flex-col gap-1.5">
      <ul className="flex flex-col gap-2 text-[11.5px]">
        {report.detections.map((d, i) => (
          <li key={`${d.service}:${d.dataType}:${i}`} className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
              <span className="font-semibold text-text">
                {SERVICE_LABELS[d.service] ?? d.service}
                {d.dataType && d.dataType !== "prompt" && <span className="ml-1 font-normal text-subtle">({d.dataType})</span>}
              </span>
              <Pill value={d.verdict} kind="verdict" />
              <Pill value={d.action} kind="action" />
            </div>
            {d.details.length > 0 && (
              <ul className="mt-0.5 text-[11px] break-words text-muted">
                {d.details.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      <div className="text-[10.5px] text-subtle">
        From Prisma AIRS · report_id <span className="font-mono break-all">{report.reportId}</span>
        {report.transactionId && (
          <>
            {" "}
            · transaction <span className="font-mono">{report.transactionId}</span>
          </>
        )}
        . Snippets, URLs and code from the prompt are withheld on purpose.
      </div>
    </div>
  );
}

export function GuardrailReportPanel({ reportId }: { reportId: string }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<GuardrailReportResponse | null>(null);

  async function load() {
    setLoading(true);
    try {
      setRes(await getGuardrailReport(reportId));
    } catch (e) {
      setRes({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  }

  function toggle() {
    const next = !open;
    setOpen(next);
    // Fetched once on first open; a pending or failed result is retried by hand.
    if (next && !res && !loading) void load();
  }

  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="inline-flex items-center gap-1 rounded-md text-[11.5px] font-semibold text-muted transition-colors hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <FileSearch size={12} /> Prisma AIRS report
      </button>
      {open && (
        <div className="mt-1.5 rounded-lg border border-line bg-surface-2/60 px-2.5 py-2">
          {loading && (
            <div className="flex items-center gap-1.5 text-[11.5px] text-muted">
              <Loader2 size={12} className="animate-spin" /> Fetching the report from Prisma AIRS…
            </div>
          )}
          {!loading && res?.ok && <ReportBody report={res.report} />}
          {!loading && res && !res.ok && (
            <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
              <span className={res.pending ? "text-muted" : "text-cf-red"}>
                {res.pending ? res.error : `Could not load the report — ${res.error}`}
                {res.httpStatus != null && !res.pending && <span className="font-mono"> (HTTP {res.httpStatus})</span>}
              </span>
              <button
                type="button"
                onClick={() => void load()}
                className="inline-flex items-center gap-1 rounded-md border border-line bg-surface px-1.5 py-0.5 text-[11px] text-muted hover:text-text"
              >
                <RotateCw size={11} /> Retry
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// One panel per Prisma AIRS result in a pipeline that carries a report id. Other
// providers have no per-request report API, so they get nothing here.
export function GuardrailReports({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  const withReports = pipeline.results.filter((r) => r.provider === "prisma-airs" && r.reportId);
  if (withReports.length === 0) return null;
  return (
    <>
      {withReports.map((r) => (
        <GuardrailReportPanel key={r.reportId!} reportId={r.reportId!} />
      ))}
    </>
  );
}
