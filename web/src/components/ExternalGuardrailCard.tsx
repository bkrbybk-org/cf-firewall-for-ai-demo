// Chat-side rendering of the external guardrail pipeline (Prisma AIRS, CrowdStrike AIDR):
// the card for a turn a guardrail stopped, the card for a guardrail-only turn
// (model deliberately not called), and the small per-result chips on a reply.
//
// Amber on purpose: red is the edge WAF, purple is AI Gateway Guardrails, and
// this is a third control that runs inside the Worker after both the edge scan
// and before the model. A colour of its own is what lets someone looking at a
// blocked turn tell which layer actually stopped it.
import { ShieldAlert, ShieldBan, SkipForward } from "lucide-react";
import type {
  ExternalGuardrailProvider,
  ExternalGuardrailResult,
  GuardrailPipelineResult,
} from "../lib/types";

const PROVIDER_LABELS: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "Prisma AIRS",
  "crowdstrike-aidr": "CrowdStrike AIDR",
};

// The long form for running prose; the chips and lists use the short one.
const PROVIDER_FULL_LABELS: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "Palo Alto Networks Prisma AIRS",
  "crowdstrike-aidr": "CrowdStrike Falcon AIDR",
};

// What the provider's own reference id is called, so it can be searched for in
// that vendor's console.
const SCAN_ID_LABEL: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "scan_id",
  "crowdstrike-aidr": "request_id",
};

// The provider name is data, not a constant: the second provider reuses this
// card, and a server newer than this bundle may send a key we don't know yet.
function providerLabel(p: ExternalGuardrailProvider): string {
  return PROVIDER_LABELS[p] ?? p;
}

function providerFullLabel(p: ExternalGuardrailProvider): string {
  return PROVIDER_FULL_LABELS[p] ?? p;
}

const DETECTION_LABELS: Record<string, string> = {
  url_cats: "Malicious URL",
  dlp: "Sensitive data (DLP)",
  injection: "Prompt injection",
  toxic_content: "Toxic content",
  malicious_code: "Malicious code",
  agent: "Agent threat",
  topic_violation: "Topic violation",
  // CrowdStrike AIDR detector names (result.detectors keys in its OpenAPI spec).
  malicious_prompt: "Malicious prompt",
  confidential_and_pii_entity: "Confidential / PII",
  malicious_entity: "Malicious entity",
  custom_entity: "Custom entity",
  secret_and_key_entity: "Secret or key",
  competitors: "Competitors",
  language: "Language",
  topic: "Topic",
  emoji: "Emoji",
  code: "Code",
  mcp_validation: "MCP validation",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <span>
      {label} {children}
    </span>
  );
}

// One line per result: what the Worker saw from that provider. An error is
// worded "unavailable" and never as a block or a verdict — the provider did not
// look at the prompt — and `failedOpen` says the turn went on unscanned by it.
function resultSummary(r: ExternalGuardrailResult): { text: string; cls: string } {
  if (r.outcome === "allow") {
    if (r.transformed) return { text: "allow — redaction not applied", cls: "text-cf-amber" };
    return r.incomplete
      ? { text: "allow (incomplete scan)", cls: "text-cf-amber" }
      : { text: "allow", cls: "text-cf-green" };
  }
  if (r.outcome === "block") return { text: "block", cls: "text-cf-amber" };
  return r.failedOpen
    ? { text: "unavailable — ran unscanned (fail open)", cls: "text-cf-amber" }
    : { text: "unavailable — not a verdict", cls: "text-muted" };
}

function ResultList({ results }: { results: ExternalGuardrailResult[] }) {
  if (results.length === 0) return null;
  return (
    <ul className="mt-2 flex flex-col gap-1 text-[11.5px]">
      {results.map((r) => {
        const s = resultSummary(r);
        return (
          <li key={r.provider} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="font-semibold text-text">{providerLabel(r.provider)}</span>
            <span className={`font-semibold ${s.cls}`}>{s.text}</span>
            <span className="font-mono text-muted">{r.latencyMs} ms</span>
          </li>
        );
      })}
    </ul>
  );
}

function NotRunList({ notRun }: { notRun: GuardrailPipelineResult["notRun"] }) {
  if (notRun.length === 0) return null;
  return (
    <ul className="mt-1.5 flex flex-col gap-1 text-[11.5px] text-muted">
      {notRun.map((n) => (
        <li key={n.provider}>
          <span className="font-semibold text-text">{providerLabel(n.provider)}</span> did not run — {n.reason}
        </li>
      ))}
    </ul>
  );
}

// Mode + wall-clock for the whole pipeline. Parallel latency is the slowest
// guardrail, sequential is the sum — saying which keeps the number honest.
function PipelineFooter({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  const n = pipeline.results.length;
  return (
    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
      <Field label="mode">
        <b className="font-mono text-text">{pipeline.mode}</b>
        {pipeline.mode === "parallel" ? " (waited for all)" : ""}
      </Field>
      <Field label="guardrails run">
        <b className="font-mono text-text">{n}</b>
      </Field>
      <Field label="pipeline total">
        <b className="font-mono text-text">{pipeline.latencyMs} ms</b>
      </Field>
    </div>
  );
}

export function ExternalGuardrailBlockedCard({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  // The DECIDING result is the one `stoppedBy` names. Never results[0]: in a
  // sequential run an earlier guardrail may have allowed, and in parallel the
  // configured order says nothing about which one stopped the turn.
  const result = pipeline.results.find((r) => r.provider === pipeline.stoppedBy);
  const others = pipeline.results.filter((r) => r !== result);
  if (!result) {
    return (
      <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border border-cf-amber/60 bg-cf-amber/10 p-4 text-sm shadow-sm">
        <div className="mb-1.5 flex items-center gap-2 font-bold text-cf-amber">
          <ShieldAlert size={16} />
          Stopped by an external guardrail
        </div>
        <div className="leading-relaxed text-text">
          The pipeline reports the turn was stopped
          {pipeline.stoppedBy ? <> by {providerLabel(pipeline.stoppedBy)}</> : null}, but no result for it came back,
          so no verdict is shown. The prompt was not sent to the model.
        </div>
        <ResultList results={others} />
        <NotRunList notRun={pipeline.notRun} />
        <PipelineFooter pipeline={pipeline} />
      </div>
    );
  }
  const name = providerLabel(result.provider);
  const isError = result.outcome === "error";
  return (
    <div className="animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border border-cf-amber/60 bg-cf-amber/10 p-4 text-sm shadow-sm">
      <div className="mb-1.5 flex items-center gap-2 font-bold text-cf-amber">
        {isError ? <ShieldAlert size={16} /> : <ShieldBan size={16} />}
        {isError ? `${name} unavailable — prompt not sent` : `Blocked by ${name}`}
      </div>

      {isError ? (
        // Deliberately no category, no detection pills and no "malicious": the
        // provider never looked at the prompt, so there is nothing to claim about it.
        <>
          <div className="leading-relaxed text-text">
            This is <b>not a verdict</b>. {name} could not be consulted, so nothing is known about this prompt. The
            guardrail is set to <b>fail closed</b>, which blocks the prompt whenever the check cannot complete — it
            was not sent to the model.
          </div>
          {result.error && <div className="mt-2 font-mono text-[11px] break-words text-muted">{result.error}</div>}
          <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
            {result.httpStatus != null && (
              <Field label="HTTP">
                <b className="font-mono text-text">{result.httpStatus}</b>
              </Field>
            )}
            <Field label="after">
              <b className="font-mono text-text">{result.latencyMs} ms</b>
            </Field>
          </div>
        </>
      ) : (
        <>
          <div className="leading-relaxed text-text">
            The prompt was stopped by <b>{providerFullLabel(result.provider)}</b> before reaching the model. This check runs{" "}
            <b>after</b> the Cloudflare edge scan, inside the Worker — a separate control from both the edge WAF and
            AI Gateway Guardrails.
          </div>
          {result.detected && result.detected.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {result.detected.map((d) => (
                <span
                  key={d}
                  title={d}
                  className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
                >
                  {DETECTION_LABELS[d] ?? d}
                </span>
              ))}
            </div>
          )}
          <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
            {result.category && (
              <Field label="category">
                <b className="font-mono text-text">{result.category}</b>
              </Field>
            )}
            {result.profileName && (
              <Field label="profile">
                <b className="font-mono text-text">{result.profileName}</b>
              </Field>
            )}
            {result.policy && (
              <Field label="policy">
                <b className="font-mono text-text">{result.policy}</b>
              </Field>
            )}
            <Field label="latency">
              <b className="font-mono text-text">{result.latencyMs} ms</b>
            </Field>
          </div>
          {result.incomplete && (
            <div className="mt-1.5 text-[11.5px] text-muted">
              At least one detection service timed out or errored, so this verdict is based on the checks that
              completed.
            </div>
          )}
          {result.summary && <div className="mt-1.5 text-[11.5px] text-muted">“{result.summary}”</div>}
          {(result.scanId || result.reportId) && (
            // These ids are what you search for in the vendor's console (Strata
            // Cloud Manager, the Falcon console) to open its own report, so they
            // are shown whole.
            <div className="mt-1.5 flex flex-col gap-0.5 font-mono text-[11px] break-all text-muted">
              {result.scanId && (
                <span>
                  {SCAN_ID_LABEL[result.provider] ?? "id"} {result.scanId}
                </span>
              )}
              {result.reportId && <span>report_id {result.reportId}</span>}
            </div>
          )}
        </>
      )}

      {(others.length > 0 || pipeline.notRun.length > 0) && (
        <div className="mt-3 border-t border-cf-amber/30 pt-2">
          <div className="text-[10.5px] font-bold tracking-wider text-subtle uppercase">Rest of the pipeline</div>
          <ResultList results={others} />
          <NotRunList notRun={pipeline.notRun} />
        </div>
      )}
      <PipelineFooter pipeline={pipeline} />
    </div>
  );
}

// Guardrail-only mode: the prompt passed the edge and every enabled external
// guardrail and the model was deliberately NOT called. This is a test result,
// not an answer — no reply, tokens or cost exist, and AI Gateway Guardrails did
// not run either (they are part of the model call). Neutral when nothing
// external ran, since then no amber control did anything.
export function GuardrailOnlyCard({ pipeline }: { pipeline?: GuardrailPipelineResult }) {
  const results = pipeline?.results ?? [];
  const unscanned = results.filter((r) => r.outcome === "error");
  const tone =
    results.length > 0 ? "border-cf-amber/60 bg-cf-amber/10" : "border-line bg-surface-2";
  return (
    <div className={`animate-rise max-w-[min(80%,720px)] self-start rounded-2xl border p-4 text-sm shadow-sm ${tone}`}>
      <div className="mb-1.5 flex items-center gap-2 font-bold text-cf-amber">
        <SkipForward size={16} /> Model skipped — guardrail-only mode
      </div>
      <div className="leading-relaxed text-text">
        {results.length > 0 ? (
          <>
            The prompt passed the edge WAF and every enabled external guardrail. <b>The model was not called</b>, so
            there is no reply, no tokens and no cost.
          </>
        ) : (
          <>
            Passed the edge WAF; <b>no external guardrail is enabled</b>. <b>The model was not called</b>, so there is
            no reply, no tokens and no cost.
          </>
        )}{" "}
        AI Gateway Guardrails did not run either — they are part of the model call.
      </div>
      {unscanned.length > 0 && (
        // A failed-open provider let the turn through without ever scanning it;
        // "passed every guardrail" would otherwise overstate what was checked.
        <div className="mt-2 text-[11.5px] text-cf-amber">
          {unscanned.map((r) => providerLabel(r.provider)).join(", ")} could not be reached and is set to fail open, so
          this prompt was <b>not scanned</b> by {unscanned.length === 1 ? "it" : "them"}.
        </div>
      )}
      <ResultList results={results} />
      {pipeline ? (
        <PipelineFooter pipeline={pipeline} />
      ) : (
        <div className="mt-2 text-[11px] text-muted">The response carried no pipeline detail.</div>
      )}
    </div>
  );
}

// Reply-metadata chips: one per provider result, from the pipeline that let the
// turn through. Renders nothing when there are no results (none enabled).
export function ExternalGuardrailBadges({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  return (
    <>
      {pipeline.results.map((r) => (
        <ExternalGuardrailBadge key={r.provider} result={r} />
      ))}
    </>
  );
}

// Reply-metadata chip for a turn the guardrail let through. Same size as the
// GUARDRAILS / ROUTE chips in Chat.tsx's meta row. A "block" or a fail-closed
// error never reaches here (those render the card), so they return nothing
// rather than a chip that would imply the reply was allowed.
export function ExternalGuardrailBadge({ result }: { result: ExternalGuardrailResult }) {
  const name = providerLabel(result.provider);
  if (result.outcome === "allow") {
    // An allow from a scan where a detection service timed out or errored only
    // covers what did run, so it gets the amber "partial" tone rather than the
    // green of a complete pass.
    // AIDR wanted part of the prompt redacted, but this app forwards the
    // original — so the model saw what AIDR would have masked. Amber, and said
    // in words, never a clean green pass.
    if (result.transformed) {
      return (
        <span
          title={`${name} redacted part of this prompt, but this app does not apply the redaction — the model received the original prompt.`}
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow · redaction not applied · {result.latencyMs} ms
        </span>
      );
    }
    if (result.incomplete) {
      return (
        <span
          title="Prisma AIRS returned a verdict, but at least one of its detection services timed out or errored — the allow covers only the checks that ran."
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow (incomplete scan){result.category ? ` · ${result.category}` : ""} · {result.latencyMs} ms
        </span>
      );
    }
    return (
      <span className="rounded-full border border-cf-green/60 bg-cf-green/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-green">
        {name} · allow
        {result.category ? ` · ${result.category}` : ""} · {result.latencyMs} ms
      </span>
    );
  }
  if (result.outcome === "error" && result.failedOpen) {
    return (
      <span
        title={result.error}
        className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
      >
        {name} unavailable — sent unscanned
      </span>
    );
  }
  return null;
}
