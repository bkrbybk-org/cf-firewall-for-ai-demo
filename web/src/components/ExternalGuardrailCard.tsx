// Chat-side rendering of an external guardrail (Prisma AIRS, ...) verdict.
//
// Amber on purpose: red is the edge WAF, purple is AI Gateway Guardrails, and
// this is a third control that runs inside the Worker after both the edge scan
// and before the model. A colour of its own is what lets someone looking at a
// blocked turn tell which layer actually stopped it.
import { ShieldAlert, ShieldBan } from "lucide-react";
import type { ExternalGuardrailProvider, ExternalGuardrailResult } from "../lib/types";

const PROVIDER_LABELS: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "Prisma AIRS",
  "crowdstrike-aidr": "CrowdStrike AIDR",
};

// The provider name is data, not a constant: the second provider reuses this
// card, and a server newer than this bundle may send a key we don't know yet.
function providerLabel(p: ExternalGuardrailProvider): string {
  return PROVIDER_LABELS[p] ?? p;
}

const DETECTION_LABELS: Record<string, string> = {
  url_cats: "Malicious URL",
  dlp: "Sensitive data (DLP)",
  injection: "Prompt injection",
  toxic_content: "Toxic content",
  malicious_code: "Malicious code",
  agent: "Agent threat",
  topic_violation: "Topic violation",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <span>
      {label} {children}
    </span>
  );
}

export function ExternalGuardrailBlockedCard({ result }: { result: ExternalGuardrailResult }) {
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
            The prompt was stopped by Palo Alto Networks <b>{name}</b> before reaching the model. This check runs{" "}
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
          {(result.scanId || result.reportId) && (
            // These two ids are what you search for in Strata Cloud Manager to
            // open the provider's own report, so they are shown whole.
            <div className="mt-1.5 flex flex-col gap-0.5 font-mono text-[11px] break-all text-muted">
              {result.scanId && <span>scan_id {result.scanId}</span>}
              {result.reportId && <span>report_id {result.reportId}</span>}
            </div>
          )}
        </>
      )}
    </div>
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
