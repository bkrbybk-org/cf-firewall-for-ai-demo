// View model for the chat-side external guardrail card (Prisma AIRS, CrowdStrike AIDR).
//
// Pure on purpose — no React, no DOM — so every layout of the card (vendor columns,
// compact rows) renders the SAME facts and cannot drift apart on what a control did.
// The rules that matter live here, where a unit test can hold them:
//  - the deciding result is the one `stoppedBy` names, never results[0]: in a
//    sequential run an earlier guardrail may have allowed, and in parallel the
//    configured order says nothing about which one stopped the turn;
//  - an error is never a verdict: the provider did not look at the prompt, so an
//    errored result carries no findings and is never headlined as a block;
//  - a verdict that covers less than it seems to (incomplete scan, redaction that
//    this app does not apply) says so in `notes` instead of reading as a clean pass.
import type {
  ExternalGuardrailProvider,
  ExternalGuardrailResult,
  GuardrailPipelineResult,
} from "./types";

export const PROVIDER_LABELS: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "Prisma AIRS",
  "crowdstrike-aidr": "CrowdStrike AIDR",
};

// The long form for running prose; the chips and lists use the short one.
export const PROVIDER_FULL_LABELS: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "Palo Alto Networks Prisma AIRS",
  "crowdstrike-aidr": "CrowdStrike Falcon AIDR",
};

// What the provider's own reference id is called, so it can be searched for in
// that vendor's console.
export const SCAN_ID_LABEL: Record<ExternalGuardrailProvider, string> = {
  "prisma-airs": "scan_id",
  "crowdstrike-aidr": "request_id",
};

export const DETECTION_LABELS: Record<string, string> = {
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

// The provider name is data, not a constant: a server newer than this bundle may
// send a key we don't know yet, and it is shown as-is rather than hidden.
export function providerLabel(p: ExternalGuardrailProvider): string {
  return PROVIDER_LABELS[p] ?? p;
}

export function providerFullLabel(p: ExternalGuardrailProvider): string {
  return PROVIDER_FULL_LABELS[p] ?? p;
}

export function scanIdLabel(p: ExternalGuardrailProvider): string {
  return SCAN_ID_LABEL[p] ?? "id";
}

export function detectionLabel(d: string): string {
  return DETECTION_LABELS[d] ?? d;
}

export const GUARDRAIL_ONLY_HEADLINE = "Model skipped — guardrail-only mode";

export type VendorState = "block" | "allow" | "unavailable" | "failedOpen" | "notRun";

const STATE_LABELS: Record<VendorState, string> = {
  block: "block",
  allow: "allow",
  unavailable: "unavailable",
  failedOpen: "unscanned (fail open)",
  notRun: "did not run",
};

export interface VendorDetail {
  label: string;
  value: string;
  // Ids and config names: shown monospace and broken anywhere, since they are what
  // gets searched for in the vendor's console. Prose (summary, error) is not.
  mono: boolean;
}

export interface VendorView {
  provider: ExternalGuardrailProvider;
  name: string; // short label, e.g. "CrowdStrike AIDR"
  fullName: string;
  state: VendorState;
  stateLabel: string;
  // An "allow" whose coverage is weaker than it reads (incomplete scan, redaction
  // not applied). The label stays "allow" — that is what the provider said — but a
  // renderer must not paint it as a clean green pass.
  partial: boolean;
  decided: boolean; // true only for the result named by pipeline.stoppedBy
  // What the card shows about this vendor's part in the stop — kept apart from
  // `decided` (the pipeline's bookkeeping) because the two differ in one case: in
  // parallel mode with two or more blocks, every blocker would have stopped the turn
  // on its own, and stoppedBy names only the first in configured order. Crediting
  // that one as "decided" would read as if the others did not matter, so each blocker
  // is "independent" and nothing is "decided".
  marker: "decided" | "independent" | null;
  findings: string[]; // human labels from `detected`, in order, deduped; never for an error
  latencyMs: number | null; // null for notRun: it never started, so there is no latency
  notes: string[];
  details: VendorDetail[];
  reportId: string | null; // Prisma AIRS only: the id the vendor-report panel fetches
}

export interface PipelineView {
  headline: string;
  tone: "warning" | "neutral";
  subline: string;
  vendors: VendorView[];
  // One line saying where two vendors' findings differ; null when they agree or
  // fewer than two found anything.
  why: string | null;
  // Set only when the pipeline says it stopped the turn but no result supports a
  // block or a failure — said in words rather than inventing a verdict.
  caveat: string | null;
}

function dedupe(items: string[]): string[] {
  return [...new Set(items)];
}

function resultVendor(r: ExternalGuardrailResult, stoppedBy: ExternalGuardrailProvider | null): VendorView {
  const name = providerLabel(r.provider);
  const isError = r.outcome === "error";
  // Anything that is not an explicit allow or block is treated as "the provider
  // gave no verdict" — never promoted to allow, which would overstate a check.
  const state: VendorState =
    r.outcome === "allow"
      ? "allow"
      : r.outcome === "block"
        ? "block"
        : r.failedOpen
          ? "failedOpen"
          : "unavailable";
  const decided = stoppedBy != null && r.provider === stoppedBy;

  const notes: string[] = [];
  if (!isError && r.incomplete) {
    notes.push("At least one detection service timed out — this verdict covers only the checks that ran");
  }
  // Only an allow can carry this: a block means the prompt never reaches the model.
  if (r.outcome === "allow" && r.transformed) {
    notes.push(`Redaction requested by ${name} was not applied — the model would receive the original prompt`);
  }
  if (state === "failedOpen") {
    notes.push("Could not be reached; set to fail open, so this prompt was not scanned by it");
  }
  if (state === "unavailable") {
    notes.push("Not a verdict — it could not be consulted, so nothing is known about this prompt from it");
    if (decided) notes.push("Set to fail closed, so the prompt was not sent to the model");
  }

  const details: VendorDetail[] = [];
  if (r.policy) details.push({ label: "policy", value: r.policy, mono: true });
  if (r.profileName) details.push({ label: "profile", value: r.profileName, mono: true });
  if (!isError && r.category) details.push({ label: "category", value: r.category, mono: true });
  if (r.scanId) details.push({ label: scanIdLabel(r.provider), value: r.scanId, mono: true });
  if (r.reportId) details.push({ label: "report_id", value: r.reportId, mono: true });
  if (!isError && r.summary) details.push({ label: "summary", value: r.summary, mono: false });
  if (isError && r.error) details.push({ label: "error", value: r.error, mono: false });
  if (r.httpStatus != null) details.push({ label: "HTTP", value: String(r.httpStatus), mono: true });

  return {
    provider: r.provider,
    name,
    fullName: providerFullLabel(r.provider),
    state,
    stateLabel: STATE_LABELS[state],
    partial: state === "allow" && (!!r.incomplete || !!r.transformed),
    decided,
    marker: decided ? "decided" : null, // revisited in pipelineView, which sees every result
    // An error is not a verdict: whatever `detected` holds, nothing was found.
    findings: isError ? [] : dedupe((r.detected ?? []).map(detectionLabel)),
    latencyMs: r.latencyMs,
    notes,
    details,
    reportId: r.provider === "prisma-airs" && !isError && r.reportId ? r.reportId : null,
  };
}

// "PII — both · Topic, Language — CrowdStrike AIDR only · Sensitive data (DLP) —
// Prisma AIRS only": findings grouped by WHICH vendors raised them, so a reader
// sees at a glance where the two controls agree and where only one caught it.
function whyLine(vendors: VendorView[]): string | null {
  const withFindings = vendors.filter((v) => v.findings.length > 0);
  if (withFindings.length < 2) return null;

  const labels = dedupe(withFindings.flatMap((v) => v.findings));
  const groups = new Map<string, { who: VendorView[]; labels: string[] }>();
  for (const label of labels) {
    const who = withFindings.filter((v) => v.findings.includes(label));
    const key = who.map((v) => v.provider).join("+");
    const g = groups.get(key) ?? { who, labels: [] };
    g.labels.push(label);
    groups.set(key, g);
  }
  if (groups.size === 1) return null; // every vendor raised exactly the same findings

  const all = [...groups.values()].filter((g) => g.who.length === withFindings.length);
  const some = [...groups.values()].filter((g) => g.who.length !== withFindings.length);
  const scope = (g: { who: VendorView[] }) =>
    g.who.length === withFindings.length
      ? withFindings.length === 2
        ? "both"
        : "all"
      : `${g.who.map((v) => v.name).join(" + ")} only`;
  return [...all, ...some].map((g) => `${g.labels.join(", ")} — ${scope(g)}`).join(" · ");
}

export function pipelineView(pipeline: GuardrailPipelineResult, kind: "blocked" | "guardrailOnly"): PipelineView {
  const ran = pipeline.results.map((r) => resultVendor(r, pipeline.stoppedBy));
  const notRun: VendorView[] = pipeline.notRun.map((n) => ({
    provider: n.provider,
    name: providerLabel(n.provider),
    fullName: providerFullLabel(n.provider),
    state: "notRun",
    stateLabel: STATE_LABELS.notRun,
    partial: false,
    decided: false,
    marker: null,
    findings: [],
    latencyMs: null,
    notes: [],
    details: [{ label: "reason", value: n.reason, mono: false }],
    reportId: null,
  }));
  const vendors = [...ran, ...notRun];

  const blocks = ran.filter((v) => v.state === "block").length;
  // Parallel + several blocks: no single result decided it (see VendorView.marker).
  // Sequential never gets here with two blocks — the first one ends the run.
  if (pipeline.mode === "parallel" && blocks >= 2) {
    for (const v of ran) v.marker = v.state === "block" ? "independent" : null;
  }
  // A failed-open guardrail is unavailable too — it just did not stop the turn — and a
  // gap in what was scanned is worth the warning colour.
  const unavailable = ran.filter((v) => v.state === "unavailable" || v.state === "failedOpen").length;
  const tone: PipelineView["tone"] = blocks > 0 || unavailable > 0 ? "warning" : "neutral";

  let headline: string;
  let caveat: string | null = null;
  if (kind === "guardrailOnly") {
    headline = GUARDRAIL_ONLY_HEADLINE;
  } else if (blocks > 0) {
    headline = `Blocked by ${blocks} of ${ran.length} ${ran.length === 1 ? "guardrail" : "guardrails"}`;
  } else {
    // Stopped with no block: a fail-closed error. Name the unavailable vendor — and
    // never word it as a block, because it never looked at the prompt.
    const decided = ran.find((v) => v.decided && v.state === "unavailable");
    const stopper = decided ?? ran.find((v) => v.state === "unavailable");
    if (stopper) {
      headline = `Not sent to the model — ${stopper.name} unavailable`;
    } else {
      const named = pipeline.stoppedBy ? providerLabel(pipeline.stoppedBy) : null;
      headline = `Stopped by ${named ?? "an external guardrail"} — no verdict shown`;
      caveat =
        `The pipeline reports the turn was stopped${named ? ` by ${named}` : ""}, but no matching block or ` +
        "failure came back, so no verdict is shown. The prompt was not sent to the model.";
    }
  }

  let subline: string;
  if (kind === "guardrailOnly" && ran.length === 0) {
    subline = "Passed the edge WAF; no external guardrail is enabled";
  } else {
    const mode = pipeline.mode === "parallel" ? "parallel (waited for all)" : "sequential";
    subline = `${mode} · ${pipeline.latencyMs} ms${kind === "guardrailOnly" ? " · model not called" : ""}`;
  }

  return { headline, tone, subline, vendors, why: whyLine(ran), caveat };
}
