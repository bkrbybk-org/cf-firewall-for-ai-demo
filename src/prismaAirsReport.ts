// Prisma AIRS threat scan reports — the per-detection breakdown behind a verdict.
//
// Facts from PANW's OpenAPI spec (pan.dev, openapi-specs/prisma-airs/scan/
// scan-service_latest.yaml): GET /v1/scan/reports?report_ids=… on the same
// regional host and with the same `x-pan-token` as the scan itself (up to 5
// ids); 200 → an array of ThreatScanReportObject, each with `detection_results`
// [{data_type, detection_service, verdict, action, result_detail}].
//
// PRIVACY is the reason this file exists rather than passing the report through.
// The report can carry the prompt's own content back: DLP / toxic / injection
// snippets, the original text with patterns masked, every URL found, extracted
// code blocks, and a model-written grounding explanation. The prompt log redacts
// PII before storing anything; showing a report verbatim would undo that in the
// browser. So the parser is an ALLOWLIST — it copies names, categories, verdicts,
// actions and counts, and nothing that came from the prompt text. A field PANW
// adds later is dropped by default, never shown by accident.
//
// HONESTY: `verdict` (what a detector concluded) and `action` (what the AI
// security profile does about it) are different facts — a "malicious" verdict
// with action "allow" means the profile only alerts on it. Both are kept, never
// merged into one word.

import type { GuardrailReport, GuardrailReportDetection } from "./types";

export const PRISMA_AIRS_REPORT_PATH = "/v1/scan/reports";
export const PRISMA_AIRS_REPORT_TIMEOUT_MS = 5000;

// What PANW report ids look like ("R" + a UUID, e.g. R126fe3c6-7a24-…). Kept
// loose on shape but strict on charset, so nothing but an id can reach the query.
export const REPORT_ID_RE = /^[A-Za-z0-9-]{1,80}$/;

const s = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const strs = (v: unknown): string[] => arr(v).filter((x): x is string => typeof x === "string" && x !== "");
const uniq = (xs: string[]): string[] => [...new Set(xs)];

// Human-readable facts from one detection's `result_detail`. Each branch reads
// only the allowlisted, non-content fields of its sub-report.
export function reportDetails(detail: unknown): string[] {
  const d = obj(detail);
  const out: string[] = [];

  const dlp = obj(d.dlp_report);
  if (Object.keys(dlp).length) {
    const name = s(dlp.dlp_profile_name);
    if (name) out.push(`DLP profile: ${name}${typeof dlp.dlp_profile_version === "number" ? ` (v${dlp.dlp_profile_version})` : ""}`);
    for (const k of ["data_pattern_rule1_verdict", "data_pattern_rule2_verdict"] as const) {
      const v = s(dlp[k]);
      if (v) out.push(`${k === "data_pattern_rule1_verdict" ? "Rule 1" : "Rule 2"}: ${v}`);
    }
    // Pattern NAMES and how many matches at each confidence — never the offsets,
    // which with the prompt in hand locate the sensitive text exactly.
    for (const p of arr(dlp.data_pattern_detection_offsets).map(obj)) {
      const pname = s(p.name);
      if (!pname) continue;
      const counts = (["high", "medium", "low"] as const)
        .map((c) => [c, arr(p[`${c}_confidence_detections`]).length] as const)
        .filter(([, n]) => n > 0)
        .map(([c, n]) => `${n} ${c}`);
      out.push(`Pattern: ${pname}${counts.length ? ` — ${counts.join(", ")} confidence` : ""}`);
    }
  }

  // URL filtering: categories, risk and action per URL — not the URLs, which
  // are prompt content.
  const urls = arr(d.urlf_report).map(obj);
  if (urls.length) {
    const cats = uniq(urls.flatMap((u) => strs(u.categories)));
    const risks = uniq(urls.map((u) => s(u.risk_level)).filter((x): x is string => !!x));
    const actions = uniq(urls.map((u) => s(u.action)).filter((x): x is string => !!x));
    out.push(
      `${urls.length} URL${urls.length === 1 ? "" : "s"}` +
        (cats.length ? ` — categories: ${cats.join(", ")}` : "") +
        (risks.length ? ` · risk: ${risks.join(", ")}` : "") +
        (actions.length ? ` · URL action: ${actions.join(", ")}` : ""),
    );
  }

  const tc = obj(d.tc_report);
  const tcCats = strs(tc.toxic_categories);
  if (tcCats.length) out.push(`Toxic categories: ${tcCats.join(", ")}`);
  if (s(tc.confidence)) out.push(`Confidence: ${s(tc.confidence)}`);

  const tg = obj(d.topic_guardrails_report);
  const blocked = strs(tg.blockedTopics);
  const allowed = strs(tg.allowedTopics);
  if (blocked.length) out.push(`Blocked topics matched: ${blocked.join(", ")}`);
  else if (s(tg.blocked_topic_list)) out.push(`Blocked topic list: ${s(tg.blocked_topic_list)}`);
  if (allowed.length) out.push(`Allowed topics matched: ${allowed.join(", ")}`);
  else if (s(tg.allowed_topic_list)) out.push(`Allowed topic list: ${s(tg.allowed_topic_list)}`);

  // Malicious code: languages and sub-verdicts — not the extracted code blocks.
  const mc = obj(d.mc_report);
  const types = uniq(arr(mc.code_analysis_by_type).map((e) => s(obj(e).file_type)).filter((x): x is string => !!x));
  if (types.length) out.push(`Code types: ${types.join(", ")}`);
  if (s(obj(mc.malware_script_report).verdict)) out.push(`Malware script: ${s(obj(mc.malware_script_report).verdict)}`);
  const cmd = arr(mc.command_injection_report).map(obj);
  if (cmd.length) {
    const bad = cmd.filter((c) => s(c.verdict) === "malicious").length;
    out.push(`Command injection: ${bad} of ${cmd.length} code block${cmd.length === 1 ? "" : "s"} malicious`);
  }

  const agent = obj(d.agent_report);
  if (s(agent.agent_framework)) out.push(`Agent framework: ${s(agent.agent_framework)}`);
  for (const p of arr(agent.agent_patterns).map(obj)) {
    const cat = s(p.category_type);
    if (cat) out.push(`Agent threat: ${cat}${s(p.verdict) ? ` (${s(p.verdict)})` : ""}`);
  }

  for (const e of arr(d.dbs_report).map(obj)) {
    const sub = s(e.sub_type);
    if (sub) out.push(`SQL ${sub}: ${s(e.verdict) ?? "?"}${s(e.action) ? ` → ${s(e.action)}` : ""}`);
  }

  // Contextual grounding: the category only — the explanation is model-written
  // text about the prompt and may quote it.
  const cg = obj(d.cg_report);
  if (s(cg.category)) out.push(`Grounding: ${s(cg.category)}${s(cg.status) ? ` (${s(cg.status)})` : ""}`);

  return out;
}

export function parseReportDetection(raw: unknown): GuardrailReportDetection | null {
  const r = obj(raw);
  const service = s(r.detection_service);
  if (!service) return null; // nothing to attribute it to
  return {
    service,
    dataType: s(r.data_type),
    verdict: s(r.verdict),
    action: s(r.action),
    details: reportDetails(r.result_detail),
  };
}

export type ReportLookup =
  | { ok: true; report: GuardrailReport }
  | { ok: false; pending: true; error: string }
  | { ok: false; pending?: false; error: string; httpStatus?: number };

// Same two error shapes as the scan endpoint (see prismaAirs.ts).
function errorMessage(body: unknown, status: number): string {
  const b = obj(body);
  const nested = s(obj(b.error).message);
  return nested ?? s(b.message) ?? `Prisma AIRS returned HTTP ${status}`;
}

export function parseReportResponse(status: number, body: unknown, reportId: string): ReportLookup {
  if (status < 200 || status >= 300) return { ok: false, error: errorMessage(body, status), httpStatus: status };
  const list = arr(body).map(obj);
  // Matched by id rather than taking [0], so a response for some other report
  // can never be shown as this one.
  const hit = list.find((x) => s(x.report_id) === reportId);
  if (!hit) {
    // Not an error and not "nothing detected": PANW simply has no report under
    // this id (yet). Saying so lets the UI offer a retry instead of a blank.
    return { ok: false, pending: true, error: "Prisma AIRS has no report for this id yet — it can take a moment to appear." };
  }
  return {
    ok: true,
    report: {
      provider: "prisma-airs",
      reportId,
      scanId: s(hit.scan_id),
      transactionId: s(hit.transaction_id),
      source: s(hit.source),
      detections: arr(hit.detection_results)
        .map(parseReportDetection)
        .filter((x): x is GuardrailReportDetection => x != null),
    },
  };
}

export async function fetchPrismaAirsReport(
  input: { baseUrl: string; apiKey: string; reportId: string; timeoutMs?: number },
  fetchImpl: typeof fetch = fetch,
): Promise<ReportLookup> {
  if (!REPORT_ID_RE.test(input.reportId)) return { ok: false, error: "Invalid report id" };
  const url = `${input.baseUrl}${PRISMA_AIRS_REPORT_PATH}?report_ids=${encodeURIComponent(input.reportId)}`;
  const timeoutMs = input.timeoutMs ?? PRISMA_AIRS_REPORT_TIMEOUT_MS;
  try {
    const res = await fetchImpl(url, {
      headers: { "x-pan-token": input.apiKey },
      signal: AbortSignal.timeout(timeoutMs),
    });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    return parseReportResponse(res.status, body, input.reportId);
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    return {
      ok: false,
      error:
        name === "TimeoutError" || name === "AbortError"
          ? `Prisma AIRS did not answer within ${timeoutMs} ms`
          : `Could not reach Prisma AIRS: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
