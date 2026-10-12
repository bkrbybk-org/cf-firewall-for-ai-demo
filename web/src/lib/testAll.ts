// "Test all vendors" (Settings → External guardrails): pure logic behind
// components/settings/TestAllVendors.tsx. No React, no fetch — the component runs the requests,
// this file decides what to run and how each outcome may be worded.
//
// Honesty rules, in order of how much they matter:
//  - A test that did not produce a verdict is "error", with its text — NEVER allow or block. That
//    covers `ok: false`, a thrown fetch / JSON parse, and a 400/403 body of just `{ error }`.
//  - A test that has not run reads "—", never blank and never "0 ms".
//  - Nothing here reads `result.raw` (the vendor's body, which can quote the prompt and detected
//    PII), and the report copies only named fields — never a vendor message, never the whole object.
import type {
  ExternalGuardrailConfig,
  ExternalGuardrailProvider,
  ExternalGuardrailTestResult,
  GuardrailTestSample,
} from "./types";

// Same wording as SettingsPage's TEST_SAMPLE_LABEL (not exported there, and that file is not ours to edit).
export const TEST_ALL_SAMPLE_LABEL: Record<GuardrailTestSample, string> = {
  benign: "Connection works",
  attack: "Attack prompt",
  pii: "PII prompt",
  thai: "Thai prompt (harmless)",
  "reply-benign": "Harmless reply",
  "reply-pii": "Reply with PII",
};

// Order of a vendor's tests: the prompt samples first, the reply samples after.
const PROMPT_SAMPLES: GuardrailTestSample[] = ["benign", "attack", "pii", "thai"];
const REPLY_SAMPLES: GuardrailTestSample[] = ["reply-benign", "reply-pii"];

export interface TestRun {
  provider: ExternalGuardrailProvider;
  label: string; // the vendor's display name, so a row never has to look the provider up again
  sample: GuardrailTestSample;
}

// `kind` is what is missing, so the UI can word its heading truthfully ("no key saved" is wrong for a
// vendor that is simply not supported yet).
export interface SkippedProvider {
  provider: ExternalGuardrailProvider;
  label: string;
  reason: string;
  kind: "unsupported" | "key" | "profile";
}

export interface TestPlan {
  runs: TestRun[];
  skipped: SkippedProvider[];
}

// A label mid-sentence: an acronym ("API key", "AI security profile name") keeps its capitals,
// "Collector token" reads lower-case (same rule as SettingsPage's keyWord).
function midSentence(label: string): string {
  return /^[A-Z]{2}/.test(label) ? label : label.toLowerCase();
}

// Why a provider cannot be tested, or null when it can. A test sends the SAVED credentials, so
// everything the real call needs must already be saved: the key, a second key if the vendor takes
// two, and a profile / project where the vendor requires one.
function skipReason(p: ExternalGuardrailConfig): Pick<SkippedProvider, "reason" | "kind"> | null {
  if (!p.supported) return { reason: "not supported yet", kind: "unsupported" };
  if (!p.apiKeySet) return { reason: `no ${midSentence(p.keyLabel)} saved`, kind: "key" };
  if (p.secondKeyLabel != null && !p.secondKeySet) {
    return { reason: `no ${midSentence(p.secondKeyLabel)} saved`, kind: "key" };
  }
  if (p.requiresProfile && !p.profileName) {
    return { reason: `no ${midSentence(p.profileLabel)} set`, kind: "profile" };
  }
  return null;
}

export function testPlan(providers: ExternalGuardrailConfig[]): TestPlan {
  const runs: TestRun[] = [];
  const skipped: SkippedProvider[] = [];
  for (const p of providers) {
    const why = skipReason(p);
    if (why) {
      skipped.push({ provider: p.provider, label: p.label, ...why });
      continue;
    }
    // The reply samples exist only where the vendor documents checking a model reply.
    const samples = p.replyCheck === true ? [...PROMPT_SAMPLES, ...REPLY_SAMPLES] : PROMPT_SAMPLES;
    for (const sample of samples) runs.push({ provider: p.provider, label: p.label, sample });
  }
  return { runs, skipped };
}

// What the page shows after "Skipped": the words in the heading must be true of every entry in it.
export function skippedHeading(skipped: SkippedProvider[]): string {
  return skipped.every((s) => s.kind === "key") ? "Skipped (no key saved)" : "Skipped (not fully set up)";
}

export function skippedText(skipped: SkippedProvider[]): string {
  return `${skippedHeading(skipped)}: ${skipped.map((s) => `${s.label} — ${s.reason}`).join("; ")}`;
}

// What one request produced. The server's answer, or — when there was no usable answer — only an
// `error`. Everything is optional because a 403 / 400 body is `{ error }` with no `result` at all.
export type TestAllOutcome = Partial<ExternalGuardrailTestResult> & { error?: string };

export type CellTone = "allow" | "block" | "partial" | "error" | "none";

export interface Cell {
  verdict: string; // "allow" | "block" | "error" | "—", plus qualifiers
  tone: CellTone; // "none" = not run. Colour is a hint only: `verdict` always says it in words.
  latency: string; // "412 ms" | "—"
  http: string; // the vendor's HTTP status | "—"
  detail: string; // error text for an error, otherwise ""
}

const NOT_RUN: Cell = { verdict: "—", tone: "none", latency: "—", http: "—", detail: "" };
const DETAIL_MAX = 200;

// One line, bounded: an error string can be long and can carry newlines, and it goes into a table
// cell and a Markdown table.
function oneLine(s: string): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > DETAIL_MAX ? `${t.slice(0, DETAIL_MAX - 1)}…` : t;
}

function ms(n: unknown, allowZero: boolean): string {
  return typeof n === "number" && Number.isFinite(n) && (allowZero ? n >= 0 : n > 0) ? `${Math.round(n)} ms` : "—";
}

function httpOf(o: TestAllOutcome): string {
  const s = o.result?.httpStatus ?? o.responseShape?.status;
  return typeof s === "number" && Number.isFinite(s) ? String(s) : "—";
}

// `undefined` / `null` = the test has not run. Anything else is judged on what it proves.
export function cellFor(o: TestAllOutcome | null | undefined): Cell {
  if (o == null || typeof o !== "object") return NOT_RUN;
  const r = o.result;
  const word = r && typeof r === "object" ? (r.action ?? r.outcome) : undefined;
  // `ok` means "the provider answered with a verdict". Without it — or with a verdict we cannot
  // read — there is no allow/block to show, only the reason there is none.
  if (o.ok !== true || !r || (word !== "allow" && word !== "block")) {
    const text = typeof o.error === "string" && o.error ? o.error : typeof r?.error === "string" ? r.error : "";
    return {
      verdict: "error",
      tone: "error",
      // A zero from a failed call is not a measurement, so only a positive time is shown.
      latency: ms(r?.latencyMs, false),
      http: httpOf(o),
      detail: oneLine(text || "No error text was returned"),
    };
  }
  const notes: string[] = [];
  if (r.detectOnly) notes.push("alerts only");
  if (r.transformed) notes.push("redaction requested");
  // The vendor says one of its detection services did not finish: an allow here is weaker than a full one.
  if (r.incomplete) notes.push("incomplete");
  return {
    verdict: notes.length ? `${word} · ${notes.join(" · ")}` : word,
    tone: word === "block" ? "block" : notes.length ? "partial" : "allow",
    latency: ms(r.latencyMs, true),
    http: httpOf(o),
    detail: "",
  };
}

export interface TestRow {
  provider: ExternalGuardrailProvider;
  label: string;
  sample: GuardrailTestSample;
  outcome?: TestAllOutcome | null; // absent = not run
}

export function runKey(r: { provider: ExternalGuardrailProvider; sample: GuardrailTestSample }): string {
  return `${r.provider}:${r.sample}`;
}

export function rowsFor(runs: TestRun[], results: Record<string, TestAllOutcome>): TestRow[] {
  return runs.map((r) => ({ ...r, outcome: results[runKey(r)] }));
}

export interface RowCounts {
  total: number;
  notRun: number;
  answered: number; // a verdict came back (allow, block or either with a qualifier)
  errors: number;
}

export function countRows(rows: TestRow[]): RowCounts {
  const c: RowCounts = { total: rows.length, notRun: 0, answered: 0, errors: 0 };
  for (const r of rows) {
    const { tone } = cellFor(r.outcome);
    if (tone === "none") c.notRun++;
    else if (tone === "error") c.errors++;
    else c.answered++;
  }
  return c;
}

// A Markdown table cell is one line, and a pipe would end it.
function mdCell(s: string): string {
  return s.replace(/\s+/g, " ").replace(/\|/g, "\\|").trim();
}

// The report an admin hands over: one table, then each test's response shape. Only named fields are
// read, so nothing from `result.raw` (or any vendor text field) can reach it. A response shape is
// field names, types and booleans — the server never puts text in it (src/responseShape.ts).
export function reportText(
  rows: TestRow[],
  opts: { skipped?: SkippedProvider[]; generatedAt?: string } = {},
): string {
  const n = countRows(rows);
  const out: string[] = ["# External guardrails — test all vendors", ""];
  if (opts.generatedAt) out.push(`Generated: ${opts.generatedAt}`);
  out.push(`Ran ${n.total - n.notRun} of ${n.total} tests: ${n.answered} verdicts, ${n.errors} errors, ${n.notRun} not run.`);
  if (opts.skipped && opts.skipped.length) out.push(skippedText(opts.skipped) + ".");
  out.push("", "| Vendor | Sample | Verdict | Latency | HTTP |", "| --- | --- | --- | --- | --- |");
  for (const r of rows) {
    const c = cellFor(r.outcome);
    const verdict = c.tone === "error" ? `error: ${c.detail}` : c.verdict;
    out.push(
      `| ${mdCell(r.label)} | ${mdCell(TEST_ALL_SAMPLE_LABEL[r.sample])} | ${mdCell(verdict)} | ${c.latency} | ${c.http} |`,
    );
  }
  out.push("", "## Response shapes", "", "Field names, types and true/false only — no text.");
  for (const r of rows) {
    const o = r.outcome;
    out.push("", `### ${r.label} — ${TEST_ALL_SAMPLE_LABEL[r.sample]}`);
    if (!o) {
      out.push("Not run.");
    } else if (!o.responseShape) {
      out.push("No response shape was returned.");
    } else {
      const json = JSON.stringify({ provider: r.provider, sample: r.sample, ...o.responseShape }, null, 2);
      out.push("```json", json, "```");
    }
  }
  return out.join("\n") + "\n";
}
