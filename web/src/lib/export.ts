// Session export: assemble the Firewall-page chat transcript (prompts,
// replies, edge verdicts) into a downloadable JSON or Markdown report.
import { getVerdict } from "./api";
import { topicLabel } from "./format";
import { verdictOutcome } from "./verdict";
import type { Msg } from "../hooks/useChat";
import type { GuardrailPipelineResult, Verdict as VerdictData } from "./types";

type VerdictSummary =
  | {
      available: true;
      action: string;
      rulesHit: { rule: string; action: string }[];
      scored: boolean;
      injectionScore: number | null;
      piiCategories: string[];
      unsafeTopics: string[];
      customTopics: { label: string; score: number }[];
    }
  | { available: false; reason: string };

// What the external guardrail pipeline did, kept to the facts a reader needs to
// audit a turn. `outcome: "error"` is exported as-is — never as a detection.
interface ExportGuardrails {
  mode: string;
  stoppedBy: string | null;
  results: { provider: string; outcome: string; latencyMs: number; failedOpen?: boolean; category?: string; detected?: string[] }[];
  notRun: { provider: string; reason: string }[];
  latencyMs: number;
}

function summarizePipeline(p: GuardrailPipelineResult): ExportGuardrails {
  return {
    mode: p.mode,
    stoppedBy: p.stoppedBy,
    results: p.results.map((r) => ({
      provider: r.provider,
      outcome: r.outcome,
      latencyMs: r.latencyMs,
      failedOpen: r.failedOpen || undefined,
      category: r.category,
      detected: r.detected,
    })),
    notRun: p.notRun,
    latencyMs: p.latencyMs,
  };
}

export interface ExportTurn {
  ts: string;
  tsMs: number; // epoch ms — anchors this turn's verdict lookup
  prompt: string;
  // "skipped" = guardrail-only: the model was deliberately not called, so there
  // is no reply and it is neither a block nor an error.
  outcome: "reply" | "skipped" | "blocked" | "error";
  externalGuardrails?: ExportGuardrails;
  model?: string;
  ray?: string;
  reply?: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number; estimated: boolean };
  cost?: number | null;
  detection?: string;
  reason?: string;
  reasonCode?: string; // the edge rule's own reason_code, when its response carried one
  errorText?: string;
  verdict?: VerdictSummary;
}

export interface SessionExport {
  exportedAt: string;
  source: string;
  systemPrompt: string;
  turnCount: number;
  turns: ExportTurn[];
}

// Pair up [user, response] messages into export turns. Every user push in
// useChat is followed by exactly one assistant/blocked/error message before
// the next user push, so simple adjacent pairing is enough — see
// buildHistory() in lib/chatHistory.ts for the same assumption.
function pairTurns(messages: Msg[]): ExportTurn[] {
  const turns: ExportTurn[] = [];
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (m.kind !== "user") continue;
    const next = messages[i + 1];
    if (!next) continue;
    if (next.kind === "assistant") {
      turns.push({
        ts: next.ts,
        tsMs: next.tsMs,
        prompt: m.text,
        outcome: "reply",
        model: next.meta.model,
        ray: next.ray,
        reply: next.text,
        usage: next.meta.usage,
        cost: next.meta.cost,
        externalGuardrails: next.meta.externalGuardrails && summarizePipeline(next.meta.externalGuardrails),
      });
    } else if (next.kind === "blocked") {
      turns.push({
        ts: next.ts,
        tsMs: next.tsMs,
        prompt: m.text,
        outcome: "blocked",
        ray: next.ray,
        detection: next.detection,
        reason: next.reason,
        reasonCode: next.code,
      });
    } else if (next.kind === "guardrails") {
      turns.push({
        ts: next.ts,
        tsMs: next.tsMs,
        prompt: m.text,
        outcome: "blocked",
        ray: next.ray,
        detection: "gateway-guardrails",
        reason:
          next.direction === "response"
            ? "response blocked by AI Gateway Guardrails (2017)"
            : "prompt blocked by AI Gateway Guardrails (2016)",
      });
    } else if (next.kind === "external") {
      const p = next.pipeline;
      // The deciding result is the one `stoppedBy` names, not results[0].
      const r = p.results.find((x) => x.provider === p.stoppedBy);
      const externalGuardrails = summarizePipeline(p);
      // A fail-closed provider error stopped the turn too, but it is not a
      // verdict — export it as an error so the report never claims a detection.
      if (r?.outcome === "block") {
        turns.push({
          ts: next.ts,
          tsMs: next.tsMs,
          prompt: m.text,
          outcome: "blocked",
          ray: next.ray,
          detection: `external-guardrail:${r.provider}`,
          reason: `blocked by ${r.provider} (${r.category ?? "no category"}${r.detected?.length ? `: ${r.detected.join(", ")}` : ""})${r.scanId ? ` · scan ${r.scanId}` : ""}`,
          externalGuardrails,
        });
      } else {
        turns.push({
          ts: next.ts,
          tsMs: next.tsMs,
          prompt: m.text,
          outcome: "error",
          ray: next.ray,
          errorText: r
            ? `${r.provider} unavailable: ${r.error ?? "unknown error"}`
            : `stopped by ${p.stoppedBy ?? "an external guardrail"}, but no result was returned for it`,
          externalGuardrails,
        });
      }
    } else if (next.kind === "guardrailOnly") {
      turns.push({
        ts: next.ts,
        tsMs: next.tsMs,
        prompt: m.text,
        outcome: "skipped",
        ray: next.ray,
        externalGuardrails: next.pipeline && summarizePipeline(next.pipeline),
      });
    } else if (next.kind === "error") {
      turns.push({ ts: next.ts, tsMs: next.tsMs, prompt: m.text, outcome: "error", errorText: next.text });
    }
  }
  return turns;
}

function summarizeVerdict(d: VerdictData): VerdictSummary {
  return {
    available: true,
    action: verdictOutcome(d),
    rulesHit: (d.rules ?? []).map((r) => ({ rule: r.description || r.ruleId, action: r.action })),
    scored: !!d.scored,
    injectionScore: d.ai?.injectionScore ?? null,
    piiCategories: d.ai?.piiCategories ?? [],
    unsafeTopics: (d.ai?.unsafeTopicCategories ?? []).map(topicLabel),
    customTopics: d.ai?.customTopicCategories ?? [],
  };
}

// Builds the full export, re-fetching each turn's edge verdict with a single
// best-effort lookup (not the multi-minute poll the live UI uses — if
// analytics haven't ingested yet the turn is marked unavailable rather than
// blocking the export for up to two minutes per turn).
//
// Each lookup is anchored to the turn's own timestamp. Without the anchor the
// server searches a window around *now*, so exporting a session that has been
// open for more than ~15 minutes reported every turn as "not yet ingested"
// while the rows were sitting in the dataset the whole time.
export async function buildSessionExport(messages: Msg[], systemPrompt: string): Promise<SessionExport> {
  const turns = pairTurns(messages);
  await Promise.all(
    turns.map(async (t) => {
      if (!t.ray) return;
      try {
        const d = await getVerdict(t.ray, t.tsMs);
        if (d.configured === false) {
          t.verdict = { available: false, reason: "live edge log disabled (CF_ANALYTICS_TOKEN not set)" };
        } else if (d.error) {
          t.verdict = { available: false, reason: d.error };
        } else if (d.ai || d.found || (d.rules && d.rules.length)) {
          t.verdict = summarizeVerdict(d);
        } else {
          t.verdict = { available: false, reason: "not yet ingested — check Security → Events" };
        }
      } catch (err) {
        t.verdict = { available: false, reason: "network error: " + err };
      }
    }),
  );
  return {
    exportedAt: new Date().toISOString(),
    source: "Cloudflare AI Security for Apps — demo",
    systemPrompt,
    turnCount: turns.length,
    turns,
  };
}

export function toMarkdown(exp: SessionExport): string {
  const lines: string[] = [
    "# Cloudflare AI Security for Apps — session export",
    "",
    `Exported ${exp.exportedAt} · ${exp.turnCount} turn${exp.turnCount === 1 ? "" : "s"}`,
    "",
    `**System prompt:** ${exp.systemPrompt || "_(default)_"}`,
    "",
  ];

  exp.turns.forEach((t, i) => {
    lines.push(`## Turn ${i + 1} — ${t.ts}`, "", `> ${t.prompt}`, "");
    if (t.outcome === "blocked") {
      // No fallback names a detection or credits AI Security: a 403 whose body did not
      // identify itself says only that the edge refused it (the verdict line says who).
      const who = t.detection ?? (t.reasonCode ? `rule ${t.reasonCode}` : "edge, unattributed");
      lines.push(`**Blocked** — ${who}: ${t.reason ?? "the response carried no structured reason"}`);
    } else if (t.outcome === "error") {
      lines.push(`**Error** — ${t.errorText}`);
    } else if (t.outcome === "skipped") {
      // Not a reply: nothing answered, so no model, tokens or cost to report.
      lines.push(
        "**Model skipped** — guardrail-only mode. The prompt passed the edge WAF" +
          (t.externalGuardrails?.results.length ? " and every enabled external guardrail" : "; no external guardrail was enabled") +
          ". The model was not called, and AI Gateway Guardrails did not run.",
      );
    } else {
      const cost = t.cost != null ? `, ~$${t.cost.toFixed(6)}` : "";
      lines.push(`**Reply** (${t.model ?? "model"}${cost}):`, "", t.reply ?? "");
    }
    lines.push("");
    if (t.ray) lines.push(`ray: \`${t.ray}\``);
    if (t.externalGuardrails) {
      const g = t.externalGuardrails;
      lines.push(`external guardrails (${g.mode}, ${g.latencyMs} ms total):`);
      for (const r of g.results) {
        const what =
          r.outcome === "error"
            ? r.failedOpen
              ? "unavailable — ran unscanned (fail open)"
              : "unavailable — not a verdict"
            : r.outcome;
        lines.push(`- ${r.provider}: ${what} (${r.latencyMs} ms)${r.provider === g.stoppedBy ? " — stopped the turn" : ""}`);
      }
      for (const n of g.notRun) lines.push(`- ${n.provider}: did not run — ${n.reason}`);
    }
    if (t.verdict?.available) {
      const v = t.verdict;
      lines.push(`edge verdict: **${v.action}**`);
      if (v.rulesHit.length) lines.push(`rules hit: ${v.rulesHit.map((r) => `${r.rule} [${r.action}]`).join(", ")}`);
      if (v.scored) {
        lines.push(`injection_score: ${v.injectionScore}`);
        if (v.piiCategories.length) lines.push(`PII: ${v.piiCategories.join(", ")}`);
        if (v.unsafeTopics.length) lines.push(`unsafe topics: ${v.unsafeTopics.join(", ")}`);
        if (v.customTopics.length)
          lines.push(`custom topics: ${v.customTopics.map((c) => `${c.label} (${c.score})`).join(", ")}`);
      }
    } else if (t.verdict) {
      lines.push(`edge verdict: unavailable — ${t.verdict.reason}`);
    }
    lines.push("", "---", "");
  });

  return lines.join("\n");
}

export function downloadFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
