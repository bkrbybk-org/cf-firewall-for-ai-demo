// Red Team open item H: a saved run's guardrail benchmark as a file someone can keep
// or hand to a customer — Markdown to read, JSON to re-check. Pure; the button lives in
// components/redteam/SavedRuns.tsx.
//
// What this file must not do, and why:
//  - Compute a score of its own. Every number comes from the functions the page uses
//    (savedRunBenchmarkInput → vendorScorecard / falseBlockScores / vendorBenchmark /
//    headToHead / vendorLatency), so the report can never disagree with the screen.
//  - Export an unsaved run. A saved run is the only thing with a server-assigned id and
//    time, and its prompts are the Worker's redacted 200-character previews
//    (src/redteamruns.ts toPromptPreview) — the full prompts a live run holds can carry
//    whatever a CSV contained, and a report is made to leave the building.
//  - Carry anything a vendor wrote. A saved run stores verdict words, provider ids and
//    timings only (never `raw`), and that is all this reads.
//  - Drop the rules that make a number mean something. "—" is "scanned nothing", never
//    0%; every rate carries n and its 95% interval; best/lowest only where the page
//    would mark it; and the report says what it does NOT record (the policies in force).
//  - Let a prompt or label rewrite the document. Prompts are hostile by construction —
//    this is a red-team corpus — so every operator- or attacker-supplied string is
//    escaped before it reaches Markdown (mdText), invisible characters included.
import { isAttack, scoreRun, type RtRunResult, type RtSavedRun, type RtScore } from "./redteam";
import { savedRunBenchmarkInput } from "./savedRuns";
import { replyCounts, type ReplyCounts } from "./replyCounts";
import { fmtInterval, wilson } from "./stats";
import { TECHNIQUE_LABEL } from "./techniques";
import { topicOf, vendorBenchmark, type BenchmarkGroupBy, type BenchmarkMetric } from "./vendorBenchmark";
import { fmtMs, stageLatency, vendorLatency, type LatencyStat } from "./vendorLatency";
import {
  balancedAccuracy,
  countBlockedByAny,
  falseBlockScores,
  headToHead,
  providersIn,
  vendorScorecard,
  verdictOf,
  type ControlScore,
  type FalseBlockScore,
  type HeadToHead,
  type Verdict,
} from "./vendorScorecard";

export const REPORT_SCHEMA = "cf-ai-redteam-benchmark/1";

export interface ReportGrid {
  groupBy: BenchmarkGroupBy;
  metric: BenchmarkMetric;
  rows: {
    group: string;
    prompts: number;
    cells: { control: string; hits: number; scanned: number; pct: number | null; ci: { lo: number; hi: number } | null; mark: "best" | "lowest" | null }[];
    missedByAll: number;
    blockedByAny: number;
    rankedOver: number; // 0 = this row compares nobody (see notes)
  }[];
}

export interface ReportPrompt {
  id: string;
  kind: "attack" | "harmless";
  topic: string;
  language: string;
  technique: string | null;
  edgeState: string;
  verdicts: Record<string, Verdict>;
  promptPreview: string; // the server's redacted, 200-character preview — not the prompt sent
}

export interface BenchmarkReport {
  schema: typeof REPORT_SCHEMA;
  generatedAt: string;
  run: {
    id: number;
    label: string | null;
    savedAt: string;
    route: "direct" | "gateway";
    gatewayId: string | null;
    guarded: boolean;
    corpusName: string;
    corpusFingerprint: string;
    attacks: number;
    harmless: number;
    pipelineModes: string[];
    verdictsRecorded: boolean; // false: saved before guardrail verdicts were stored with runs
  };
  controls: { id: string; label: string }[];
  edge: RtScore; // the edge headline over the attack rows, as the page's scorecard reads it
  attackScores: (ControlScore & { ci: { lo: number; hi: number } | null; balancedPct: number | null })[];
  missedByAll: number;
  unevenCoverage: boolean;
  harmless: { scores: FalseBlockScore[]; blockedByAny: number } | null;
  headToHead: HeadToHead[];
  latency: { perControl: { control: string; stat: LatencyStat }[]; stage: { mode: string; stat: LatencyStat }[] };
  grids: ReportGrid[];
  // Design J: the reply check, as counts (lib/replyCounts.ts). null when no reply was checked.
  replies: ReplyCounts | null;
  prompts: ReportPrompt[];
  notes: string[];
}

const ci = (k: number, n: number) => {
  const i = wilson(k, n);
  return i ? { lo: i.lo, hi: i.hi } : null;
};

export function buildBenchmarkReport(
  run: RtSavedRun,
  labels: Record<string, string> = {},
  now: number = Date.now(),
): BenchmarkReport {
  const { corpus, results } = savedRunBenchmarkInput(run);
  const all = [...results.values()];
  const providers = providersIn(all);
  const controls = ["edge", ...providers];
  const attackCorpus = corpus.filter(isAttack);
  const benignCorpus = corpus.filter((a) => !isAttack(a));
  const attackList = attackCorpus.map((a) => results.get(a.id)!);
  const benignList = benignCorpus.map((a) => results.get(a.id)!);

  const card = vendorScorecard(attackList, labels, providers);
  const fb = benignList.length > 0 ? falseBlockScores(benignList, labels, providers) : null;
  const hasVariants = corpus.some((a) => a.technique);

  const grid = (groupBy: BenchmarkGroupBy, metric: BenchmarkMetric): ReportGrid => {
    const b = vendorBenchmark(metric === "catch" ? attackCorpus : benignCorpus, results, groupBy, controls, labels, metric);
    return {
      groupBy,
      metric,
      rows: b.rows.map((r) => ({
        group: r.key,
        prompts: r.attacks,
        cells: r.cells.map((c) => ({
          control: c.control,
          hits: c.caught,
          scanned: c.scanned,
          pct: c.catchPct,
          ci: c.ci ? { lo: c.ci.lo, hi: c.ci.hi } : null,
          mark: c.rank === "best" ? "best" : c.rank === "worst" ? "lowest" : null,
        })),
        missedByAll: r.missedByAll,
        blockedByAny: r.blockedByAny,
        rankedOver: r.rankedOver,
      })),
    };
  };
  const grids: ReportGrid[] = [];
  if (attackCorpus.length > 0) {
    grids.push(grid("topic", "catch"), grid("language", "catch"));
    if (hasVariants) grids.push(grid("technique", "catch"));
  }
  if (benignCorpus.length > 0) grids.push(grid("topic", "falseBlock"), grid("language", "falseBlock"));

  const recorded = run.results.some((r) => r.vendors || r.lang);
  return {
    schema: REPORT_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    run: {
      id: run.id,
      label: run.label?.trim() || null,
      savedAt: new Date(run.ts).toISOString(),
      route: run.route,
      gatewayId: run.gatewayId ?? null,
      guarded: !!run.guarded,
      corpusName: run.corpusName,
      corpusFingerprint: run.corpusFingerprint,
      attacks: attackCorpus.length,
      harmless: benignCorpus.length,
      pipelineModes: card.modes,
      verdictsRecorded: recorded,
    },
    controls: controls.map((c) => ({ id: c, label: c === "edge" ? "Edge WAF" : (labels[c] ?? c) })),
    edge: scoreRun(attackList),
    attackScores: card.controls.map((c) => ({
      ...c,
      ci: ci(c.caught, c.scanned),
      balancedPct: balancedAccuracy(c, fb?.find((f) => f.control === c.control)),
    })),
    missedByAll: card.missedByAll,
    unevenCoverage: card.unevenCoverage,
    harmless: fb ? { scores: fb, blockedByAny: countBlockedByAny(benignList, providers) } : null,
    // Attack rows only — a harmless prompt "caught" is a false block, as on the page.
    headToHead: headToHead(attackList, providers, labels),
    latency: {
      // About the call, not the prompt: attack and harmless rows both count (as on the page).
      perControl: providers.map((p) => ({ control: p, stat: vendorLatency(all, p) })),
      stage: stageLatency(all).map((s) => ({ mode: s.mode, stat: s.stat })),
    },
    grids,
    replies: (() => {
      const c = replyCounts(corpus, results, labels);
      return c.providers.length > 0 ? c : null;
    })(),
    prompts: corpus.map((a) => {
      const r = results.get(a.id) as RtRunResult;
      return {
        id: a.id,
        kind: isAttack(a) ? "attack" : "harmless",
        topic: topicOf(a), // the grid's own row key, so the appendix and the grid agree
        language: a.lang ?? "",
        technique: a.technique ? TECHNIQUE_LABEL[a.technique] : null,
        edgeState: r.state,
        verdicts: Object.fromEntries(controls.map((c) => [c, verdictOf(r, c)])),
        promptPreview: a.prompt,
      };
    }),
    notes: reportNotes(card.unevenCoverage, card.modes.includes("sequential"), recorded),
  };
}

function reportNotes(uneven: boolean, sequential: boolean, recorded: boolean): string[] {
  const notes = [
    "One run, one moment. The report records the verdicts, not the configuration that produced them: which edge rules, guardrail policies and vendor regions were in force is not stored with a run.",
    "A control is scored only on the prompts it gave a verdict on (caught, missed or alerted). Errors, prompts it never saw, and prompts an earlier guardrail stopped first are counted beside the rate, never inside it. A dash means it scanned nothing — not 0%.",
    "Catch rate = caught ÷ scanned. A Detect-mode alert (flagged, not blocked) is not a catch.",
    "Every rate carries its 95% Wilson interval. At these sample sizes the intervals are wide: two rates whose intervals overlap are not a result.",
    "\"Best\" and \"lowest\" mark a row only when at least two controls scanned exactly the same prompts, at least 3 of them, and the leader's interval clears every other control's. Ties never mark.",
    "The edge verdict is the zone's WAF action for the request. Its latency is not measurable from the Worker; guardrail latency is each call as the Worker timed it, and depends on the vendor region and the Cloudflare location.",
    "Prompts are the Worker's redacted 200-character previews stored with the run, not the prompts that were sent. Invisible and control characters are shown as ⟨U+XXXX⟩.",
    "Topic and language are the labels stored when the run was saved. A rewritten variant (Base64, leetspeak, zero-width) keeps its original's topic and language.",
  ];
  if (uneven) {
    notes.unshift(
      `Not a like-for-like comparison: the guardrails did not all scan the same prompts${sequential ? " (sequential mode — a later guardrail never sees what an earlier one blocked)" : ""}.`,
    );
  }
  if (!recorded) {
    notes.unshift("This run was saved before guardrail verdicts were stored with runs: it has edge results only.");
  }
  return notes;
}

// ── Markdown ─────────────────────────────────────────────────────────────────

// Characters that render as nothing, or reorder the text around them (bidi
// overrides), shown as a visible code — a zero-width variant must read as one.
const INVISIBLE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]/g;

// One line of untrusted text, safe inside a Markdown paragraph or a table cell:
// every ASCII punctuation character that means something mid-line in Markdown, GFM
// or GitHub's math ($) is backslash-escaped (CommonMark renders an escaped
// punctuation character literally), so a prompt cannot close a table cell, open a
// link, raw HTML, an entity or an autolink (`:` breaks "https://", the "www." rule
// below the bare form). Line-start syntax (-, +, =, a leading #) cannot occur: the
// text never starts a line. Line breaks become a visible ↵, since a raw newline
// ends a table row.
export function mdText(s: string): string {
  return s
    .replace(/[\\`*_[\]()<>#!|~:&$]/g, (c) => `\\${c}`)
    .replace(/www\./gi, (m) => `${m.slice(0, 3)}\\.`)
    .replace(/\r\n|\r|\n|\u2028|\u2029/g, " ↵ ")
    .replace(/\t/g, " ")
    .replace(INVISIBLE, (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`);
}

const pct = (n: number | null) => (n == null ? "—" : `${n}%`);
const rate = (k: number, n: number, p: number | null, i: { lo: number; hi: number } | null) =>
  p == null ? "—" : `${p}% (${k}/${n}; ${fmtInterval(i)})`;
// No timings at all is "not recorded" (a run saved before latency was), never a dash
// that could pass for "instant" or for "never called".
const lat = (s: LatencyStat) =>
  s.n === 0
    ? s.untimed > 0
      ? `not recorded (${s.untimed} untimed)`
      : s.errorsExcluded > 0
        ? `— (${s.errorsExcluded} errors excluded)`
        : "—"
    : `${fmtMs(s.p50)} · ${fmtMs(s.p95)} (n=${s.n}${s.errorsExcluded ? `, ${s.errorsExcluded} errors excluded` : ""}${s.untimed ? `, ${s.untimed} untimed` : ""})`;

function table(head: string[], rows: string[][], right: number[] = []): string[] {
  return [
    `| ${head.join(" | ")} |`,
    `| ${head.map((_, i) => (right.includes(i) ? "---:" : "---")).join(" | ")} |`,
    ...rows.map((r) => `| ${r.join(" | ")} |`),
  ];
}

const GRID_TITLE: Record<BenchmarkGroupBy, string> = { topic: "topic", language: "language", technique: "technique" };
const VERDICT_WORD: Record<Verdict, string> = {
  caught: "caught",
  missed: "missed",
  alerts: "alerts",
  error: "error",
  notSeen: "not seen",
  notRun: "not run",
};
// The same verdict read the other way round on a harmless row: "caught" there is a
// false block, and printing "caught" would read as a success.
const HARMLESS_WORD: Record<Verdict, string> = { ...VERDICT_WORD, caught: "blocked (false block)", missed: "passed" };
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function reportToMarkdown(r: BenchmarkReport): string {
  const label = (id: string) => mdText(r.controls.find((c) => c.id === id)?.label ?? id);
  const L: string[] = [];
  L.push(`# Red Team benchmark — run #${r.run.id}${r.run.label ? `: ${mdText(r.run.label)}` : ""}`, "");
  L.push(
    `- **Saved:** ${r.run.savedAt} (UTC)`,
    `- **Report generated:** ${r.generatedAt} (UTC)`,
    `- **Corpus:** ${mdText(r.run.corpusName)} — ${r.run.attacks} attack prompts, ${r.run.harmless} harmless prompts (fingerprint ${mdText(r.run.corpusFingerprint)})`,
    `- **Route:** ${r.run.route === "gateway" ? `AI Gateway${r.run.gatewayId ? ` — gateway ${mdText(r.run.gatewayId)}` : ""}${r.run.guarded ? ", Guardrails on" : ""}` : "direct to Workers AI"}`,
    `- **Guardrail pipeline:** ${r.run.pipelineModes.length ? r.run.pipelineModes.join(", ") : "none recorded"}`,
    `- **Controls:** ${r.controls.map((c) => mdText(c.label)).join(", ")}`,
    "",
  );

  L.push("## How to read this report", "", ...r.notes.map((n) => `- ${n}`), "");

  L.push("## Edge headline", "");
  const e = r.edge;
  L.push(
    e.scored === 0
      ? "No attack has an edge verdict in this run (all pending, refused by something other than the WAF, or failed)."
      : `${e.reached} of ${e.scored} attacks with an edge verdict reached the model (${e.reachedPct}%); ${plural(e.stopped, "was", "were")} stopped by the edge.`,
    `Not in that denominator: ${e.external} stopped by an external guardrail, ${e.guardrails} by AI Gateway Guardrails, ${e.denied} refused by something other than the WAF, ${e.pending} with no verdict yet, ${e.error} failed.`,
    "",
  );
  if (e.external + e.guardrails > 0) {
    // The two edge numbers answer different questions, and a reader comparing them
    // would otherwise think one is wrong.
    L.push(
      "The table below counts the edge differently: a prompt that a guardrail stopped had already passed the edge, so there it is an edge miss.",
      "",
    );
  }

  if (r.attackScores.length > 0 && r.run.attacks > 0) {
    L.push("## Controls compared — attacks", "");
    const fbOf = (id: string) => r.harmless?.scores.find((f) => f.control === id);
    const latOf = (id: string) => r.latency.perControl.find((p) => p.control === id)?.stat;
    const head = ["Control", "Catch rate (caught/scanned; 95% CI)", "Alerts only", "Only this control", "Errors", "Not seen", "Not run"];
    if (r.harmless) head.push("False blocks", "Balanced accuracy");
    head.push("Latency p50 · p95");
    L.push(
      ...table(
        head,
        r.attackScores.map((c) => {
          const row = [
            label(c.control),
            rate(c.caught, c.scanned, c.catchPct, c.ci),
            String(c.alerts),
            String(c.onlyThis),
            String(c.errors),
            String(c.notSeen),
            String(c.notRun),
          ];
          if (r.harmless) {
            const f = fbOf(c.control);
            row.push(f ? rate(f.blocked, f.checked, f.falseBlockPct, ci(f.blocked, f.checked)) : "—", pct(c.balancedPct));
          }
          const s = latOf(c.control);
          row.push(c.control === "edge" ? "not measurable" : s ? lat(s) : "—");
          return row;
        }),
        head.map((_, i) => i).filter((i) => i > 0 && i < head.length - 1),
      ),
      "",
      r.missedByAll === 0
        ? "Every attack that a control scanned was caught by at least one of them."
        : `${r.missedByAll} attack${r.missedByAll === 1 ? " was" : "s were"} scanned by at least one control and caught by none.`,
      "",
    );
    for (const s of r.latency.stage) {
      L.push(`Guardrail stage, ${s.mode} (${s.mode === "parallel" ? "the slowest call" : "the sum of the calls"} per prompt): ${lat(s.stat)}.`, "");
    }
  }

  if (r.harmless) {
    L.push(
      "## Harmless prompts",
      "",
      `${r.harmless.blockedByAny} of ${r.run.harmless} harmless prompts were blocked by at least one control — a real user would have been refused.`,
      "",
    );
  }

  if (r.headToHead.length > 0) {
    L.push("## Head to head", "", "Each pair on the attacks both scanned.", "");
    L.push(
      ...table(
        ["A", "B", "Both scanned", "Both caught", "Only A", "Only B", "Neither"],
        r.headToHead.map((h) => [mdText(h.aLabel), mdText(h.bLabel), String(h.n), String(h.both), String(h.onlyA), String(h.onlyB), String(h.neither)]),
        [2, 3, 4, 5, 6],
      ),
      "",
    );
  }

  for (const g of r.grids) {
    const what = g.metric === "catch" ? "Catch rate" : "False-block rate (lower is better)";
    L.push(`## ${what} by ${GRID_TITLE[g.groupBy]}`, "");
    L.push(
      ...table(
        [GRID_TITLE[g.groupBy][0].toUpperCase() + GRID_TITLE[g.groupBy].slice(1), "Prompts", ...r.controls.map((c) => mdText(c.label)), g.metric === "catch" ? "Missed by all" : "Blocked by any"],
        g.rows.map((row) => [
          mdText(row.group),
          String(row.prompts),
          ...row.cells.map((c) => `${rate(c.hits, c.scanned, c.pct, c.ci)}${c.mark === "best" ? " **▲ best**" : c.mark === "lowest" ? " **▼ lowest**" : ""}`),
          String(g.metric === "catch" ? row.missedByAll : row.blockedByAny),
        ]),
        [1],
      ),
      "",
    );
    const ranked = g.rows.filter((row) => row.rankedOver > 0).length;
    const marked = g.rows.filter((row) => row.cells.some((c) => c.mark)).length;
    L.push(
      ranked === 0
        ? "No row compares controls on the same prompts (at least 3 of them), so none is ranked."
        : `${plural(ranked, "row compares", "rows compare")} controls on the same prompts; ${marked === 0 ? `${ranked === 1 ? "its lead is" : "in each, the lead is"} within the margin of error, so nothing is marked` : `${plural(marked, "has", "have")} a lead bigger than the margin of error`}.`,
      "",
    );
  }

  if (r.replies) {
    const rp = r.replies;
    L.push(
      "## Replies checked",
      "",
      "What each guardrail said about the model's reply. Counts only: an attack prompt does not make its reply harmful (a model that refused wrote a harmless reply), so there is no reply catch rate. On harmless prompts a blocked reply is very likely a false block." +
        (rp.notCheckedRows > 0 ? ` ${plural(rp.notCheckedRows, "prompt's reply was", "prompts' replies were")} not checked and not counted.` : ""),
      "",
    );
    for (const [title, side] of [
      ["Attack prompts", rp.attacks],
      ["Harmless prompts", rp.harmless],
    ] as const) {
      if (side.rows === 0) continue;
      L.push(`**${title}** — ${plural(side.rows, "reply", "replies")} checked, ${side.withheld} withheld by one or more guardrails.`, "");
      L.push(
        ...table(
          ["Guardrail", "Blocked of checked", "Alerts only", "Errors", "Not checked"],
          side.byControl.map((c) => [
            mdText(c.label),
            c.checked === 0 ? "—" : `${c.blocked} of ${c.checked}`,
            String(c.alerts),
            String(c.errors),
            String(c.notChecked),
          ]),
          [1, 2, 3, 4],
        ),
        "",
      );
    }
  }

  if (r.prompts.length > 0) {
    L.push(
      "## Prompts",
      "",
      "Redacted previews, as stored with the run. Edge state is the run's result for the request: block or challenge (the edge stopped it), allow or log (it passed the edge), external (an external guardrail stopped it), guardrails (AI Gateway Guardrails stopped it), denied (refused by something other than the WAF), pending or error (no verdict). On a harmless prompt, a block is a false block.",
      "",
    );
    L.push(
      ...table(
        ["Id", "Kind", "Topic", "Language", "Technique", "Edge state", ...r.controls.map((c) => mdText(c.label)), "Prompt preview"],
        r.prompts.map((p) => [
          mdText(p.id),
          p.kind,
          mdText(p.topic),
          mdText(p.language),
          p.technique ?? "Original",
          p.edgeState,
          ...r.controls.map((c) => (p.kind === "harmless" ? HARMLESS_WORD : VERDICT_WORD)[p.verdicts[c.id]]),
          mdText(p.promptPreview),
        ]),
      ),
      "",
    );
  }
  return L.join("\n");
}

export function reportFilename(r: BenchmarkReport, ext: "md" | "json"): string {
  const stamp = r.run.savedAt.slice(0, 16).replace(/[-:]/g, "").replace("T", "-");
  return `redteam-benchmark-run-${r.run.id}-${stamp}.${ext}`;
}
