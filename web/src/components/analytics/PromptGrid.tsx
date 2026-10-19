// Prompt × vendor grid (2026-10-19): what each vendor answered on each curated prompt in the window — the scheduled set
// and its reply pairs, and the Red Team's rows — from the prompt id each verdict carries since 2026-10-18.
//
// Honesty rules, as everywhere on this page:
//   - A cell shows the vendor's NEWEST verdict (block / allow) in words and a symbol, never colour alone.
//   - A wrong answer is named: an attack allowed is "missed", a harmless prompt blocked is "false block".
//   - A vendor that answered the same prompt both ways in the window is marked "mixed", with the counts on hover — that is
//     drift (or a vendor that is not deterministic), the thing this grid exists to show.
//   - Only errors: "no verdict", never an allow. Never checked: "—".
//   - Ids only, never a prompt's text: the scheduled ids are in src/scheduledCorpus.ts, the Red Team's in its corpus.
import type { ExternalGuardrailProvider, PromptGrid as Grid, PromptGridCell } from "../../lib/types";
import { providerLabel } from "../../lib/guardrailView";

const ORDER: ExternalGuardrailProvider[] = [
  "prisma-airs",
  "crowdstrike-aidr",
  "cisco-ai-defense",
  "lakera-guard",
  "cato-ai-security",
  "datadog-ai-guard",
];

function Cell({ c, expect, n }: { c: PromptGridCell | undefined; expect: "attack" | "benign" | ""; n: (v: number) => string }) {
  if (!c) return <span className="text-subtle" title="This vendor did not check this prompt in the window">—</span>;
  const title = `blocked ${n(c.block)} · allowed ${n(c.allow)} · no verdict ${n(c.noVerdict)}${
    c.lastTs ? ` · newest verdict ${new Date(c.lastTs).toLocaleString()}` : ""
  }`;
  if (!c.last) return <span className="text-subtle" title={title}>no verdict</span>;
  const mixed = c.block > 0 && c.allow > 0;
  const wrong = (c.last === "allow" && expect === "attack") || (c.last === "block" && expect === "benign");
  const block = c.last === "block";
  return (
    <span className="inline-flex flex-wrap items-center gap-1" title={title}>
      <span
        className={`inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-[10.5px] font-bold ${
          block ? "border-cf-red/50 bg-cf-red/10 text-cf-red" : "border-cf-green/50 bg-cf-green/10 text-cf-green-ink"
        }`}
      >
        <span aria-hidden>{block ? "✕" : "✓"}</span>
        {block ? "block" : "allow"}
      </span>
      {wrong && (
        <span className="text-[10.5px] font-semibold text-cf-amber-ink">{block ? "false block" : "missed"}</span>
      )}
      {mixed && (
        <span className="rounded-full border border-dashed border-cf-amber/60 px-1 text-[10px] font-semibold text-cf-amber-ink">
          mixed
        </span>
      )}
    </span>
  );
}

export function PromptGrid({ grid, n }: { grid: Grid; n: (v: number) => string }) {
  const vendors = ORDER.filter((p) => grid.cells.some((c) => c.provider === p));
  const at = new Map(grid.cells.map((c) => [`${c.dir}|${c.promptId}|${c.provider}`, c]));
  return (
    <>
      <p className="mb-2 text-[11.5px] leading-relaxed text-muted">
        Each vendor's <b className="text-text">newest verdict</b> on each prompt in the window. <b className="text-text">missed</b>{" "}
        = an attack it allowed, <b className="text-text">false block</b> = a harmless prompt it blocked,{" "}
        <b className="text-text">mixed</b> = it answered the same prompt both ways in the window (hover for the counts).
        Prompt ids only — the scheduled ones are in <code className="font-mono text-[11px]">src/scheduledCorpus.ts</code>.
      </p>
      {grid.capped && (
        <p className="mb-2 text-[11.5px] text-cf-amber-ink">
          {grid.total} prompts in the window — the {grid.prompts.length} checked most often are shown.
        </p>
      )}
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-line text-left text-[11px] text-subtle">
              <th className="py-1.5 pr-3 font-semibold">Prompt</th>
              {vendors.map((p) => (
                <th key={p} className="py-1.5 pr-3 font-semibold whitespace-nowrap">
                  {providerLabel(p)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {grid.prompts.map((p) => (
              <tr key={`${p.dir}|${p.promptId}`} className="border-b border-line/60 last:border-0">
                <th scope="row" className="py-1.5 pr-3 text-left font-normal whitespace-nowrap">
                  <span className="font-mono text-[11.5px] text-text">{p.promptId}</span>{" "}
                  {p.expect && (
                    <span
                      className={`rounded-full border px-1.5 text-[10px] ${
                        p.expect === "attack" ? "border-cf-red/40 text-cf-red" : "border-line text-muted"
                      }`}
                    >
                      {p.expect === "attack" ? (p.dir === "reply" ? "should withhold" : "attack") : "harmless"}
                    </span>
                  )}{" "}
                  {p.dir === "reply" && <span className="rounded-full border border-line px-1.5 text-[10px] text-subtle">reply</span>}
                </th>
                {vendors.map((v) => (
                  <td key={v} className="py-1.5 pr-3">
                    <Cell c={at.get(`${p.dir}|${p.promptId}|${v}`)} expect={p.expect} n={n} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
