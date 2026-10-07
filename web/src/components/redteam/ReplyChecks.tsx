// Design J, part 2: what each guardrail said about the model's replies in this run.
// Renders lib/replyCounts.ts and computes nothing itself. Counts only, never a rate
// or a winner: an attack prompt does not make its reply harmful (that file's header).
import type { ReplyCount, ReplyCounts } from "../../lib/replyCounts";

const th = "px-2 pb-1.5 text-right text-[10.5px] font-semibold tracking-wide text-subtle uppercase";
const num = "px-2 py-1.5 text-right font-mono text-[11.5px] tabular-nums";

function Side({ title, rows, byControl, blockedWord }: { title: string; rows: number; byControl: ReplyCount[]; blockedWord: string }) {
  if (rows === 0) return null;
  return (
    <>
      <tr>
        <td colSpan={5} className="pt-2.5 pb-1 pl-2 text-[11px] font-semibold text-muted">
          {title} — {rows} {rows === 1 ? "reply" : "replies"} checked
        </td>
      </tr>
      {byControl.map((c) => (
        <tr key={c.control} className="border-t border-line">
          <td className="py-1.5 pr-2 pl-2 text-[12px] font-semibold text-text">{c.label}</td>
          <td className={`${num} ${c.blocked > 0 ? "font-semibold text-text" : "text-muted"}`} title={`${c.blocked} ${blockedWord} of ${c.checked} it gave a verdict on`}>
            {c.checked === 0 ? "—" : `${c.blocked} of ${c.checked}`}
          </td>
          <td className={`${num} text-muted`}>{c.alerts}</td>
          <td className={`${num} text-muted`} title="could not be consulted — not a verdict">
            {c.errors}
          </td>
          <td className={`${num} text-muted`} title="cannot check replies, or not run after an earlier guardrail blocked the reply">
            {c.notChecked}
          </td>
        </tr>
      ))}
    </>
  );
}

export function ReplyChecks({ counts }: { counts: ReplyCounts }) {
  if (counts.providers.length === 0) return null;
  const { attacks, harmless, notCheckedRows } = counts;
  return (
    <div className="mt-4 border-t border-line pt-3">
      <h3 className="text-[12.5px] font-bold text-text">Replies checked</h3>
      <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
        What each guardrail said about the model's <b>reply</b>. Counts only: an attack prompt does not make its reply
        harmful — a model that refused wrote a harmless reply — so there is no reply catch rate. On harmless prompts a
        blocked reply is very likely a false block.
        {notCheckedRows > 0 &&
          ` ${notCheckedRows} ${notCheckedRows === 1 ? "prompt's reply was" : "prompts' replies were"} not checked (no reply, or reply checks off) and ${notCheckedRows === 1 ? "is" : "are"} not counted.`}
      </p>
      {/* relative: scroll box (CLAUDE.md, scroll containers). */}
      <div className="relative mt-2 overflow-x-auto">
        <table className="w-full min-w-[480px] border-collapse">
          <thead>
            <tr>
              <th className={`${th} text-left`}>Guardrail</th>
              <th className={th}>Blocked / checked</th>
              <th className={th}>Alerts only</th>
              <th className={th}>Errors</th>
              <th className={th}>Not checked</th>
            </tr>
          </thead>
          <tbody>
            <Side title="Attack prompts" rows={attacks.rows} byControl={attacks.byControl} blockedWord="replies blocked" />
            <Side title="Harmless prompts" rows={harmless.rows} byControl={harmless.byControl} blockedWord="replies blocked (likely false blocks)" />
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-[11.5px] text-muted">
        {attacks.rows > 0 && `${attacks.withheld} of ${attacks.rows} attack replies withheld by at least one guardrail.`}
        {harmless.rows > 0 && ` ${harmless.withheld} of ${harmless.rows} harmless replies withheld.`}
      </p>
    </div>
  );
}
