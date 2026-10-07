// Design J, part 2: what the guardrails said about the model's REPLIES in a Red Team
// run. COUNTS ONLY — the user's decision (D4, 2026-10-07) — and on purpose:
//  - An attack prompt does not make its reply harmful. A model that refused wrote a
//    harmless reply, and a guardrail that let it through was right. With no ground
//    truth for the reply, a "reply catch rate" over attack rows would be invented, so
//    there is none: "N replies blocked of M checked", never a percentage or a trophy.
//  - Harmless prompts are counted the same way. A blocked reply there is very likely a
//    false block, and the table says so in words, but it stays a count.
//  - "Checked" = the guardrail gave a verdict on the reply (block, allow or alerts). An
//    error, a guardrail that cannot check replies, or one an earlier guardrail made
//    redundant (sequential) is "not checked", counted beside it — never a pass.
//  - A prompt whose reply was not checked at all (switch off, no reply, model skipped)
//    is outside every count, and the total of those is stated.
import { isAttack, type RedTeamAttack, type RtRunResult } from "./redteam";

export interface ReplyCount {
  control: string;
  label: string;
  checked: number; // blocked + passed + alerts
  blocked: number;
  passed: number;
  alerts: number; // flagged, not blocked (Detect mode)
  errors: number; // could not be consulted — not a verdict
  notChecked: number; // cannot check replies, or not run (sequential)
}

export interface ReplyCounts {
  providers: string[];
  attacks: { rows: number; withheld: number; byControl: ReplyCount[] };
  harmless: { rows: number; withheld: number; byControl: ReplyCount[] };
  notCheckedRows: number; // prompts with a result whose reply was not checked at all
}

function count(rows: RtRunResult[], provider: string, label: string): ReplyCount {
  const c: ReplyCount = { control: provider, label, checked: 0, blocked: 0, passed: 0, alerts: 0, errors: 0, notChecked: 0 };
  for (const r of rows) {
    const v = r.replyVendors?.find((x) => x.provider === provider);
    if (!v || v.verdict === "notRun") c.notChecked++;
    else if (v.verdict === "error") c.errors++;
    else if (v.verdict === "block") c.blocked++;
    else if (v.verdict === "alerts") c.alerts++;
    else c.passed++;
  }
  c.checked = c.blocked + c.passed + c.alerts;
  return c;
}

export function replyCounts(
  corpus: RedTeamAttack[],
  results: Map<string, RtRunResult>,
  labels: Record<string, string> = {},
): ReplyCounts {
  const checkedRows: { r: RtRunResult; harmless: boolean }[] = [];
  let notCheckedRows = 0;
  for (const a of corpus) {
    const r = results.get(a.id);
    if (!r) continue;
    if (r.replyVendors && r.replyVendors.length > 0) checkedRows.push({ r, harmless: !isAttack(a) });
    else notCheckedRows++;
  }
  const providers = [...new Set(checkedRows.flatMap(({ r }) => r.replyVendors!.map((v) => v.provider)))];
  const side = (harmless: boolean) => {
    const rows = checkedRows.filter((x) => x.harmless === harmless).map((x) => x.r);
    return {
      rows: rows.length,
      // Withheld: at least one guardrail blocked the reply. A fail-closed error also
      // withholds one, but a stored "error" cannot say which fail mode applied, so it
      // is counted as an error, not here.
      withheld: rows.filter((r) => r.replyVendors!.some((v) => v.verdict === "block")).length,
      byControl: providers.map((p) => count(rows, p, labels[p] ?? p)),
    };
  };
  return { providers, attacks: side(false), harmless: side(true), notCheckedRows };
}
