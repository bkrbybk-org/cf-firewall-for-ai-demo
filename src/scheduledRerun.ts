// #15: the scheduled re-run. Every 6 hours a Cron Trigger sends a fixed set of 12 prompts (src/scheduledCorpus.ts)
// straight to the enabled external guardrails, and logs each verdict like any other — source "scheduled" — so the
// Analytics page shows DRIFT: the same prompts, the same vendors, a different answer over time.
//
// Decided with the user (2026-10-12): every 6 hours, 12 prompts, no model calls.
//   - **Vendors only.** The cron runs inside the Worker, behind the edge, so the edge WAF is never re-tested here, and
//     the model is never called (guardrail-only): the point is the vendors' verdicts, and a model call would only
//     spend Neurons. ~12 calls per enabled vendor per run.
//   - **All at once, whatever the chat pipeline's mode.** Sequential would skip a vendor after another's block, and a
//     vendor that did not see a prompt cannot drift on it. Parallel gives every vendor every prompt; a quorum is a
//     chat-turn decision and has no meaning for a measurement.
//   - **Its own source.** "scheduled" is set here and nowhere else: a request header cannot claim it (sourceOf), so
//     chat and Red Team traffic never mix with the re-runs, and the re-runs never count as a person's chat.
//   - **Labelled.** Each prompt carries its fixed attack/benign label, so the false-block and catch rates apply.
//   - **A run id per prompt**, in the ray column, so the vendors' verdicts on one prompt group together (Analytics
//     "where the vendors disagreed"). It starts "sch" — real rays are hex only, so it can never be mistaken for one.
//   - A prompt's failure is a verdict row like any other (error / failed_open), never a skipped prompt: an outage is
//     exactly what this should show.

import { loadGuardrailSetup, runPipeline } from "./externalGuardrails";
import { logVerdicts } from "./guardrailLog";
import { SCHEDULED_PROMPTS, SCHEDULED_SET_VERSION } from "./scheduledCorpus";
import type { Env } from "./types";

export const RERUN_CRON = "0 */6 * * *";
// Between prompts: each prompt fans out to every enabled vendor at once, so a short gap keeps 12 prompts from
// landing on a vendor's rate limit as one burst. The whole run takes about half a minute.
export const RERUN_GAP_MS = 2000;

export function scheduledRunId(): string {
  return "sch" + crypto.randomUUID().replace(/-/g, "").slice(0, 13);
}

export interface RerunSummary {
  event: "scheduled_rerun";
  setVersion: number;
  vendors: number;
  prompts: number;
  ms: number;
  skipped?: string;
}

export async function runScheduledRerun(
  env: Env,
  deps: { fetchImpl?: typeof fetch; sleep?: (ms: number) => Promise<void>; log?: (line: unknown) => void } = {},
): Promise<RerunSummary> {
  const started = Date.now();
  const log = deps.log ?? ((line: unknown) => console.log(line));
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const base = { event: "scheduled_rerun" as const, setVersion: SCHEDULED_SET_VERSION };
  const setup = await loadGuardrailSetup(env);
  if (!setup || setup.enabled.length === 0) {
    const s = { ...base, vendors: 0, prompts: 0, ms: Date.now() - started, skipped: "no external guardrail enabled" };
    log(s);
    return s;
  }
  const forced = { pipeline: { ...setup.pipeline, mode: "parallel" as const, guardrailOnly: true }, enabled: setup.enabled };
  let sent = 0;
  for (const p of SCHEDULED_PROMPTS) {
    if (sent > 0) await sleep(RERUN_GAP_MS);
    const result = await runPipeline(env, { prompt: p.prompt, model: "", ray: null }, deps.fetchImpl ?? fetch, { setup: forced });
    logVerdicts(result, "scheduled", scheduledRunId(), { ae: env.GUARDRAIL_VERDICTS, expect: p.expect });
    sent++;
  }
  const s = { ...base, vendors: setup.enabled.length, prompts: sent, ms: Date.now() - started };
  log(s);
  return s;
}
