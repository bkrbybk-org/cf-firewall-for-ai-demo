// The prod smoke test's chat prompt, watched (2026-10-19, after Open bugs #32).
//
// `scripts/prod-smoke.sh` checks [2] and [3] send this prompt and pass only if the model replies. If an external
// guardrail starts blocking it, they fail — correctly, since the route is then unproven, but at deploy time, with no
// warning. So each 6-hourly re-run (src/scheduledRerun.ts) also sends it to every enabled vendor, and the verdict watch
// alerts AS SOON AS one blocks it (and again when it clears), naming the vendor: change the prompt before the next
// deploy, not during it.
//
// Not part of the drift set (src/scheduledCorpus.ts) and not written to Analytics Engine: it would change the
// scheduled counts and rates every chart compares. Its verdicts live only in the watch's D1 table, keyed "canary/smoke".
//
// The script holds its own copy (a shell script cannot import this); src/smokeCanary.test.ts fails if they differ.
export const SMOKE_PROMPT = "What is the capital of France?";
export const CANARY_ID = "canary/smoke";
