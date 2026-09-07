// ============================================================================
// Turns a red-team run's reached-model categories into concrete, copy-pasteable
// Cloudflare control recommendations, cross-referenced against the zone's
// actual WAF rules (useZoneRules).
//
// This is advice a customer may paste into a production zone, never something
// this app applies for them — there is no write path here (no Rulesets PUT),
// only strings for the operator to review and paste themselves. See
// GapControls.tsx for the read-only, copy-to-clipboard presentation.
//
// ── THE SCORE INVERSION (read this before touching a threshold) ────────────
// `cf.llm.prompt.injection_score` is 1–99 and LOW = attack; 100 = not scored.
// Custom-topic scores invert the same way. A block/log threshold is therefore
// always `injection_score le N` — never `ge` — and this holds for BOTH a
// block rule and a log rule; only N differs (a log rule usually carries a
// HIGHER `le`, since its job is to catch more borderline traffic for
// visibility, not to enforce on it). Get the comparison backwards and the
// rule either blocks all traffic (`ge` with a low N) or blocks nothing
// (`ge` with a high N) — see README.md "Zone setup" and src/cloudflare.ts.
// Every expression builder in this file hard-codes `le`; there is no branch
// that could emit `ge`.
//
// ── WHAT WE WILL AND WON'T INVENT ───────────────────────────────────────────
// Every field emitted here is verified against the Cloudflare Ruleset Engine
// field reference, NOT inferred from this repo. That distinction cost a round
// of rework: the repo's own artefacts (README's rule table, the ZONE_RULES
// mirror, src/zone-rules.test.ts) mention only five fields, and the mirror
// describes the zone's custom-topic rules in prose ("custom topic score ≤ 40")
// rather than as expressions — so grepping the repo suggests no custom-topic
// field exists. It does. The repo is simply not a field reference.
//
//   cf.llm.prompt.injection_score          Number       1–99, low = attack
//   cf.llm.prompt.pii_detected             Boolean
//   cf.llm.prompt.pii_categories           Array<String>  Presidio entity names
//   cf.llm.prompt.unsafe_topic_detected    Boolean
//   cf.llm.prompt.unsafe_topic_categories  Array<String>  S1–S14
//   cf.llm.prompt.custom_topic_categories  Map<Number>    1–99, low = match
//
// https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/
//
// The rule stands unchanged for anything NOT on that list: no field is
// fabricated to make a recommendation look complete. AI Gateway Guardrails
// (malicious code) has no cf.llm.* equivalent, so those gaps carry
// `expression: null` and say so. A plausible-looking invented field is worse
// than admitting we don't have one — a customer could paste a rule that
// silently never matches, and believe they were protected.
// ============================================================================
import { byCategory, type RedTeamAttack, type RtBreakdownRow, type RtRunResult } from "./redteam";
import type { ZoneRulesState, UiZoneRule } from "../hooks/useZoneRules";

const CHAT_PATH_EXPR = 'http.request.uri.path eq "/api/chat"';

// ── expression builders (pure, unit-tested directly) ────────────────────────

// Numeric injection_score threshold. `le` only — see file header. Thresholds
// outside 1–99 can't match anything real (100 means "not scored" and is
// deliberately excluded, since a rule catching "not scored" would fire on
// requests the detector never assessed).
export function injectionExpression(thresholdLe: number): string {
  if (!Number.isInteger(thresholdLe) || thresholdLe < 1 || thresholdLe > 99) {
    throw new Error(`injection threshold must be an integer in 1..99, got ${thresholdLe}`);
  }
  return `${CHAT_PATH_EXPR} and cf.llm.prompt.injection_score le ${thresholdLe}`;
}

// Boolean unsafe-topic trigger. There is no confirmed array-filter syntax in
// this repo for narrowing to specific S-codes (the live rules do that, but we
// only ever observe their prose summary or, at best, their compiled
// expression string — never the syntax for writing a NEW one), so the
// starting point is the boundary already proven safe: "any unsafe topic
// detected at all."
export function unsafeTopicExpression(): string {
  return `${CHAT_PATH_EXPR} and cf.llm.prompt.unsafe_topic_detected`;
}

// PII boolean trigger — kept for completeness/future corpora; the built-in
// RT_CORPUS has no PII-labeled category today (see redteam.ts), so no gap
// entry currently reaches this builder.
export function piiExpression(): string {
  return `${CHAT_PATH_EXPR} and cf.llm.prompt.pii_detected`;
}

// Custom-topic score threshold. `custom_topic_categories` is a Map<Number>
// keyed by the topic LABEL as typed in the dashboard, scored 1–99 with the
// same inversion as injection_score (low = strong match).
//
// Operator note: the field reference's own example uses `lt` and the zone's
// existing rules are documented as `≤ N`. Both are correct — what matters is
// the DIRECTION, never the strictness. `le` is used here so this file keeps a
// single invariant that is trivial to audit: no builder in it can emit `ge`.
//
// The label is a map key inside a quoted string, so a `"` or `\` in a topic
// name would terminate the literal early and produce a broken — or worse, a
// subtly different — expression. Reject those rather than escaping them: a
// topic name needing escapes almost certainly means the caller passed the
// wrong string, and this output gets pasted into a production zone.
export function customTopicExpression(topicLabel: string, thresholdLe: number): string {
  if (!Number.isInteger(thresholdLe) || thresholdLe < 1 || thresholdLe > 99) {
    throw new Error(`custom topic threshold must be an integer in 1..99, got ${thresholdLe}`);
  }
  const label = topicLabel.trim();
  if (!label || /["\\]/.test(label)) {
    throw new Error(`custom topic label must be non-empty and free of quotes/backslashes, got ${JSON.stringify(topicLabel)}`);
  }
  return `${CHAT_PATH_EXPR} and cf.llm.prompt.custom_topic_categories["${label}"] le ${thresholdLe}`;
}

// ── coverage cross-reference ─────────────────────────────────────────────
export type CoverageConfidence = "live-expression" | "live-name" | "fallback-name" | "none" | "not-applicable";

export interface GapCoverage {
  exists: boolean;
  ruleName?: string;
  confidence: CoverageConfidence;
  note: string;
}

// fieldNeedle: a substring to look for in a LIVE rule's real expression —
// ground truth, per useZoneRules' header comment. Pass null when no field
// name is confirmed (custom topics — see file header) so this function can
// never claim an expression match it didn't actually check.
// nameNeedles: lowercase substrings to match a rule's NAME. This is the only
// signal available on the fallback mirror (its "expression" is hand-written
// prose, not a real one — matching prose text would be indistinguishable
// from matching the real field, so we deliberately never try).
function coverageByField(state: ZoneRulesState, fieldNeedle: string | null, nameNeedles: string[]): GapCoverage {
  if (state.source === "live" && fieldNeedle) {
    const hit = state.rules.find((r) => r.llm && r.detail?.includes(fieldNeedle));
    if (hit) {
      return {
        exists: true,
        ruleName: hit.name,
        confidence: "live-expression",
        note: `Live zone: '${hit.name}' expression references ${fieldNeedle} — ground truth, not a name guess.`,
      };
    }
  }
  const hitName = state.rules.find((r) => nameNeedles.some((n) => r.name.toLowerCase().includes(n)));
  if (hitName) {
    return {
      exists: true,
      ruleName: hitName.name,
      confidence: state.source === "live" ? "live-name" : "fallback-name",
      note:
        state.source === "live"
          ? `Live zone: matched '${hitName.name}' by name only — its expression didn't confirm the field, so this is weaker than an expression match.`
          : `Static mirror (source=fallback — CF_ANALYTICS_TOKEN lacks Zone→WAF→Read): matched '${hitName.name}' by name only. The mirror's "expression" is hand-written prose, so this is not a verified field match.`,
    };
  }
  return {
    exists: false,
    confidence: "none",
    note:
      state.source === "live"
        ? "No live rule's name or expression plausibly covers this category."
        : "No rule in the static mirror (fallback) plausibly covers this category by name.",
  };
}

const NOT_APPLICABLE_COVERAGE: GapCoverage = {
  exists: false,
  confidence: "not-applicable",
  note: "Not a WAF control — useZoneRules only tracks the zone's WAF custom rules, not AI Gateway Guardrails settings.",
};

// ── category → mechanism mapping ────────────────────────────────────────
export type GapMechanism = "injection" | "unsafe_topic" | "custom_topic_existing" | "custom_topic_new" | "ai_gateway" | "unmapped";

export interface GapControl {
  category: string;
  reached: number; // in THIS run, not the PDF scan
  scored: number; // in THIS run
  mechanism: GapMechanism;
  recommendation: string; // prose: what to do and why
  expression: string | null; // copy-pasteable cf.llm.* expression, or null when inert
  expressionAction?: "block" | "log"; // the action the expression above is meant to sit on
  expressionNote?: string; // present when expression is null, or extra context
  coverage: GapCoverage;
}

interface MechanismSpec {
  mechanism: GapMechanism;
  fieldNeedle: string | null;
  nameNeedles: string[];
  build: (row: RtBreakdownRow, coverage: GapCoverage) => Pick<GapControl, "recommendation" | "expression" | "expressionAction" | "expressionNote">;
}

// Starting-point thresholds, one tier looser than the zone's current 15/50
// injection cutoffs. They are a REVIEW STARTING POINT, not a run-derived
// number — this module only ever sees the edge's block/log/allow verdict per
// attack (RtRunResult.state), never the numeric injection_score itself, so it
// cannot compute "the cutoff that would have caught this run's misses." A
// human should tune from here against the actual scores in the prompt log.
const INJECTION_BLOCK_STARTING_POINT = 30;
const INJECTION_LOG_STARTING_POINT = 65;

function injectionSpec(): MechanismSpec {
  return {
    mechanism: "injection",
    fieldNeedle: "injection_score",
    nameNeedles: ["injection"],
    build: (row, coverage) => ({
      recommendation: coverage.exists
        ? `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run despite '${coverage.ruleName}' existing on the zone — they scored above its cutoff (or landed in its log-only band). Raise the block threshold so more of this category is caught; remember higher le = broader net, since low scores are the attacks.`
        : `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run and no Injection rule was found on the zone. Add one on cf.llm.prompt.injection_score.`,
      expression: injectionExpression(INJECTION_BLOCK_STARTING_POINT),
      expressionAction: "block",
      expressionNote: `Starting point only — one tier looser than the zone's current 15/50 injection cutoffs. A paired log rule at le ${INJECTION_LOG_STARTING_POINT} widens visibility without enforcing.`,
    }),
  };
}

function unsafeTopicSpec(): MechanismSpec {
  return {
    mechanism: "unsafe_topic",
    fieldNeedle: "unsafe_topic",
    nameNeedles: ["unsafe categories", "unsafe"],
    build: (row, coverage) => ({
      recommendation: coverage.exists
        ? `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run even with '${coverage.ruleName}' on the zone — likely an S-code outside its blocked set (S1–S5, S8–S12) or caught only by the log-only rule (S1–S14). Extend the block rule's S-code coverage in the dashboard, or promote it to block the wider S1–S14 set.`
        : `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run and no Unsafe Categories rule was found on the zone. Add one on cf.llm.prompt.unsafe_topic_detected, then narrow to specific S-codes in the dashboard rule builder.`,
      expression: unsafeTopicExpression(),
      expressionAction: "block",
      expressionNote:
        "This is the boolean 'any unsafe topic' trigger — narrowing to specific S-codes (S1–S14) is a dashboard rule-builder step; this repo has no confirmed expression syntax for filtering the S-code array, so it isn't fabricated here.",
    }),
  };
}

// Existing custom-topic rules (Politics & Election today).
//
// The one thing we genuinely cannot know is the topic's KEY. The zone tells us
// a rule's *description* ("Monitor LLM Custom Topics - Politics and Election"),
// but `custom_topic_categories` is keyed by the topic LABEL as typed into the
// dashboard, and those are not the same string. So the expression carries an
// obvious placeholder rather than a guess dressed up as the real key — a
// plausible-but-wrong label compiles fine and then matches nothing, which is
// the exact silent failure this module exists to avoid.
const CUSTOM_TOPIC_PLACEHOLDER = "<your topic label>";
const CUSTOM_TOPIC_BLOCK_STARTING_POINT = 50;

function customTopicExistingSpec(nameNeedles: string[], ruleLabel: string): MechanismSpec {
  return {
    mechanism: "custom_topic_existing",
    fieldNeedle: "custom_topic_categories",
    nameNeedles,
    build: (row, coverage) => ({
      recommendation: coverage.exists
        ? `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run. '${coverage.ruleName}' already targets this topic but its threshold only catches strong matches — raise it in the dashboard (Security → WAF → Custom rules) so more borderline matches are blocked too. Lower score = stronger match, so a HIGHER threshold casts a wider net.`
        : `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run and no ${ruleLabel} rule was found on the zone. Create a Custom Topic for it, then a WAF rule on its score.`,
      expression: customTopicExpression(CUSTOM_TOPIC_PLACEHOLDER, CUSTOM_TOPIC_BLOCK_STARTING_POINT),
      expressionAction: "block",
      expressionNote: `Replace ${CUSTOM_TOPIC_PLACEHOLDER} with the topic's exact label from Security → AI Security → Custom Topics. The zone reports a rule's description, not the topic key it reads, so that string cannot be filled in from here. If the rule already exists, editing its threshold in place is simpler than pasting this.`,
    }),
  };
}

// Brand Tarnishing / Self-Criticism: the scan's single largest gap (53 attacks)
// and no rule covers it today, which makes this the flagship recommendation on
// the page — the one a customer is most likely to act on.
//
// Unlike the existing-topic case above, the topic key IS knowable here, because
// we are the ones proposing it: the operator creates the topic under the name
// this recommendation gives them, so the expression is exact rather than a
// placeholder. It stays inert until they do, which the note states plainly.
const SELF_CRITICISM_TOPIC = "Self-Criticism";

const CUSTOM_TOPIC_NEW_SPEC: MechanismSpec = {
  mechanism: "custom_topic_new",
  fieldNeedle: "custom_topic_categories",
  nameNeedles: ["self-criticism", "self criticism", "brand tarnish"],
  build: (row) => ({
    recommendation: `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run. None of the built-in detections covers it — this is not injection, not PII, and not an S1–S14 unsafe topic — so it needs a Custom Topic of its own. Create one named "${SELF_CRITICISM_TOPIC}" (Security → AI Security → Custom Topics), then add the rule below.`,
    expression: customTopicExpression(SELF_CRITICISM_TOPIC, CUSTOM_TOPIC_BLOCK_STARTING_POINT),
    expressionAction: "block",
    expressionNote: `Order matters: this expression matches nothing until a topic named exactly "${SELF_CRITICISM_TOPIC}" exists, and a rule that never matches looks identical to a rule that is working. Create the topic first, then paste this. Threshold ${CUSTOM_TOPIC_BLOCK_STARTING_POINT} is a starting point — lower score means a stronger match, so raise it to widen the net.`,
  }),
};

// Malware Generation / Remote Code Execution: not a WAF gap. cf.llm.* has no
// malicious-code field; the matching control lives in AI Gateway Guardrails.
const AI_GATEWAY_SPEC: MechanismSpec = {
  mechanism: "ai_gateway",
  fieldNeedle: null,
  nameNeedles: [],
  build: (row) => ({
    recommendation: `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run. This is not a WAF miss — cf.llm.* has no malicious-code field. Enable AI Gateway Guardrails → Malicious Code Detection → Block on the gateway you route through (the "guarded" gateway, if using AI Gateway route on this page).`,
    expression: null,
    expressionNote: "AI Gateway Guardrails setting, not a WAF rule — there is nothing to paste into Security → WAF for this one.",
  }),
};

const UNMAPPED_SPEC: MechanismSpec = {
  mechanism: "unmapped",
  fieldNeedle: null,
  nameNeedles: [],
  build: (row) => ({
    recommendation: `${row.reached} of ${row.scored} scored "${row.key}" attacks reached the model this run. This category isn't one of the built-in scan categories this module maps to a Cloudflare mechanism (it likely came from a custom CSV). Review the reached prompts manually against injection_score, pii_detected, and unsafe_topic_detected before writing a rule.`,
    expression: null,
    expressionNote: "No known cf.llm.* mapping for this category name — nothing is guessed.",
  }),
};

// The 15 categories RT_CORPUS produces (see redteam.ts RT_CORPUS). Political
// content is split across two category strings in the corpus (a "brand"-class
// "Political Endorsements" and a "safety"-class "Political") but both map to
// the same zone rule, since that's the only control the zone actually has for
// either.
const CATEGORY_MECHANISM: Record<string, MechanismSpec> = {
  "Jailbreak": injectionSpec(),
  "Prompt Injection": injectionSpec(),
  "Adversarial Suffix": injectionSpec(),
  "Violent Crimes / Weapons": unsafeTopicSpec(),
  "Bias": unsafeTopicSpec(),
  "CBRN": unsafeTopicSpec(),
  "Cybercrime": unsafeTopicSpec(),
  "Hate / Toxic / Abuse": unsafeTopicSpec(),
  "Sexual": unsafeTopicSpec(),
  "Non Violent Crimes": unsafeTopicSpec(),
  "Malware Generation": AI_GATEWAY_SPEC,
  "Remote Code Execution": AI_GATEWAY_SPEC,
  "Political Endorsements": customTopicExistingSpec(["politics", "election"], "Custom Topics - Politics and Election"),
  "Political": customTopicExistingSpec(["politics", "election"], "Custom Topics - Politics and Election"),
  "Brand Tarnishing / Self-Criticism": CUSTOM_TOPIC_NEW_SPEC,
};

function specFor(category: string): MechanismSpec {
  return CATEGORY_MECHANISM[category] ?? UNMAPPED_SPEC;
}

function coverageFor(spec: MechanismSpec, state: ZoneRulesState): GapCoverage {
  if (spec.mechanism === "ai_gateway") return NOT_APPLICABLE_COVERAGE;
  if (spec.mechanism === "unmapped") {
    return { exists: false, confidence: "none", note: "No known mechanism mapped — nothing to check against the zone rules." };
  }
  return coverageByField(state, spec.fieldNeedle, spec.nameNeedles);
}

// Main entry point. Pure — corpus + results + zone rule state in, gap list
// out. `results` uses the same Map<string, RtRunResult> shape useRedTeam
// exposes; byCategory (redteam.ts) already tallies reached/scored/total per
// category from it, so this module only adds the "what to do about it" layer.
export function computeGapControls(
  corpus: RedTeamAttack[],
  results: Map<string, RtRunResult>,
  zoneRules: ZoneRulesState,
): GapControl[] {
  const rows = byCategory(corpus, results).filter((row) => row.reached > 0);
  return rows.map((row) => {
    const spec = specFor(row.key);
    const coverage = coverageFor(spec, zoneRules);
    const built = spec.build(row, coverage);
    return {
      category: row.key,
      reached: row.reached,
      scored: row.scored,
      mechanism: spec.mechanism,
      coverage,
      ...built,
    };
  });
}

// Re-exported so GapControls.tsx can type its props without importing the
// hook module directly (keeps the component's import list to lib + the hook).
export type { UiZoneRule };
