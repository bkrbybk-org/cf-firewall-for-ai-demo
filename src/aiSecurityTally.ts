// Which WAF events were AI Security's own — for evidence that claims "AI Security
// blocked N" (Compliance, MEASURE 2.7). Open bug #22: that chip summed every block
// in the zone (Sensitive Paths, geography, crawler and CVE rules); over 24 h only
// 31% were AI Security rules. Pure, so the rule that a non-LLM block never counts
// is unit-tested.
//
// Input is firewallEventsAdaptiveGroups — grouped, so NOT capped at the 500 rows
// the rest of /api/analytics reads. But it is an Adaptive dataset: Cloudflare
// samples it under load and returns ESTIMATES (developers.cloudflare.com/analytics/
// graphql-api/sampling). `avg.sampleInterval` > 1 on any group means the totals
// are estimates, and the result says so — never presented as an exact count.
//
// Classification, strongest evidence first:
//   - "expression": the zone's live custom rules are readable and this event's rule
//     (by id, else by description) has an expression using cf.llm.* — a fact. Since
//     2026-10-08 that includes rules INSIDE the custom rulesets an execute rule runs
//     (src/cloudflare.ts flattenCustomRules): this zone's AI rules all live there.
//   - "category": a deployed MANAGED rule Cloudflare tags firewall-for-ai (its expression
//     is hidden) — also a fact. Before this, "Detects PII categories in the prompt" and
//     its siblings were not counted at all: their names never say "LLM".
//   - "name": otherwise, the rule's description matches \bLLM\b — a heuristic. It
//     also covers account-level rules ("[Account-Level] Detect LLM Injection"),
//     which the zone's ruleset never lists. The method used is returned, so the
//     evidence can say which kind of claim it is.

export interface RuleGroup {
  action: string;
  description: string;
  ruleId: string;
  count: number;
  sampleInterval: number; // avg over the group; 1 = every event counted
}

export interface LiveRuleRef {
  id: string;
  name: string;
  llm: boolean; // expression references cf.llm.* — or a managed rule with the firewall-for-ai category
  // What the classification rests on: the rule's readable expression (custom rules, nested
  // ones included), or Cloudflare's category on a managed rule whose expression is hidden.
  via?: "expression" | "category";
}

export interface AiSecurityTally {
  blocked: number; // AI Security rule events whose action blocked the request
  logged: number; // …that matched but only logged (rule in Log mode)
  other: number; // …any other action (challenge, skip, …)
  rules: { name: string; action: string; count: number; via: "expression" | "category" | "name" }[];
  // How AI Security rules were told apart. "expression": every counted event matched one
  // of the zone's readable rules (a cf.llm.* expression, or a managed rule's firewall-for-ai
  // category). "mixed": readable rules covered some, the name heuristic the rest
  // (account-level rules are never in the zone's rulesets).
  classifiedBy: "expression" | "name" | "mixed";
  sampled: boolean; // true → every count above is Cloudflare's estimate, not exact
  // The group query hit its limit, so the smallest groups were not returned and every
  // count is a floor ("at least"). Ordered by count, so what is missing is the tail.
  capped: boolean;
  zoneBlocked: number; // every block in the zone, for context — never presented as AI Security's
}

const LLM_NAME = /\bllm\b/i;
const isBlock = (a: string) => /block|drop/i.test(a);
const isLog = (a: string) => /log/i.test(a) && !isBlock(a);

export function tallyAiSecurity(groups: RuleGroup[], liveRules: LiveRuleRef[] | null, capped = false): AiSecurityTally {
  const byId = new Map((liveRules ?? []).map((r) => [r.id, r]));
  const byName = new Map((liveRules ?? []).map((r) => [r.name.trim().toLowerCase(), r]));
  const t: AiSecurityTally = {
    blocked: 0,
    logged: 0,
    other: 0,
    rules: [],
    classifiedBy: "name",
    sampled: false,
    capped,
    zoneBlocked: 0,
  };
  let viaExpression = 0;
  let viaName = 0;
  const rows = new Map<string, AiSecurityTally["rules"][number]>();

  for (const g of groups) {
    if (!Number.isFinite(g.count) || g.count <= 0) continue;
    if (isBlock(g.action)) t.zoneBlocked += g.count;

    const live = byId.get(g.ruleId) ?? byName.get(g.description.trim().toLowerCase());
    // A live rule decides by its expression — including "not AI Security", even if its
    // name happens to say LLM. Only a rule the zone ruleset does not list falls back
    // to the name.
    let via: "expression" | "category" | "name" | null = null;
    if (live) via = live.llm ? (live.via ?? "expression") : null;
    else if (LLM_NAME.test(g.description)) via = "name";
    if (!via) continue;
    // Only the groups counted decide whether the counts are estimates: the zone's
    // heavily-sampled geography and path rules say nothing about AI Security's numbers.
    if (g.sampleInterval > 1) t.sampled = true;

    if (via !== "name") viaExpression += g.count;
    else viaName += g.count;
    if (isBlock(g.action)) t.blocked += g.count;
    else if (isLog(g.action)) t.logged += g.count;
    else t.other += g.count;

    const name = g.description || g.ruleId || "(unnamed rule)";
    const key = `${name}|${g.action}`;
    const row = rows.get(key) ?? { name, action: g.action, count: 0, via };
    row.count += g.count;
    rows.set(key, row);
  }

  t.rules = [...rows.values()].sort((a, b) => b.count - a.count);
  t.classifiedBy = viaExpression > 0 && viaName > 0 ? "mixed" : viaExpression > 0 ? "expression" : "name";
  return t;
}
