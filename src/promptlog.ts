// Query building for GET /api/prompt-log.
//
// Split out of handlers.ts so it can be tested directly: this is the code that
// decides which rows a reviewer can actually reach, and it interpolates a
// column name into SQL (the only place in the app that does), so it needs to
// be provably closed to anything not on the whitelist.

export const PROMPT_LOG_MAX_LIMIT = 200;
export const PROMPT_LOG_DEFAULT_LIMIT = 25;

// Sort keys the client may ask for → the SQL that orders by them. A map, not
// string interpolation of user input: `sort` reaches ORDER BY, where binding a
// parameter is not possible, so the value must come from this table or not at
// all.
export const PROMPT_LOG_SORTS = {
  ts: "ts",
  outcome: "outcome",
  route: "route",
  model: "model",
  tokens: "(COALESCE(prompt_tokens,0) + COALESCE(completion_tokens,0))",
  redactions: "redactions",
  latency: "latency_ms",
} as const;

export type PromptLogSort = keyof typeof PROMPT_LOG_SORTS;

export interface PromptLogQuery {
  clause: string; // "WHERE …" or "" — shared by the row query and its COUNT
  binds: unknown[]; // binds for `clause` only
  orderBy: string; // "ORDER BY … [, ts DESC]"
  limit: number;
  offset: number;
}

export interface PromptLogParams {
  route?: string | null;
  outcomes?: string[];
  since?: number | null;
  until?: number | null;
  q?: string | null;
  sort?: string | null;
  dir?: string | null;
  limit?: number | null;
  offset?: number | null;
}

function clampInt(v: number | null | undefined, min: number, max: number, fallback: number): number {
  if (v == null || !Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(v)));
}

export function buildPromptLogQuery(p: PromptLogParams): PromptLogQuery {
  const where: string[] = [];
  const binds: unknown[] = [];

  if (p.route === "direct" || p.route === "gateway") {
    where.push("route = ?");
    binds.push(p.route);
  }
  const outcomes = (p.outcomes ?? []).filter(
    (o): o is "reply" | "guardrails" | "external" | "skipped" | "error" =>
      o === "reply" || o === "guardrails" || o === "external" || o === "skipped" || o === "error",
  );
  if (outcomes.length) {
    where.push(`outcome IN (${outcomes.map(() => "?").join(",")})`);
    binds.push(...outcomes);
  }
  if (p.since != null) {
    where.push("ts >= ?");
    binds.push(p.since);
  }
  if (p.until != null) {
    where.push("ts <= ?");
    binds.push(p.until);
  }

  // Text search moved server-side along with paging. It used to filter the
  // fetched page in the browser, which was fine while every row was in hand —
  // but once the table is paged, filtering one page silently reads as filtering
  // the table. LIKE escaping: \ is the ESCAPE char, so it goes first.
  const q = (p.q ?? "").trim();
  if (q) {
    // % and _ are LIKE wildcards, so a literal one typed by the user must be
    // escaped or the search quietly matches more than it was asked for. The
    // backslash is escaped first, since it is the ESCAPE character itself.
    const needle = "%" + q.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
    const like = "LIKE ? ESCAPE '\\'";
    where.push(
      `(prompt ${like} OR COALESCE(reply,'') ${like} OR model ${like} OR ray ${like})`,
    );
    binds.push(needle, needle, needle, needle);
  }

  const sortKey: PromptLogSort = (p.sort && p.sort in PROMPT_LOG_SORTS ? p.sort : "ts") as PromptLogSort;
  const dir = String(p.dir).toLowerCase() === "asc" ? "ASC" : "DESC";
  // Secondary key keeps equal outcomes/routes in a stable, readable order —
  // and makes paging deterministic, which an unstable sort would not be.
  const orderBy =
    sortKey === "ts"
      ? `ORDER BY ts ${dir}`
      : `ORDER BY ${PROMPT_LOG_SORTS[sortKey]} ${dir}, ts DESC`;

  return {
    clause: where.length ? `WHERE ${where.join(" AND ")}` : "",
    binds,
    orderBy,
    limit: clampInt(p.limit, 1, PROMPT_LOG_MAX_LIMIT, PROMPT_LOG_DEFAULT_LIMIT),
    offset: clampInt(p.offset, 0, Number.MAX_SAFE_INTEGER, 0),
  };
}

// ── Retention ──────────────────────────────────────────────────────────────
// The log keeps the last PROMPT_LOG_MAX_AGE_DAYS days, and at most the newest
// PROMPT_LOG_MAX_ROWS rows — whichever removes more. Pruned at write time, in the
// same D1 batch as the insert (logPrompt in handlers.ts): there is no scheduled
// job to forget, and a log that is not being written to is not growing. The
// consequence, stated wherever counts are shown: a row older than the limits may
// survive until the next write, so "kept" is a ceiling, not a promise of deletion
// at the minute.
export const PROMPT_LOG_MAX_AGE_DAYS = 90;
export const PROMPT_LOG_MAX_ROWS = 1000;

// The two prune statements. Rows go by age first, then the count: the newest N by
// ts, with ray as the tiebreak so two rows in the same millisecond can never both
// fall on the boundary and leave N + 1.
export function promptLogPruneStatements(now: number): { sql: string; binds: number[] }[] {
  return [
    { sql: "DELETE FROM prompt_log WHERE ts < ?", binds: [now - PROMPT_LOG_MAX_AGE_DAYS * 86_400_000] },
    {
      sql: "DELETE FROM prompt_log WHERE ray NOT IN (SELECT ray FROM prompt_log ORDER BY ts DESC, ray DESC LIMIT ?)",
      binds: [PROMPT_LOG_MAX_ROWS],
    },
  ];
}

export interface PromptLogRetention {
  maxAgeDays: number;
  maxRows: number;
  rows: number; // rows held now, across all time
  oldestTs: number | null; // oldest row held now
  // True when the asked-for window reaches back past what the log is guaranteed to
  // keep: further than the age limit (or all time), or before the oldest row while
  // the row cap is full. Every count in that window is then a FLOOR ("at least").
  // A property of the window against the policy, not a guess about whether rows
  // were actually deleted — this app keeps no record of that, and "at least" is
  // still true when nothing was.
  windowPartial: boolean;
}

// `since` null = all time. Pure, so the honesty rule is unit-tested.
export function promptLogRetention(
  since: number | null,
  rows: number,
  oldestTs: number | null,
  now: number,
): PromptLogRetention {
  const reachesPastAge = since == null || since < now - PROMPT_LOG_MAX_AGE_DAYS * 86_400_000;
  const capFull = rows >= PROMPT_LOG_MAX_ROWS;
  const beforeOldest = oldestTs != null && (since == null || since < oldestTs);
  const windowPartial = reachesPastAge || (capFull && beforeOldest);
  return { maxAgeDays: PROMPT_LOG_MAX_AGE_DAYS, maxRows: PROMPT_LOG_MAX_ROWS, rows, oldestTs, windowPartial };
}
