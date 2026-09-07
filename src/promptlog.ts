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
    (o): o is "reply" | "guardrails" | "error" => o === "reply" || o === "guardrails" || o === "error",
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
