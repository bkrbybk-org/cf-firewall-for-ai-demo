// The prompt-log query builder. Two reasons this is tested rather than
// inlined: it decides which rows an auditor can actually reach (the bug it
// fixes made everything past the newest 200 unreachable), and it is the only
// place in the app that interpolates a column name into SQL.
import { describe, expect, it } from "vitest";
import { buildPromptLogQuery, PROMPT_LOG_MAX_LIMIT } from "./promptlog";

describe("buildPromptLogQuery — filters", () => {
  it("builds no WHERE clause when nothing is filtered", () => {
    const q = buildPromptLogQuery({});
    expect(q.clause).toBe("");
    expect(q.binds).toEqual([]);
  });

  it("accepts only the two real routes", () => {
    expect(buildPromptLogQuery({ route: "gateway" }).clause).toBe("WHERE route = ?");
    expect(buildPromptLogQuery({ route: "gateway" }).binds).toEqual(["gateway"]);
    // Anything else is dropped rather than passed through to SQL.
    expect(buildPromptLogQuery({ route: "'; DROP TABLE prompt_log; --" }).clause).toBe("");
  });

  it("keeps only known outcomes and binds one placeholder each", () => {
    const q = buildPromptLogQuery({ outcomes: ["reply", "bogus", "error"] });
    expect(q.clause).toBe("WHERE outcome IN (?,?)");
    expect(q.binds).toEqual(["reply", "error"]);
  });

  it("combines time bounds with other filters", () => {
    const q = buildPromptLogQuery({ route: "direct", since: 1000, until: 2000 });
    expect(q.clause).toBe("WHERE route = ? AND ts >= ? AND ts <= ?");
    expect(q.binds).toEqual(["direct", 1000, 2000]);
  });
});

describe("buildPromptLogQuery — search", () => {
  it("searches all four text columns with one needle", () => {
    const q = buildPromptLogQuery({ q: "sim swap" });
    expect(q.clause).toContain("prompt LIKE ?");
    expect(q.clause).toContain("COALESCE(reply,'') LIKE ?");
    expect(q.clause).toContain("model LIKE ?");
    expect(q.clause).toContain("ray LIKE ?");
    expect(q.binds).toEqual(["%sim swap%", "%sim swap%", "%sim swap%", "%sim swap%"]);
  });

  it("escapes LIKE wildcards so a literal % or _ is not a wildcard", () => {
    // Without this, searching for "100%" matches every row.
    expect(buildPromptLogQuery({ q: "100%" }).binds[0]).toBe("%100\\%%");
    expect(buildPromptLogQuery({ q: "a_b" }).binds[0]).toBe("%a\\_b%");
    // The escape character itself is escaped first, or it would eat the next char.
    expect(buildPromptLogQuery({ q: "a\\b" }).binds[0]).toBe("%a\\\\b%");
  });

  it("ignores a blank or whitespace-only search", () => {
    expect(buildPromptLogQuery({ q: "   " }).clause).toBe("");
  });
});

describe("buildPromptLogQuery — sorting", () => {
  it("defaults to newest first", () => {
    expect(buildPromptLogQuery({}).orderBy).toBe("ORDER BY ts DESC");
  });

  it("honours a whitelisted column and direction", () => {
    expect(buildPromptLogQuery({ sort: "model", dir: "asc" }).orderBy).toBe("ORDER BY model ASC, ts DESC");
  });

  it("maps the tokens column to its computed expression", () => {
    expect(buildPromptLogQuery({ sort: "tokens", dir: "desc" }).orderBy).toBe(
      "ORDER BY (COALESCE(prompt_tokens,0) + COALESCE(completion_tokens,0)) DESC, ts DESC",
    );
  });

  it("maps the latency column to latency_ms", () => {
    expect(buildPromptLogQuery({ sort: "latency", dir: "desc" }).orderBy).toBe(
      "ORDER BY latency_ms DESC, ts DESC",
    );
  });

  it("falls back to ts for a column that is not on the whitelist", () => {
    // This value reaches ORDER BY, where a bind parameter is not possible — so
    // anything off the whitelist must be discarded, never interpolated.
    expect(buildPromptLogQuery({ sort: "prompt); DROP TABLE prompt_log; --" }).orderBy).toBe("ORDER BY ts DESC");
    expect(buildPromptLogQuery({ sort: "password" }).orderBy).toBe("ORDER BY ts DESC");
  });

  it("treats any direction that is not asc as desc", () => {
    expect(buildPromptLogQuery({ sort: "model", dir: "sideways" }).orderBy).toContain("DESC");
    expect(buildPromptLogQuery({ sort: "model", dir: "ASC" }).orderBy).toContain("ASC");
  });

  it("adds a stable secondary key on non-time sorts", () => {
    // Paging over an unstable sort can show the same row twice, or skip one.
    expect(buildPromptLogQuery({ sort: "outcome" }).orderBy).toMatch(/, ts DESC$/);
    // ts is already unique enough to page on, so it needs no tiebreak.
    expect(buildPromptLogQuery({ sort: "ts" }).orderBy).not.toMatch(/, ts DESC$/);
  });
});

describe("buildPromptLogQuery — paging", () => {
  it("clamps the page size to the server cap", () => {
    expect(buildPromptLogQuery({ limit: 10_000 }).limit).toBe(PROMPT_LOG_MAX_LIMIT);
    expect(buildPromptLogQuery({ limit: 0 }).limit).toBe(1);
    expect(buildPromptLogQuery({ limit: -5 }).limit).toBe(1);
  });

  it("never produces a negative or fractional offset", () => {
    expect(buildPromptLogQuery({ offset: -1 }).offset).toBe(0);
    expect(buildPromptLogQuery({ offset: 12.7 }).offset).toBe(12);
  });

  it("allows an offset past the old 200-row ceiling", () => {
    // The whole point of the change: row 2,500 must be reachable.
    expect(buildPromptLogQuery({ offset: 2500, limit: 25 }).offset).toBe(2500);
  });

  it("falls back to defaults for missing or non-finite values", () => {
    expect(buildPromptLogQuery({}).offset).toBe(0);
    expect(buildPromptLogQuery({ limit: Number.NaN }).limit).toBe(25);
    expect(buildPromptLogQuery({ offset: Number.NaN }).offset).toBe(0);
  });
});
