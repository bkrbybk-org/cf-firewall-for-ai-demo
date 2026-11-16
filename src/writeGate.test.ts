// The 2026-11-16 review's write rules, through the real handlers (D1 is a stand-in that records what ran):
//   S1/S2 — clearing the prompt log, deleting a saved run and saving one need a guardrail admin once
//           GUARDRAIL_ADMIN_EMAILS is set, exactly like the guardrail settings (#26); with it unset nothing changes.
//   S4    — a JSON write must say it is JSON, so a cross-site text/plain form post (no CORS preflight) is a 415.
// With the gate on, a request with no Access JWT is refused before D1 is touched: `ran` stays empty.
import { describe, expect, it } from "vitest";
import { handleChat, handlePromptLog, handleRedTeamRuns } from "./handlers";
import type { Env } from "./types";

function stand(gate: boolean): { env: Env; ran: string[] } {
  const ran: string[] = [];
  const DB = {
    prepare: (sql: string) => {
      const stmt = {
        bind: () => stmt,
        first: async () => null,
        all: async () => ({ results: [] }),
        run: async () => {
          ran.push(sql);
          return { success: true, meta: { changes: 1, last_row_id: 1 } };
        },
      };
      return stmt;
    },
    batch: async (stmts: unknown[]) => stmts.map(() => ({ success: true })),
  } as unknown as D1Database;
  const env = {
    DB,
    PROMPT_LOG_ENABLED: "true",
    ...(gate
      ? { GUARDRAIL_ADMIN_EMAILS: "admin@example.com", ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud" }
      : {}),
  } as unknown as Env;
  return { env, ran };
}

const req = (method: string, path: string, init: RequestInit = {}) =>
  new Request(`https://demo.example${path}`, { method, ...init });

describe("admin gate on the shared-evidence writes (S1/S2)", () => {
  it("DELETE /api/prompt-log: 403 without an admin login, and nothing is deleted", async () => {
    const { env, ran } = stand(true);
    const r = await handlePromptLog(req("DELETE", "/api/prompt-log"), new URL("https://demo.example/api/prompt-log"), env);
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toMatch(/^Only guardrail admins can clear the prompt log: /);
    expect(ran).toEqual([]);
  });

  it("DELETE /api/redteam-runs: 403 without an admin login, and nothing is deleted", async () => {
    const { env, ran } = stand(true);
    const u = new URL("https://demo.example/api/redteam-runs?id=3");
    const r = await handleRedTeamRuns(req("DELETE", "/api/redteam-runs?id=3"), u, env);
    expect(r.status).toBe(403);
    expect(ran).toEqual([]);
  });

  it("POST /api/redteam-runs: 403 without an admin login, so no save can prune real runs", async () => {
    const { env, ran } = stand(true);
    const u = new URL("https://demo.example/api/redteam-runs");
    const r = await handleRedTeamRuns(
      req("POST", "/api/redteam-runs", { headers: { "content-type": "application/json" }, body: "{}" }),
      u,
      env,
    );
    expect(r.status).toBe(403);
    expect(ran).toEqual([]);
  });

  it("gate off (GUARDRAIL_ADMIN_EMAILS unset): the deletes run as before", async () => {
    const { env, ran } = stand(false);
    const log = await handlePromptLog(req("DELETE", "/api/prompt-log"), new URL("https://demo.example/api/prompt-log"), env);
    expect(log.status).toBe(200);
    const run = await handleRedTeamRuns(
      req("DELETE", "/api/redteam-runs?id=3"),
      new URL("https://demo.example/api/redteam-runs?id=3"),
      env,
    );
    expect(run.status).toBe(200);
    expect(ran).toEqual([
      "DELETE FROM prompt_log",
      "DELETE FROM redteam_results WHERE run_id = ?",
      "DELETE FROM redteam_runs WHERE id = ?",
    ]);
  });
});

describe("JSON writes must say they are JSON (S4)", () => {
  const body = JSON.stringify({ prompt: "hello" });

  it("POST /api/chat as text/plain (a cross-site form post) is a 415, before any model or vendor runs", async () => {
    const { env } = stand(false);
    const r = await handleChat(req("POST", "/api/chat", { headers: { "content-type": "text/plain" }, body }), env);
    expect(r.status).toBe(415);
  });

  it("POST /api/chat with no content type is a 415 too", async () => {
    const { env } = stand(false);
    const r = await handleChat(new Request("https://demo.example/api/chat", { method: "POST", body: new Blob([body]) }), env);
    expect(r.status).toBe(415);
  });

  it("POST /api/redteam-runs as text/plain is a 415 (gate off, so the content type is what refuses it)", async () => {
    const { env, ran } = stand(false);
    const r = await handleRedTeamRuns(
      req("POST", "/api/redteam-runs", { headers: { "content-type": "text/plain" }, body: "{}" }),
      new URL("https://demo.example/api/redteam-runs"),
      env,
    );
    expect(r.status).toBe(415);
    expect(ran).toEqual([]);
  });

  it("application/json with a charset, and a +json type, are accepted (validation runs: 400, not 415)", async () => {
    const { env } = stand(false);
    for (const type of ["application/json; charset=utf-8", "application/vnd.demo+json"]) {
      const r = await handleRedTeamRuns(
        req("POST", "/api/redteam-runs", { headers: { "content-type": type }, body: "{}" }),
        new URL("https://demo.example/api/redteam-runs"),
        env,
      );
      expect(r.status).toBe(400);
    }
  });
});
