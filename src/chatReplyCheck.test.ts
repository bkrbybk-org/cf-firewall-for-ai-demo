// Design J end to end through handleChat: the reply check runs after the model, a
// block withholds every word of the reply, and the switch changes nothing when it is
// off. Local workerd cannot reach the vendors that check replies (CLAUDE.md), so the
// vendor, the model and D1 are stand-ins here — the handler code between them is real.
import { afterEach, describe, expect, it, vi } from "vitest";
import { encryptSecret } from "./externalGuardrails";
import { handleChat } from "./handlers";
import type { Env } from "./types";

const SECRET = btoa(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i + 1)));
const REPLY = "The SSN on file is 078-05-1120.";

async function env(opts: { scanReplies: boolean; failMode?: "block" | "allow" }): Promise<{ env: Env; logged: unknown[][] }> {
  const logged: unknown[][] = [];
  const row = {
    provider: "prisma-airs",
    enabled: 1,
    region: "us",
    profile_name: "demo-profile",
    fail_mode: opts.failMode ?? "block",
    api_key_enc: await encryptSecret("the-real-key", SECRET, "prisma-airs"),
    api_key_last4: "-key",
    updated_at: 1,
  };
  const pipeline = { mode: "sequential", guardrail_only: 0, provider_order: "", scan_replies: opts.scanReplies ? 1 : 0 };
  const DB = {
    prepare: (sql: string) => {
      const stmt = {
        bind: (...args: unknown[]) => {
          if (/INTO prompt_log/i.test(sql)) logged.push(args);
          return stmt;
        },
        first: async () => (sql.includes("guardrail_pipeline") ? pipeline : null),
        all: async () => ({ results: sql.includes("external_guardrails") ? [row] : [] }),
        run: async () => ({ success: true }),
      };
      return stmt;
    },
    batch: async (stmts: unknown[]) => stmts.map(() => ({ success: true })),
  } as unknown as D1Database;
  const AI = { run: vi.fn(async () => ({ response: REPLY })) } as unknown as Ai;
  return {
    env: { DB, AI, GUARDRAIL_SECRET_KEY: SECRET, PROMPT_LOG_ENABLED: "true" } as unknown as Env,
    logged,
  };
}

// The vendor: allows every prompt check, and answers a reply check with `replyVerdict`.
function vendor(replyVerdict: "allow" | "block" | "down") {
  const bodies: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      // The AI Gateway REST call (the gateway route): an OpenAI-shaped reply.
      if (url.includes("/ai/v1/chat/completions")) {
        return Response.json({ model: "@cf/m", choices: [{ message: { role: "assistant", content: REPLY } }], usage: { prompt_tokens: 3, completion_tokens: 9 } });
      }
      const body = JSON.parse(init!.body as string);
      bodies.push(body);
      const isReply = body.contents?.[0]?.response != null;
      if (!isReply) return Response.json({ action: "allow", category: "benign" });
      if (replyVerdict === "down") throw new Error("connection refused");
      return Response.json({ action: replyVerdict, category: replyVerdict === "block" ? "malicious" : "benign", response_detected: { dlp: replyVerdict === "block" } });
    }),
  );
  return bodies;
}

const chat = (e: Env, body: Record<string, unknown> = {}) =>
  handleChat(
    new Request("https://x/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-ray": "abc123-SIN" },
      body: JSON.stringify({ prompt: "What SSN is on file?", ...body }),
    }),
    e,
  );

afterEach(() => vi.unstubAllGlobals());

describe("handleChat — reply check (design J)", () => {
  it("a blocked reply is withheld: no reply text anywhere, usage still reported, logged as external_reply", async () => {
    const { env: e, logged } = await env({ scanReplies: true });
    const bodies = vendor("block");
    const res = await chat(e, { stream: true });
    expect(res.headers.get("content-type")).toContain("application/json"); // never streamed
    const text = await res.text();
    expect(text).not.toContain("078-05-1120");
    const j = JSON.parse(text);
    expect(j).toMatchObject({ externalReplyBlocked: true, notStreamed: "reply-scan", replyGuardrails: { direction: "reply", stoppedBy: "prisma-airs" } });
    expect(j.reply).toBeUndefined();
    expect(j.usage.completion_tokens).toBeGreaterThan(0); // the model ran; its cost was spent
    expect(decodeURIComponent(res.headers.get("x-external-guardrails-reply")!)).not.toContain("078-05-1120");
    // The vendor saw the reply beside its prompt — and the prompt check came first, without it.
    expect(bodies.map((b) => (b.contents as { response?: string }[])[0].response ?? null)).toEqual([null, REPLY]);
    // Logged as its own outcome, with a null reply.
    const row = logged[0];
    expect(row).toContain("external_reply");
    expect(row.some((v) => typeof v === "string" && v.includes("078-05-1120"))).toBe(false);
  });

  it("an allowed reply is returned with the reply check's verdicts", async () => {
    const { env: e } = await env({ scanReplies: true });
    vendor("allow");
    const j = (await (await chat(e)).json()) as Record<string, unknown>;
    expect(j.reply).toBe(REPLY);
    expect(j.replyGuardrails).toMatchObject({ direction: "reply", stoppedBy: null });
  });

  it("an unreachable vendor follows the fail mode: closed withholds, open returns the reply marked failedOpen", async () => {
    const closed = await env({ scanReplies: true, failMode: "block" });
    vendor("down");
    expect(await (await chat(closed.env)).json()).toMatchObject({ externalReplyBlocked: true });
    const open = await env({ scanReplies: true, failMode: "allow" });
    vendor("down");
    const j = (await (await chat(open.env)).json()) as { reply: string; replyGuardrails: { results: { failedOpen?: boolean }[] } };
    expect(j.reply).toBe(REPLY);
    expect(j.replyGuardrails.results[0].failedOpen).toBe(true);
  });

  it("the gateway route withholds a blocked reply the same way", async () => {
    const { env: e } = await env({ scanReplies: true });
    Object.assign(e, { CF_AIG_TOKEN: "t", CF_ACCOUNT_ID: "acct" });
    vendor("block");
    const res = await chat(e, { gateway: true, gatewayId: "plain-gw", stream: true });
    const text = await res.text();
    expect(text).not.toContain("078-05-1120");
    expect(JSON.parse(text)).toMatchObject({ externalReplyBlocked: true, notStreamed: "reply-scan", gateway: { gatewayId: "plain-gw" } });
  });

  // The Analytics page's External guardrails tab reads these lines back from Workers Logs.
  it("writes one verdict log line per check — names only, no prompt or reply — and none when excluded", async () => {
    const { env: e } = await env({ scanReplies: true });
    vendor("block");
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const req = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
        handleChat(
          new Request("https://x/api/chat", {
            method: "POST",
            headers: { "content-type": "application/json", "cf-ray": "abc123-SIN", ...headers },
            body: JSON.stringify({ prompt: "What SSN is on file?", ...body }),
          }),
          e,
        );
      await req({}, { "x-demo-source": "redteam" });
      const lines = spy.mock.calls.map((c) => c[0]).filter((l) => (l as { event?: string })?.event === "guardrail_verdict");
      expect(lines).toEqual([
        expect.objectContaining({ dir: "prompt", provider: "prisma-airs", outcome: "allow", src: "redteam", ray: "abc123" }),
        expect.objectContaining({ dir: "reply", provider: "prisma-airs", outcome: "block", decided: true, detected: "dlp" }),
      ]);
      const text = JSON.stringify(lines);
      expect(text).not.toContain("078-05-1120");
      expect(text).not.toContain("What SSN");

      spy.mockClear();
      await req({ excludeFromLog: true });
      expect(spy.mock.calls.some((c) => (c[0] as { event?: string })?.event === "guardrail_verdict")).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });

  it("switch off: no reply check, no second vendor call, and nothing in the reply about one", async () => {
    const { env: e } = await env({ scanReplies: false });
    const bodies = vendor("block");
    const j = (await (await chat(e)).json()) as Record<string, unknown>;
    expect(j.reply).toBe(REPLY);
    expect(j.replyGuardrails).toBeUndefined();
    expect(bodies).toHaveLength(1);
  });
});
