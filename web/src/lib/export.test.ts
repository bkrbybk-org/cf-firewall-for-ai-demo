// The session export and design J: a withheld reply is its own outcome, with the reply
// check's verdicts, and no reply text — the browser never received one.
import { describe, expect, it } from "vitest";
import { buildSessionExport, toMarkdown } from "./export";
import type { Msg } from "../hooks/useChat";
import type { GuardrailPipelineResult } from "./types";

const reply: GuardrailPipelineResult = {
  direction: "reply",
  mode: "sequential",
  guardrailOnly: false,
  results: [{ provider: "prisma-airs", outcome: "block", latencyMs: 80, detected: ["dlp"] }],
  notRun: [],
  stoppedBy: "prisma-airs",
  latencyMs: 80,
};

describe("session export — a withheld reply", () => {
  it("exports the turn as withheld, with its usage and the reply check — and is never dropped", async () => {
    const msgs: Msg[] = [
      { id: 1, kind: "user", text: "What SSN is on file?", ts: "t", tsMs: 0 } as Msg,
      {
        id: 2,
        kind: "replyWithheld",
        ts: "t",
        tsMs: 0,
        replyPipeline: reply,
        model: "@cf/m",
        usage: { prompt_tokens: 3, completion_tokens: 9, total_tokens: 12, estimated: false },
        cost: 0.000001,
      },
    ];
    const exp = await buildSessionExport(msgs, "");
    expect(exp.turns).toHaveLength(1);
    expect(exp.turns[0]).toMatchObject({ outcome: "withheld", model: "@cf/m", replyGuardrails: { stoppedBy: "prisma-airs" } });
    expect(exp.turns[0].reply).toBeUndefined();
    const md = toMarkdown(exp);
    expect(md).toContain("**Reply withheld** (@cf/m, 12 tokens");
    expect(md).toContain("reply check (sequential, 80 ms total):");
    expect(md).toContain("- prisma-airs: block (80 ms) — withheld the reply");
  });
});
