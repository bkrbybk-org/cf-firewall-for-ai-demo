// What a turn resends as multi-turn context, and the token/cost estimates shown
// when a model reports no usage. The history rule is a safety one: a blocked
// attack prompt must never be replayed, or every later turn would be blocked too.
import { describe, expect, it } from "vitest";
import { buildHistory, estimateCost, estimateUsage } from "./chatHistory";
import type { Msg } from "../hooks/useChat";
import type { Model, Usage } from "./types";

let nextId = 1;
const base = () => ({ id: nextId++, ts: "00:00:00", tsMs: 0 });
const user = (text: string): Msg => ({ ...base(), kind: "user", text });
const assistant = (text: string): Msg => ({ ...base(), kind: "assistant", text, meta: {} });
const blocked = (): Msg => ({ ...base(), kind: "blocked", raw: "{}", contentType: "application/json" });
const error = (text = "boom"): Msg => ({ ...base(), kind: "error", text });
// Minimal fixtures for kinds whose payloads buildHistory never reads.
const external = (): Msg => ({ ...base(), kind: "external", pipeline: {} } as unknown as Msg);
const guardrails = (): Msg => ({ ...base(), kind: "guardrails" }) as unknown as Msg;
const skipped = (): Msg => ({ ...base(), kind: "guardrailOnly" }) as unknown as Msg;

describe("buildHistory", () => {
  it("is empty for no messages and for a single message", () => {
    expect(buildHistory([])).toEqual([]);
    expect(buildHistory([user("hi")])).toEqual([]);
    expect(buildHistory([assistant("hi")])).toEqual([]);
  });

  it("turns one user→assistant pair into two turns", () => {
    expect(buildHistory([user("q"), assistant("a")])).toEqual([
      { role: "user", content: "q" },
      { role: "assistant", content: "a" },
    ]);
  });

  it("preserves order across several pairs", () => {
    const out = buildHistory([user("q1"), assistant("a1"), user("q2"), assistant("a2")]);
    expect(out.map((t) => t.content)).toEqual(["q1", "a1", "q2", "a2"]);
    expect(out.map((t) => t.role)).toEqual(["user", "assistant", "user", "assistant"]);
  });

  it("drops a user prompt that the edge WAF blocked", () => {
    expect(buildHistory([user("attack"), blocked()])).toEqual([]);
  });

  it("drops a user prompt followed by an external guardrail stop", () => {
    expect(buildHistory([user("attack"), external()])).toEqual([]);
  });

  it("drops a user prompt followed by an error", () => {
    expect(buildHistory([user("q"), error()])).toEqual([]);
  });

  it("drops a user prompt followed by a guardrail-only (skipped) result", () => {
    expect(buildHistory([user("q"), skipped()])).toEqual([]);
  });

  it("drops a user prompt followed by an AI Gateway guardrails block", () => {
    expect(buildHistory([user("attack"), guardrails()])).toEqual([]);
  });

  it("keeps good pairs on either side of a dropped one", () => {
    const out = buildHistory([
      user("q1"),
      assistant("a1"),
      user("attack"),
      blocked(),
      user("q2"),
      assistant("a2"),
    ]);
    expect(out.map((t) => t.content)).toEqual(["q1", "a1", "q2", "a2"]);
    expect(out.some((t) => t.content === "attack")).toBe(false);
  });

  it("does not pair a user turn with an assistant reply that is not adjacent", () => {
    expect(buildHistory([user("q"), blocked(), assistant("stray")])).toEqual([]);
  });

  it("ignores an assistant message with no preceding user message", () => {
    expect(buildHistory([assistant("stray"), user("q"), assistant("a")])).toEqual([
      { role: "user", content: "q" },
      { role: "assistant", content: "a" },
    ]);
  });

  it("drops the earlier of two consecutive user prompts", () => {
    const out = buildHistory([user("first"), user("second"), assistant("a")]);
    expect(out).toEqual([
      { role: "user", content: "second" },
      { role: "assistant", content: "a" },
    ]);
  });

  it("emits only role and content, never message metadata", () => {
    const out = buildHistory([user("q"), assistant("a")]);
    for (const t of out) expect(Object.keys(t).sort()).toEqual(["content", "role"]);
  });
});

describe("estimateUsage", () => {
  it("counts chars / 4 rounded UP, per side", () => {
    // 9 chars -> ceil(2.25) = 3; 5 chars -> ceil(1.25) = 2.
    const u = estimateUsage("", [], "123456789", "12345");
    expect(u.prompt_tokens).toBe(3);
    expect(u.completion_tokens).toBe(2);
  });

  it("does not round an exact multiple of 4", () => {
    const u = estimateUsage("", [], "12345678", "1234");
    expect(u.prompt_tokens).toBe(2);
    expect(u.completion_tokens).toBe(1);
  });

  it("rounds a single character up to one token", () => {
    expect(estimateUsage("", [], "a", "b")).toMatchObject({ prompt_tokens: 1, completion_tokens: 1 });
  });

  it("is zero for no text at all", () => {
    expect(estimateUsage("", [], "", "")).toEqual({
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
      estimated: true,
    });
  });

  it("sums system prompt, history and prompt BEFORE dividing, not per part", () => {
    // 3 + (2 + 3) + 1 = 9 chars -> ceil(2.25) = 3. Rounding each part first would give 1+1+1+1 = 4.
    const history = [
      { role: "user" as const, content: "ab" },
      { role: "assistant" as const, content: "cde" },
    ];
    const u = estimateUsage("sys", history, "p", "");
    expect(u.prompt_tokens).toBe(3);
  });

  it("does not count the reply in prompt_tokens", () => {
    const u = estimateUsage("", [], "1234", "x".repeat(400));
    expect(u.prompt_tokens).toBe(1);
    expect(u.completion_tokens).toBe(100);
  });

  it("totals prompt + completion and flags the numbers as estimated", () => {
    // prompt: 8 + 4 + 12 = 24 chars -> 6; reply: 10 chars -> 3.
    const history = [{ role: "user" as const, content: "abcd" }];
    const u = estimateUsage("12345678", history, "123456789012", "1234567890");
    expect(u).toEqual({ prompt_tokens: 6, completion_tokens: 3, total_tokens: 9, estimated: true });
  });

  it("total is the sum of the rounded sides, not the rounded sum of chars", () => {
    // prompt 1 char -> 1, reply 1 char -> 1: total 2, whereas ceil(2 / 4) would be 1.
    expect(estimateUsage("", [], "a", "b").total_tokens).toBe(2);
  });
});

describe("estimateCost", () => {
  const usage = (prompt_tokens: number, completion_tokens: number): Usage => ({
    prompt_tokens,
    completion_tokens,
    total_tokens: prompt_tokens + completion_tokens,
    estimated: true,
  });
  const models: Model[] = [
    { id: "paid", label: "Paid", priceIn: 2, priceOut: 10 },
    { id: "free", label: "Free", priceIn: 0, priceOut: 0 },
    { id: "free-in", label: "Free in", priceIn: 0, priceOut: 4 },
    { id: "no-prices", label: "No prices" },
    { id: "no-out", label: "No out", priceIn: 1 },
    { id: "no-in", label: "No in", priceOut: 1 },
  ];

  it("is null for an unknown model", () => {
    expect(estimateCost(models, "nope", usage(1000, 1000))).toBeNull();
    expect(estimateCost([], "paid", usage(1000, 1000))).toBeNull();
  });

  it("is null when either price is missing", () => {
    expect(estimateCost(models, "no-prices", usage(1000, 1000))).toBeNull();
    expect(estimateCost(models, "no-out", usage(1000, 1000))).toBeNull();
    expect(estimateCost(models, "no-in", usage(1000, 1000))).toBeNull();
  });

  it("is null when a price is explicitly null (a JSON payload can carry one)", () => {
    const m = [{ id: "n", label: "N", priceIn: null, priceOut: 1 }] as unknown as Model[];
    expect(estimateCost(m, "n", usage(1, 1))).toBeNull();
  });

  it("returns 0, not null, when both prices are 0", () => {
    // 0 is a real price ("free"), unlike an unknown one; null would hide a $0 cost.
    expect(estimateCost(models, "free", usage(1_000_000, 1_000_000))).toBe(0);
  });

  it("charges only the other side when one price is 0", () => {
    // 5M in at $0 + 500k out at $4/M = $2.
    expect(estimateCost(models, "free-in", usage(5_000_000, 500_000))).toBeCloseTo(2, 10);
  });

  it("is tokens / 1e6 x price, per side", () => {
    // 500k in at $2/M = $1.00; 250k out at $10/M = $2.50 -> $3.50.
    expect(estimateCost(models, "paid", usage(500_000, 250_000))).toBeCloseTo(3.5, 10);
  });

  it("scales down to small token counts", () => {
    // 1200 in at $2/M = 0.0024; 300 out at $10/M = 0.003 -> 0.0054.
    expect(estimateCost(models, "paid", usage(1200, 300))).toBeCloseTo(0.0054, 10);
  });

  it("is 0 for zero tokens on a priced model", () => {
    expect(estimateCost(models, "paid", usage(0, 0))).toBe(0);
  });

  it("picks the model by id, not by position", () => {
    expect(estimateCost(models, "free-in", usage(1_000_000, 1_000_000))).toBeCloseTo(4, 10);
    expect(estimateCost(models, "paid", usage(1_000_000, 1_000_000))).toBeCloseTo(12, 10);
  });
});
