// Pure text helpers for /api/chat: what the client may send as history, and how
// the assistant's text is read out of each Workers AI response shape. Kept out of
// handlers.ts so they are unit-tested without loading the whole route table.

import { MAX_HISTORY_CHARS, MAX_HISTORY_TURNS } from "./config";
import type { ChatTurn } from "./types";

// Re-validate the client-supplied conversation history: only user/assistant
// turns, capped by turn count and total characters (newest turns win).
export function sanitizeHistory(raw: unknown): ChatTurn[] {
  if (!Array.isArray(raw)) return [];
  const turns: ChatTurn[] = [];
  for (const t of raw) {
    const turn = t as { role?: unknown; content?: unknown };
    if (
      (turn?.role === "user" || turn?.role === "assistant") &&
      typeof turn.content === "string" &&
      turn.content.trim() !== ""
    ) {
      turns.push({ role: turn.role, content: turn.content });
    }
  }
  const recent = turns.slice(-MAX_HISTORY_TURNS);
  const kept: ChatTurn[] = [];
  let total = 0;
  for (let i = recent.length - 1; i >= 0; i--) {
    total += recent[i].content.length;
    if (total > MAX_HISTORY_CHARS) break;
    kept.unshift(recent[i]);
  }
  return kept;
}

// Reasoning models wrap chain-of-thought in <think>…</think> before the real
// answer. Show the answer; if the model was cut off mid-think, show the
// partial reasoning rather than nothing. A model that thinks and then says
// nothing shows its reasoning without either tag — the closer used to leak
// into the bubble. Both tags match case-insensitively, like the opener always did.
export function stripThink(text: string): string {
  const close = /<\/think>/i.exec(text);
  if (close) {
    const after = text.slice(close.index + close[0].length).trim();
    if (after) return after;
    const thought = text.slice(0, close.index).replace(/^\s*<think>\s*/i, "").trim();
    if (thought) return thought;
  }
  return text.replace(/^\s*<think>\s*/i, "").trim() || text;
}

// Extract the assistant text across Workers AI response shapes:
// - most models return { response: "..." }
// - OpenAI-format models (gpt-oss) return { choices: [{ message: { content } }] }
// - reasoning models (Gemma 4, DeepSeek R1) can finish with content: null and
//   the usable text in message.reasoning
export function extractReply(obj: Record<string, unknown>, result: unknown): string {
  if (typeof obj.response === "string" && obj.response !== "") return stripThink(obj.response);
  const choices = obj.choices as
    | { message?: { content?: unknown; reasoning?: unknown } }[]
    | undefined;
  const msg = choices?.[0]?.message;
  if (typeof msg?.content === "string" && msg.content !== "") return stripThink(msg.content);
  if (typeof msg?.reasoning === "string" && msg.reasoning !== "") return msg.reasoning.trim();
  if (obj.response && typeof obj.response === "object") {
    const out = (obj.response as { output_text?: unknown }).output_text;
    // Same `!== ""` guard as the branches above: an empty field is not a reply.
    if (typeof out === "string" && out !== "") return out;
  }
  return typeof result === "string" ? result : JSON.stringify(result);
}
