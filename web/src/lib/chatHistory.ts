// Pure helpers behind useChat: which past turns are resent as context, and the
// token/cost estimates shown when a model reports no usage. Kept out of the hook
// so they are unit-tested without React.

import type { Msg } from "../hooks/useChat";
import type { ChatTurn, Model, Usage } from "./types";

// Multi-turn context = completed user→assistant pairs only. A blocked user
// prompt has no assistant reply and is deliberately dropped — resending an
// attack prompt inside history would get every later turn blocked too.
export function buildHistory(msgs: Msg[]): ChatTurn[] {
  const out: ChatTurn[] = [];
  for (let i = 0; i < msgs.length - 1; i++) {
    const q = msgs[i];
    const a = msgs[i + 1];
    if (q.kind === "user" && a.kind === "assistant") {
      out.push({ role: "user", content: q.text });
      out.push({ role: "assistant", content: a.text });
    }
  }
  return out;
}

export function estimateUsage(systemPrompt: string, history: ChatTurn[], prompt: string, reply: string): Usage {
  const historyChars = history.reduce((n, t) => n + t.content.length, 0);
  const prompt_tokens = Math.ceil((systemPrompt.length + historyChars + prompt.length) / 4);
  const completion_tokens = Math.ceil(reply.length / 4);
  return { prompt_tokens, completion_tokens, total_tokens: prompt_tokens + completion_tokens, estimated: true };
}

export function estimateCost(models: Model[], modelId: string, usage: Usage): number | null {
  const m = models.find((x) => x.id === modelId);
  if (!m || m.priceIn == null || m.priceOut == null) return null;
  return (usage.prompt_tokens / 1e6) * m.priceIn + (usage.completion_tokens / 1e6) * m.priceOut;
}
