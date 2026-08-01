// Minimal SSE reader for the Worker side.
//
// The client already parses these streams (web/src/lib/api.ts) to render
// tokens; the Worker needs the same text for a different reason — a streamed
// reply is never seen server-side, so the prompt log stored `reply = NULL` for
// what is actually the default path. This assembles the reply as it passes
// through, without buffering or delaying it.
//
// Chunk shapes, all three of which appear in this app:
//   {"response":"…"}                          Workers AI binding
//   {"choices":[{"delta":{"content":"…"}}]}   OpenAI-compatible (gateway)
//   {"choices":[{"delta":{"reasoning":"…"}}]} reasoning models

// The token carried by one `data:` line, or "" for anything without one
// (`[DONE]`, comments, the trailing gateway event, malformed JSON).
export function sseToken(line: string): string {
  if (!line.startsWith("data:")) return "";
  const payload = line.slice(5).trim();
  if (!payload || payload === "[DONE]") return "";
  try {
    const j = JSON.parse(payload) as {
      response?: unknown;
      choices?: { delta?: { content?: unknown; reasoning?: unknown } }[];
    };
    if (typeof j.response === "string") return j.response;
    const delta = j.choices?.[0]?.delta;
    if (typeof delta?.content === "string") return delta.content;
    if (typeof delta?.reasoning === "string") return delta.reasoning;
    return "";
  } catch {
    return ""; // partial or non-JSON line — the caller re-buffers it
  }
}

// Stateful line splitter: SSE chunks do not align to line boundaries, so the
// tail of a chunk is held back until the rest of the line arrives.
export function createSseAccumulator(): { push: (chunk: string) => void; done: () => string } {
  let buffer = "";
  let text = "";
  return {
    push(chunk: string) {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? ""; // last element is incomplete (or "")
      for (const line of lines) text += sseToken(line);
    },
    done() {
      if (buffer) {
        text += sseToken(buffer);
        buffer = "";
      }
      return text;
    },
  };
}
