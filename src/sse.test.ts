// The Worker-side SSE reader that recovers a streamed reply for the prompt
// log. It exists because streaming is the DEFAULT path here, so before this
// the log's reply column was empty for most real traffic — which made the
// "evidence trail" claim false exactly where it mattered most.
import { describe, expect, it } from "vitest";
import { createSseAccumulator, sseToken } from "./sse";

describe("sseToken", () => {
  it("reads the Workers AI binding shape", () => {
    expect(sseToken('data: {"response":"hello"}')).toBe("hello");
  });

  it("reads the OpenAI-compatible delta shape (gateway route)", () => {
    expect(sseToken('data: {"choices":[{"delta":{"content":"hi"}}]}')).toBe("hi");
  });

  it("reads a reasoning delta", () => {
    expect(sseToken('data: {"choices":[{"delta":{"reasoning":"thinking"}}]}')).toBe("thinking");
  });

  it("ignores [DONE], blanks and non-data lines", () => {
    expect(sseToken("data: [DONE]")).toBe("");
    expect(sseToken("data:")).toBe("");
    expect(sseToken(": keep-alive comment")).toBe("");
    expect(sseToken("event: message")).toBe("");
  });

  it("ignores the Worker's own trailing gateway event", () => {
    // Appended by appendRestGatewayEvent — metadata, not reply text. Counting
    // it would put JSON into the logged reply.
    expect(sseToken('data: {"gateway":{"gatewayId":"gw","cached":true}}')).toBe("");
  });

  it("returns nothing for a malformed payload rather than throwing", () => {
    expect(sseToken('data: {"response":')).toBe("");
    expect(sseToken("data: not json at all")).toBe("");
  });
});

describe("createSseAccumulator", () => {
  it("assembles a reply across chunks", () => {
    const acc = createSseAccumulator();
    acc.push('data: {"response":"Hello"}\n');
    acc.push('data: {"response":", world"}\n');
    acc.push("data: [DONE]\n");
    expect(acc.done()).toBe("Hello, world");
  });

  it("re-buffers a line split mid-chunk", () => {
    // The real failure this guards: network chunks do not align to line
    // boundaries, and a naive per-chunk parse drops every token that straddles
    // one.
    const acc = createSseAccumulator();
    acc.push('data: {"resp');
    acc.push('onse":"split"}\n');
    expect(acc.done()).toBe("split");
  });

  it("flushes a final line that never got its newline", () => {
    const acc = createSseAccumulator();
    acc.push('data: {"response":"tail"}');
    expect(acc.done()).toBe("tail");
  });

  it("is empty for a stream that carried no tokens", () => {
    const acc = createSseAccumulator();
    acc.push("data: [DONE]\n");
    expect(acc.done()).toBe("");
  });

  it("mixes both chunk shapes in one stream", () => {
    const acc = createSseAccumulator();
    acc.push('data: {"response":"a"}\n');
    acc.push('data: {"choices":[{"delta":{"content":"b"}}]}\n');
    expect(acc.done()).toBe("ab");
  });
});
