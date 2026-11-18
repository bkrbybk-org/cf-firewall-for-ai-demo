// Booth's own gateway choice (2026-11-18): it may pick a gateway the account has, and nothing else.
import { describe, expect, it } from "vitest";
import { resolveBoothChoice, resolveBoothGateway } from "./boothGateway";

const G = [
  { id: "plain-gw", label: "plain-gw", guarded: false },
  { id: "guarded-gw", label: "guarded-gw (Guardrails)", guarded: true },
];

describe("resolveBoothGateway", () => {
  it("no preference: the chat page's gateway", () => {
    expect(resolveBoothGateway("", G, "plain-gw")).toEqual({ id: "plain-gw", source: "chat", missing: false });
  });

  it("a preference the account has wins over the chat page", () => {
    expect(resolveBoothGateway("guarded-gw", G, "plain-gw")).toEqual({ id: "guarded-gw", source: "booth", missing: false });
  });

  it("a preference no longer in the account is never sent — falls back, and says it is missing", () => {
    expect(resolveBoothGateway("deleted-gw", G, "plain-gw")).toEqual({ id: "plain-gw", source: "chat", missing: true });
  });

  it("before the list loads, a preference is not called missing (an empty list is not evidence)", () => {
    expect(resolveBoothGateway("guarded-gw", [], "")).toEqual({ id: "", source: "chat", missing: false });
  });
});

describe("resolveBoothChoice (booth model)", () => {
  const M = ["@cf/meta/llama-3.2-3b-instruct", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"];
  it("a listed model wins; an unlisted one is never sent", () => {
    expect(resolveBoothChoice(M[1], M, M[0])).toEqual({ id: M[1], source: "booth", missing: false });
    expect(resolveBoothChoice("@cf/removed/model", M, M[0])).toEqual({ id: M[0], source: "chat", missing: true });
    expect(resolveBoothChoice("", M, M[0]).source).toBe("chat");
  });
});
