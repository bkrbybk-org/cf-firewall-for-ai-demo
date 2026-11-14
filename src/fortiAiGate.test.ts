// FortiAIGate settings (2026-11-14): the URL rule that keeps the stored credentials on the operator's own zone,
// write-only credentials, and what Test connection may say. No network: fetch is a stand-in.
import { describe, expect, it } from "vitest";
import {
  FORTIAIGATE_CHAT_PATH,
  FORTIAIGATE_DEFAULT_BLOCK_MESSAGE,
  applyCredentials,
  checkBaseUrl,
  decryptForti,
  defaultFortiConfig,
  testForti,
  toPublicForti,
  validateFortiUpdate,
  type FortiConfig,
} from "./fortiAiGate";

const SUFFIX = "example.com";
const SECRET = btoa(String.fromCharCode(...new Uint8Array(32).map((_, i) => i + 1)));

describe("checkBaseUrl — the stored credentials only ever go to the allowed zone", () => {
  it("accepts an https origin on the suffix or a subdomain, normalised", () => {
    expect(checkBaseUrl("https://fortiaigate.example.com", SUFFIX)).toEqual({ ok: true, origin: "https://fortiaigate.example.com" });
    expect(checkBaseUrl("https://FAIG.Example.COM/", SUFFIX)).toEqual({ ok: true, origin: "https://faig.example.com" });
    expect(checkBaseUrl("https://example.com", SUFFIX)).toMatchObject({ ok: true });
  });

  it("refuses another domain, a look-alike, http, a port, a path, user info, and no suffix configured", () => {
    for (const bad of [
      "https://evil.com",
      "https://example.com.evil.com",
      "https://notexample.com",
      "http://fortiaigate.example.com",
      "https://fortiaigate.example.com:8443",
      "https://fortiaigate.example.com/ai/openai",
      "https://fortiaigate.example.com/?x=1",
      "https://user:pw@fortiaigate.example.com",
      "not a url",
    ]) {
      expect(checkBaseUrl(bad, SUFFIX).ok, bad).toBe(false);
    }
    expect(checkBaseUrl("https://fortiaigate.example.com", undefined).ok).toBe(false);
    expect(checkBaseUrl("https://fortiaigate.example.com", "  ").ok).toBe(false);
  });
});

describe("validateFortiUpdate", () => {
  const cur = defaultFortiConfig();

  it("keeps omitted fields, dedupes models, folds the default block message to null", () => {
    const v = validateFortiUpdate(
      { baseUrl: "https://faig.example.com", models: ["bedrock/apac.anthropic.claude-3-haiku-v1:0", " x ", "x", ""], blockMessage: FORTIAIGATE_DEFAULT_BLOCK_MESSAGE },
      cur,
      SUFFIX,
    );
    expect(v.ok && v.next).toMatchObject({ baseUrl: "https://faig.example.com", models: ["bedrock/apac.anthropic.claude-3-haiku-v1:0", "x"], blockMessage: null });
    const again = validateFortiUpdate({}, v.ok ? v.next : cur, SUFFIX);
    expect(again.ok && again.next.baseUrl).toBe("https://faig.example.com");
  });

  it("rejects a bad URL, a bad model name, a long block message, and half a service token", () => {
    expect(validateFortiUpdate({ baseUrl: "https://evil.com" }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ models: ["has space"] }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ models: "x" }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ blockMessage: "x".repeat(501) }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ accessClientId: "id.access" }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ virtualKey: "a b" }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate({ clearAccess: true, accessClientId: "a", accessClientSecret: "b" }, cur, SUFFIX).ok).toBe(false);
    expect(validateFortiUpdate([], cur, SUFFIX).ok).toBe(false);
  });

  it("an empty credential keeps the saved one; clearAccess removes the token", async () => {
    const v = validateFortiUpdate({ virtualKey: "vk-12345678", accessClientId: "cid.access", accessClientSecret: "csecretABCD" }, cur, SUFFIX);
    if (!v.ok) throw new Error(v.error);
    const saved = await applyCredentials(v, SECRET, 1000);
    const keep = validateFortiUpdate({ virtualKey: "", accessClientId: "", accessClientSecret: "" }, saved, SUFFIX);
    expect(keep.ok && keep.newVirtualKey).toBeNull();
    expect(keep.ok && keep.next.virtualKeyEnc).toBe(saved.virtualKeyEnc);
    const cleared = validateFortiUpdate({ clearAccess: true }, saved, SUFFIX);
    expect(cleared.ok && cleared.next.accessClientIdEnc).toBeNull();
    expect(cleared.ok && cleared.next.virtualKeyEnc).toBe(saved.virtualKeyEnc);
  });
});

describe("credentials are encrypted, bound to their column, and never returned", () => {
  it("round-trips, shows last 4 only, and refuses a ciphertext moved to another column", async () => {
    const v = validateFortiUpdate({ virtualKey: "vk-secret-9999", accessClientId: "cid.access", accessClientSecret: "csecretABCD" }, defaultFortiConfig(), SUFFIX);
    if (!v.ok) throw new Error(v.error);
    const c = await applyCredentials(v, SECRET, 1000);
    expect(c.virtualKeyEnc).not.toContain("vk-secret");
    expect(await decryptForti(c, SECRET)).toEqual({ virtualKey: "vk-secret-9999", access: { clientId: "cid.access", clientSecret: "csecretABCD" } });
    const pub = toPublicForti(c, SUFFIX);
    expect(JSON.stringify(pub)).not.toMatch(/vk-secret|csecretABCD|cid\.access|Enc"/);
    expect(pub).toMatchObject({ virtualKeySet: true, virtualKeyLast4: "9999", accessSet: true, accessClientSecretLast4: "ABCD", chatRoute: false });
    const swapped: FortiConfig = { ...c, virtualKeyEnc: c.accessClientSecretEnc };
    await expect(decryptForti(swapped, SECRET)).rejects.toThrow();
  });
});

describe("testForti — observations, never a verdict, never text", () => {
  const cfg: FortiConfig = { ...defaultFortiConfig(), baseUrl: "https://faig.example.com", models: ["m1"] };
  const creds = { virtualKey: "vk", access: { clientId: "id", clientSecret: "sec" } };
  const fake = (res: Response | Error, seen?: { url?: string; init?: RequestInit }) =>
    (async (url: RequestInfo | URL, init?: RequestInit) => {
      if (seen) Object.assign(seen, { url: String(url), init });
      if (res instanceof Error) throw res;
      return res;
    }) as typeof fetch;

  it("sends the fixed prompt to the OpenAI path with both credentials and never follows a redirect", async () => {
    const seen: { url?: string; init?: RequestInit } = {};
    const r = await testForti(cfg, creds, "m1", "benign", fake(Response.json({ choices: [{ message: { content: "OK" } }] }), seen));
    expect(seen.url).toBe("https://faig.example.com" + FORTIAIGATE_CHAT_PATH);
    expect(seen.init?.redirect).toBe("manual");
    const h = seen.init?.headers as Record<string, string>;
    expect(h).toMatchObject({ authorization: "Bearer vk", "cf-access-client-id": "id", "cf-access-client-secret": "sec" });
    expect(JSON.parse(String(seen.init?.body))).toMatchObject({ model: "m1", stream: false, messages: [{ role: "user", content: "Reply with OK." }] });
    expect(r).toMatchObject({ outcome: "replied", status: 200, replyChars: 2 });
    expect(JSON.stringify(r)).not.toContain('"OK"');
  });

  it("names the block message, Access's redirect, a key refusal, and no answer", async () => {
    const blocked = await testForti(cfg, creds, "m1", "attack", fake(Response.json({ error: { message: FORTIAIGATE_DEFAULT_BLOCK_MESSAGE } }, { status: 400 })));
    expect(blocked).toMatchObject({ outcome: "block_message_seen", status: 400 });
    expect(JSON.stringify(blocked)).not.toContain("safety systems");
    const redirected = await testForti(cfg, creds, "m1", "benign", fake(new Response(null, { status: 302, headers: { location: "https://team.cloudflareaccess.com/login" } })));
    expect(redirected.outcome).toBe("access_redirect");
    expect(JSON.stringify(redirected)).not.toContain("cloudflareaccess");
    const key = await testForti(cfg, creds, "m1", "benign", fake(Response.json({ error: "invalid key sk-leak" }, { status: 401 })));
    expect(key.outcome).toBe("unauthorized");
    expect(JSON.stringify(key)).not.toContain("sk-leak");
    const down = await testForti(cfg, creds, "m1", "benign", fake(new TypeError("internal error")));
    expect(down).toMatchObject({ outcome: "unreachable", status: null });
  });

  it("a 200 with no reply is not 'replied'", async () => {
    const r = await testForti(cfg, creds, "m1", "benign", fake(Response.json({ choices: [{ message: { content: "" } }] })));
    expect(r.outcome).toBe("http_error");
  });

  // The two bodies FortiAIGate 8.0.2 really sent on 2026-11-14 (through the tunnel), with ids and timestamps kept.
  it("real block: HTTP 200, finish_reason content_filter, the block message as the reply", async () => {
    const real = {
      choices: [{ finish_reason: "content_filter", index: 0, message: { content: FORTIAIGATE_DEFAULT_BLOCK_MESSAGE, role: "assistant" } }],
      created: 1794665749,
      id: "chatcmpl-blocked",
      model: "bedrock-apse1-amazon.nova-micro-v1-0",
      object: "chat.completion",
      usage: { completion_tokens: 0, prompt_tokens: 0, total_tokens: 0 },
    };
    const r = await testForti(cfg, creds, "m1", "attack", fake(Response.json(real)));
    expect(r).toMatchObject({ outcome: "block_message_seen", status: 200 });
    expect(JSON.stringify(r.responseShape)).toContain('"finish_reason":"string = content_filter"');
    expect(JSON.stringify(r)).not.toContain("safety systems");
  });

  it("real unknown model: 404 model_not_found gets a message saying what to fix, and only the code is revealed", async () => {
    const real = { error: { message: "model amazon.nova-micro-v1:0 is not available to this API key", type: "not_found_error", param: null, code: "model_not_found" } };
    const r = await testForti(cfg, creds, "amazon.nova-micro-v1:0", "benign", fake(Response.json(real, { status: 404 })));
    expect(r.outcome).toBe("http_error");
    expect(r.error).toMatch(/Model Catalog/);
    expect(r.responseShape).toEqual({ error: { message: "string", type: "string = not_found_error", param: "null", code: "string = model_not_found" } });
    expect(JSON.stringify(r)).not.toContain("is not available");
  });
});
