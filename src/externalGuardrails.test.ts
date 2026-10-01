// Tests for external-guardrail configuration and forwarding.
//
// Most of these are about what a hostile or careless caller of the config API
// could do — /api/external-guardrails is reachable by anything that passes
// Cloudflare Access, which includes a scanner's service token, not just humans.
// The properties pinned: the API key can only ever be sent to an official
// provider host; it is never returned; it is stored encrypted and bound to its
// provider; nothing can be switched on that cannot work; and an error is never
// treated as a verdict.
import { describe, expect, it } from "vitest";
import {
  decryptSecret,
  defaultConfig,
  encryptSecret,
  forwardPrompt,
  stopsTurn,
  toPublicConfig,
  validateUpdate,
  type StoredConfig,
} from "./externalGuardrails";
import type { Env, ExternalGuardrailResult } from "./types";

// 32 bytes, base64 — the shape `openssl rand -base64 32` produces.
const SECRET = btoa(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i + 1)));
const airs = (): StoredConfig => defaultConfig("prisma-airs");

describe("validateUpdate", () => {
  it("accepts a region from the allowlist", () => {
    const v = validateUpdate({ provider: "prisma-airs", region: "sg" }, airs());
    expect(v.ok && v.next.region).toBe("sg");
  });

  // The stored key travels in a header. A free URL would let anyone who can
  // reach the API point it at their own server.
  it("rejects anything that is not an allowlisted region id — including a URL", () => {
    for (const region of ["https://evil.example", "us ", "US", "", "eu-west-1"]) {
      const v = validateUpdate({ provider: "prisma-airs", region }, airs());
      expect(v.ok, region).toBe(false);
    }
  });

  it("ignores any client-sent endpoint field: there is no way to set one", () => {
    const v = validateUpdate({ provider: "prisma-airs", endpoint: "https://evil.example", url: "https://evil.example" }, airs());
    expect(v.ok).toBe(true);
    if (v.ok) expect(JSON.stringify(v.next)).not.toContain("evil.example");
  });

  it("refuses to enable without a key, and without a profile", () => {
    expect(validateUpdate({ provider: "prisma-airs", enabled: true, profileName: "p" }, airs())).toMatchObject({
      ok: false,
      error: "Cannot enable: save an API key first",
    });
    expect(validateUpdate({ provider: "prisma-airs", enabled: true, apiKey: "k" }, airs())).toMatchObject({
      ok: false,
      error: "Cannot enable: an AI security profile name is required",
    });
  });

  it("allows enabling in the same request that supplies the key and profile", () => {
    const v = validateUpdate({ provider: "prisma-airs", enabled: true, apiKey: "abcd1234", profileName: "p" }, airs());
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.newApiKey).toBe("abcd1234");
      expect(v.next.apiKeyLast4).toBe("1234");
    }
  });

  it("keeps the existing key when the field is empty (the form's default)", () => {
    const current = { ...airs(), apiKeyEnc: "CIPHER", apiKeyLast4: "9999" };
    const v = validateUpdate({ provider: "prisma-airs", apiKey: "", profileName: "p" }, current);
    expect(v.ok && v.newApiKey).toBe(null);
    if (v.ok) expect(v.next.apiKeyEnc).toBe("CIPHER");
  });

  it("clearing the key also disables the provider", () => {
    const current = { ...airs(), enabled: true, apiKeyEnc: "CIPHER", apiKeyLast4: "9999", profileName: "p" };
    const v = validateUpdate({ provider: "prisma-airs", clearApiKey: true }, current);
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.next).toMatchObject({ enabled: false, apiKeyEnc: null, apiKeyLast4: null });
  });

  it("rejects malformed fields", () => {
    const bad = [
      { provider: "prisma-airs", failMode: "maybe" },
      { provider: "prisma-airs", enabled: "yes" },
      { provider: "prisma-airs", apiKey: "has space" },
      { provider: "prisma-airs", apiKey: 42 },
      { provider: "prisma-airs", profileName: "x".repeat(201) },
    ];
    for (const b of bad) expect(validateUpdate(b, airs()).ok, JSON.stringify(b)).toBe(false);
    expect(validateUpdate(null, airs()).ok).toBe(false);
  });

  it("rejects configuring a provider that is not supported yet", () => {
    expect(validateUpdate({ provider: "crowdstrike-aidr", enabled: true }, defaultConfig("crowdstrike-aidr")).ok).toBe(false);
  });
});

describe("toPublicConfig", () => {
  it("never returns the stored key, only its last four characters", () => {
    const c = { ...airs(), apiKeyEnc: "SECRET-CIPHERTEXT", apiKeyLast4: "1234" };
    const pub = toPublicConfig(c);
    expect(JSON.stringify(pub)).not.toContain("SECRET-CIPHERTEXT");
    expect(pub).toMatchObject({ apiKeySet: true, apiKeyLast4: "1234" });
    expect(pub.endpoint).toBe("https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request");
  });
});

describe("API key encryption", () => {
  it("round-trips, and never stores the plaintext", async () => {
    const blob = await encryptSecret("my-real-key", SECRET, "prisma-airs");
    expect(blob).not.toContain("my-real-key");
    expect(await decryptSecret(blob, SECRET, "prisma-airs")).toBe("my-real-key");
  });

  it("uses a fresh IV each time, so equal keys do not produce equal ciphertexts", async () => {
    expect(await encryptSecret("same", SECRET, "prisma-airs")).not.toBe(await encryptSecret("same", SECRET, "prisma-airs"));
  });

  it("binds the ciphertext to its provider: copied onto another row it will not decrypt", async () => {
    const blob = await encryptSecret("k", SECRET, "prisma-airs");
    await expect(decryptSecret(blob, SECRET, "crowdstrike-aidr")).rejects.toThrow();
  });

  it("detects tampering", async () => {
    const blob = await encryptSecret("k", SECRET, "prisma-airs");
    const bytes = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    bytes[bytes.length - 1] ^= 1;
    await expect(decryptSecret(btoa(String.fromCharCode(...bytes)), SECRET, "prisma-airs")).rejects.toThrow();
  });

  it("refuses a secret that is not 32 bytes", async () => {
    await expect(encryptSecret("k", btoa("too short"), "prisma-airs")).rejects.toThrow(/32 bytes/);
  });
});

describe("stopsTurn", () => {
  const r = (o: Partial<ExternalGuardrailResult>): ExternalGuardrailResult => ({ provider: "prisma-airs", outcome: "allow", latencyMs: 1, ...o });
  it("stops on a block and on a fail-closed error; lets an allow and a fail-open error through", () => {
    expect(stopsTurn(r({ outcome: "block" }))).toBe(true);
    expect(stopsTurn(r({ outcome: "error" }))).toBe(true);
    expect(stopsTurn(r({ outcome: "error", failedOpen: true }))).toBe(false);
    expect(stopsTurn(r({ outcome: "allow" }))).toBe(false);
  });
});

describe("forwardPrompt", () => {
  // A D1 stand-in that serves one stored row for the "enabled" lookup.
  // `secret: null` means "not set". Not `undefined`: passing undefined to a
  // parameter with a default silently applies the default.
  async function envWith(row: Record<string, unknown> | null, secret: string | null = SECRET): Promise<Env> {
    return {
      GUARDRAIL_SECRET_KEY: secret ?? undefined,
      DB: { prepare: () => ({ first: async () => row }) } as unknown as D1Database,
    } as Env;
  }
  async function storedRow(overrides: Record<string, unknown> = {}) {
    return {
      provider: "prisma-airs",
      enabled: 1,
      region: "eu",
      profile_name: "demo-profile",
      fail_mode: "block",
      api_key_enc: await encryptSecret("the-real-key", SECRET, "prisma-airs"),
      api_key_last4: "-key",
      updated_at: 1,
      ...overrides,
    };
  }

  it("does nothing when no provider is enabled, or the secret is missing", async () => {
    const never = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    expect(await forwardPrompt(await envWith(null), { prompt: "p", model: "m", ray: null }, never)).toBeNull();
    expect(await forwardPrompt(await envWith(await storedRow(), null), { prompt: "p", model: "m", ray: null }, never)).toBeNull();
  });

  it("sends the decrypted key only to the configured region's official host", async () => {
    let seenUrl = "";
    let seenKey = "";
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seenUrl = url;
      seenKey = (init?.headers as Record<string, string>)["x-pan-token"];
      return Response.json({ action: "allow", category: "benign" });
    }) as typeof fetch;
    const r = await forwardPrompt(await envWith(await storedRow()), { prompt: "p", model: "m", ray: "abc" }, fetchImpl);
    expect(seenUrl).toBe("https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request");
    expect(seenKey).toBe("the-real-key");
    expect(r?.outcome).toBe("allow");
  });

  it("marks an error as failed-open only when the fail mode says allow", async () => {
    const down = (async () => {
      throw new TypeError("down");
    }) as typeof fetch;
    const closed = await forwardPrompt(await envWith(await storedRow({ fail_mode: "block" })), { prompt: "p", model: "m", ray: null }, down);
    expect(closed).toMatchObject({ outcome: "error" });
    expect(closed?.failedOpen).toBeUndefined();
    expect(stopsTurn(closed!)).toBe(true);
    const open = await forwardPrompt(await envWith(await storedRow({ fail_mode: "allow" })), { prompt: "p", model: "m", ray: null }, down);
    expect(open).toMatchObject({ outcome: "error", failedOpen: true });
    expect(stopsTurn(open!)).toBe(false);
  });

  it("reports a key that no longer decrypts (secret rotated) as an error, not a silent pass", async () => {
    const otherSecret = btoa(String.fromCharCode(...Array.from({ length: 32 }, () => 7)));
    const r = await forwardPrompt(await envWith(await storedRow(), otherSecret), { prompt: "p", model: "m", ray: null });
    expect(r).toMatchObject({ outcome: "error" });
    expect(r?.error).toMatch(/could not be decrypted/);
  });
});
