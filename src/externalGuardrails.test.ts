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
  PROVIDER_IDS,
  PROVIDERS,
  defaultConfig,
  defaultPipeline,
  encryptSecret,
  executePipeline,
  normalizeOrder,
  RAW_MAX_CHARS,
  loadGuardrailSetup,
  runPipeline,
  runReplyCheck,
  secondKeyAad,
  stopsTurn,
  willCheckReply,
  stripRaw,
  toPublicConfig,
  validatePipelineUpdate,
  validateUpdate,
  type Scan,
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

  // Configurable (that is how they get verified) but flagged unverified, and held to
  // the same enable rules as the others: a key, plus Lakera's project.
  it("lets Cisco AI Defense and Lakera Guard be configured, flagged unverified, under the same rules", () => {
    expect([PROVIDERS["cisco-ai-defense"].verified, PROVIDERS["lakera-guard"].verified]).toEqual([false, false]);
    expect([PROVIDERS["prisma-airs"].verified, PROVIDERS["crowdstrike-aidr"].verified]).toEqual([true, true]);
    expect(validateUpdate({ provider: "cisco-ai-defense", enabled: true }, defaultConfig("cisco-ai-defense"))).toMatchObject({
      ok: false,
      error: "Cannot enable: save an API key first",
    });
    expect(validateUpdate({ provider: "lakera-guard", enabled: true, apiKey: "k" }, defaultConfig("lakera-guard"))).toMatchObject({
      ok: false,
      error: "Cannot enable: a project ID is required",
    });
    expect(validateUpdate({ provider: "cisco-ai-defense", apiKey: "k", enabled: true }, defaultConfig("cisco-ai-defense")).ok).toBe(true);
  });

  // Cato: the Guard's key is the policy, so a key alone enables it; one official host.
  // Its string verdict is the only field Test connection may show the value of.
  it("lets Cato AI Security be configured, unverified, with a key alone and one host", () => {
    const spec = PROVIDERS["cato-ai-security"];
    expect([spec.supported, spec.verified, spec.requiresProfile]).toEqual([true, false, false]);
    expect(spec.regions.map((r) => r.url)).toEqual(["https://api.aisec.catonetworks.com"]);
    expect(spec.revealPaths).toEqual(["required_action.action_type"]);
    expect(PROVIDER_IDS.filter((p) => PROVIDERS[p].revealPaths)).toEqual(["cato-ai-security"]);
    expect(validateUpdate({ provider: "cato-ai-security", enabled: true }, defaultConfig("cato-ai-security"))).toMatchObject({
      ok: false,
      error: "Cannot enable: save an API key first",
    });
    expect(validateUpdate({ provider: "cato-ai-security", apiKey: "k", enabled: true }, defaultConfig("cato-ai-security")).ok).toBe(true);
  });

  // Datadog: two keys, six official site hosts, and the policy rides on the org (no profile).
  it("lets Datadog AI Guard be configured, unverified, on its six site hosts", () => {
    const spec = PROVIDERS["datadog-ai-guard"];
    expect([spec.supported, spec.verified, spec.requiresProfile, spec.replyCheck]).toEqual([true, false, false, true]);
    expect([spec.keyLabel, spec.secondKeyLabel]).toEqual(["API key", "Application key"]);
    expect(spec.regions.map((r) => r.url)).toEqual([
      "https://app.datadoghq.com",
      "https://us3.datadoghq.com",
      "https://us5.datadoghq.com",
      "https://app.datadoghq.eu",
      "https://ap1.datadoghq.com",
      "https://ap2.datadoghq.com",
    ]);
    expect(PROVIDER_IDS.filter((p) => PROVIDERS[p].secondKeyLabel)).toEqual(["datadog-ai-guard"]);
  });

  describe("a second key (Datadog)", () => {
    const dd = () => defaultConfig("datadog-ai-guard");

    it("cannot be enabled until BOTH keys are saved", () => {
      expect(validateUpdate({ enabled: true, secondKey: "app1" }, dd())).toMatchObject({ ok: false, error: "Cannot enable: save an API key first" });
      expect(validateUpdate({ enabled: true, apiKey: "api1" }, dd())).toMatchObject({
        ok: false,
        error: "Cannot enable: save an application key first",
      });
      const both = validateUpdate({ enabled: true, apiKey: "api-1111", secondKey: "app-2222" }, dd());
      expect(both).toMatchObject({ ok: true, newApiKey: "api-1111", newSecondKey: "app-2222" });
      if (both.ok) expect([both.next.apiKeyLast4, both.next.secondKeyLast4]).toEqual(["1111", "2222"]);
      // Both already stored: enabling needs nothing new.
      const stored = { ...dd(), apiKeyEnc: "C1", apiKeyLast4: "1111", secondKeyEnc: "C2", secondKeyLast4: "2222" };
      expect(validateUpdate({ enabled: true }, stored).ok).toBe(true);
    });

    it("keeps a saved second key when the field is empty, and replaces it alone", () => {
      const stored = { ...dd(), apiKeyEnc: "C1", apiKeyLast4: "1111", secondKeyEnc: "C2", secondKeyLast4: "2222" };
      const keep = validateUpdate({ apiKey: "", secondKey: "" }, stored);
      expect(keep).toMatchObject({ ok: true, newApiKey: null, newSecondKey: null });
      if (keep.ok) expect(keep.next).toMatchObject({ apiKeyEnc: "C1", secondKeyEnc: "C2" });
      const swap = validateUpdate({ secondKey: "new-3333" }, stored);
      expect(swap).toMatchObject({ ok: true, newApiKey: null, newSecondKey: "new-3333" });
      if (swap.ok) expect(swap.next).toMatchObject({ apiKeyEnc: "C1", secondKeyLast4: "3333" });
    });

    it("Remove key removes both and disables; malformed or misplaced second keys are refused", () => {
      const stored = { ...dd(), enabled: true, apiKeyEnc: "C1", apiKeyLast4: "1111", secondKeyEnc: "C2", secondKeyLast4: "2222" };
      const v = validateUpdate({ clearApiKey: true, secondKey: "ignored" }, stored);
      expect(v).toMatchObject({ ok: true, newSecondKey: null });
      if (v.ok) expect(v.next).toMatchObject({ enabled: false, apiKeyEnc: null, apiKeyLast4: null, secondKeyEnc: null, secondKeyLast4: null });
      expect(validateUpdate({ secondKey: "has space" }, dd()).ok).toBe(false);
      expect(validateUpdate({ secondKey: 42 }, dd()).ok).toBe(false);
      expect(validateUpdate({ secondKey: "x".repeat(4097) }, dd()).ok).toBe(false);
      // A one-key provider never stores a second secret.
      expect(validateUpdate({ secondKey: "k" }, airs())).toMatchObject({ ok: false, error: expect.stringMatching(/takes one key/) });
    });

    it("never returns either key, only their last 4", () => {
      const pub = toPublicConfig({ ...dd(), apiKeyEnc: "CIPHER-1", apiKeyLast4: "1111", secondKeyEnc: "CIPHER-2", secondKeyLast4: "2222" });
      expect(pub).toMatchObject({ secondKeyLabel: "Application key", secondKeySet: true, secondKeyLast4: "2222", apiKeyLast4: "1111" });
      expect(JSON.stringify(pub)).not.toMatch(/CIPHER/);
      // A one-key provider says so, even if a stray second ciphertext were stored on its row.
      expect(toPublicConfig({ ...airs(), secondKeyEnc: "CIPHER-2", secondKeyLast4: "2222" })).toMatchObject({
        secondKeyLabel: null,
        secondKeySet: false,
        secondKeyLast4: null,
      });
    });
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

  // CrowdStrike AIDR takes its policy from the collector token, so it has no
  // profile to require — but it still cannot be enabled without its token.
  it("CrowdStrike AIDR: enables with a token and no profile, never without a token", () => {
    const aidr = defaultConfig("crowdstrike-aidr");
    expect(validateUpdate({ provider: "crowdstrike-aidr", enabled: true }, aidr)).toMatchObject({
      ok: false,
      error: "Cannot enable: save a collector token first",
    });
    const v = validateUpdate({ provider: "crowdstrike-aidr", enabled: true, apiKey: "pts_abc123" }, aidr);
    expect(v.ok && v.next).toMatchObject({ enabled: true, region: "us-1", apiKeyLast4: "c123" });
  });

  it("CrowdStrike AIDR: region must be one of its three official hosts", () => {
    for (const region of ["us", "eu", "https://api.crowdstrike.com", "us-3"]) {
      expect(validateUpdate({ provider: "crowdstrike-aidr", region }, defaultConfig("crowdstrike-aidr")).ok, region).toBe(false);
    }
    expect(validateUpdate({ provider: "crowdstrike-aidr", region: "eu-1" }, defaultConfig("crowdstrike-aidr")).ok).toBe(true);
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

describe("pipeline config", () => {
  it("normalises a stored order into a full permutation", () => {
    const ALL = ["prisma-airs", "crowdstrike-aidr", "cisco-ai-defense", "lakera-guard", "cato-ai-security", "datadog-ai-guard"];
    expect(
      normalizeOrder(["lakera-guard", "datadog-ai-guard", "crowdstrike-aidr", "cato-ai-security", "cisco-ai-defense", "prisma-airs"]),
    ).toEqual(["lakera-guard", "datadog-ai-guard", "crowdstrike-aidr", "cato-ai-security", "cisco-ai-defense", "prisma-airs"]);
    // Unknown ids dropped, duplicates removed, missing providers appended — a
    // hand-edited row can never make a provider vanish from the pipeline.
    // Missing ones are appended in registry order, so an order stored before a
    // provider existed (2026-10-05: two providers became four; 2026-10-06: five; 2026-10-09: six) stays valid.
    expect(normalizeOrder(["bogus", "crowdstrike-aidr", "crowdstrike-aidr"])).toEqual([
      "crowdstrike-aidr",
      "prisma-airs",
      "cisco-ai-defense",
      "lakera-guard",
      "cato-ai-security",
      "datadog-ai-guard",
    ]);
    // Prod's stored orders from before Cato and before Datadog existed: each joins at the end.
    expect(normalizeOrder(["prisma-airs", "crowdstrike-aidr", "cisco-ai-defense", "lakera-guard"])).toEqual(ALL);
    expect(normalizeOrder(["prisma-airs", "crowdstrike-aidr", "cisco-ai-defense", "lakera-guard", "cato-ai-security"])).toEqual(ALL);
    expect(normalizeOrder([])).toEqual(ALL);
  });

  it("accepts a valid update and leaves omitted fields alone", () => {
    const v = validatePipelineUpdate({ mode: "parallel" }, defaultPipeline());
    expect(v).toEqual({
      ok: true,
      next: {
        mode: "parallel",
        guardrailOnly: false,
        order: ["prisma-airs", "crowdstrike-aidr", "cisco-ai-defense", "lakera-guard", "cato-ai-security", "datadog-ai-guard"],
        scanReplies: false,
      },
    });
    const order = ["crowdstrike-aidr", "datadog-ai-guard", "cato-ai-security", "lakera-guard", "prisma-airs", "cisco-ai-defense"];
    const w = validatePipelineUpdate({ guardrailOnly: true, order }, defaultPipeline());
    expect(w.ok && w.next).toMatchObject({ mode: "sequential", guardrailOnly: true, order });
  });

  // Strict on input: silently repairing a bad order would save one the operator never chose.
  it("rejects an order that is not exactly a permutation, and malformed fields", () => {
    for (const order of [["prisma-airs"], ["prisma-airs", "prisma-airs"], ["prisma-airs", "evil"], "prisma-airs", [1, 2]]) {
      expect(validatePipelineUpdate({ order }, defaultPipeline()).ok, JSON.stringify(order)).toBe(false);
    }
    expect(validatePipelineUpdate({ mode: "race" }, defaultPipeline()).ok).toBe(false);
    expect(validatePipelineUpdate({ guardrailOnly: "yes" }, defaultPipeline()).ok).toBe(false);
    expect(validatePipelineUpdate([], defaultPipeline()).ok).toBe(false);
  });
});

describe("executePipeline", () => {
  // Fake providers. The registry has two ids, which is all the ordering rules need.
  const A = { ...defaultConfig("prisma-airs"), enabled: true };
  const B = { ...defaultConfig("crowdstrike-aidr"), enabled: true };
  const verdict = (provider: StoredConfig["provider"], outcome: ExternalGuardrailResult["outcome"], extra = {}): ExternalGuardrailResult => ({
    provider,
    outcome,
    latencyMs: 1,
    ...extra,
  });
  // Records the call order and lets each fake take a set time.
  function fakes(plan: Record<string, { r: ExternalGuardrailResult; ms?: number }>) {
    const calls: string[] = [];
    const scan: Scan = async (c) => {
      calls.push(c.provider);
      const p = plan[c.provider];
      if (p.ms) await new Promise((res) => setTimeout(res, p.ms));
      return p.r;
    };
    return { calls, scan };
  }

  it("sequential: runs in the configured order and goes on while each allows", async () => {
    const f = fakes({ "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "allow") }, "prisma-airs": { r: verdict("prisma-airs", "allow") } });
    const out = await executePipeline([B, A], "sequential", false, f.scan);
    expect(f.calls).toEqual(["crowdstrike-aidr", "prisma-airs"]);
    expect(out).toMatchObject({ stoppedBy: null, notRun: [], mode: "sequential" });
    expect(out.results.map((r) => r.provider)).toEqual(["crowdstrike-aidr", "prisma-airs"]);
  });

  it("sequential: the first block ends it — later guardrails are not called, and say why", async () => {
    const f = fakes({ "prisma-airs": { r: verdict("prisma-airs", "block") }, "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "allow") } });
    const out = await executePipeline([A, B], "sequential", false, f.scan);
    expect(f.calls).toEqual(["prisma-airs"]);
    expect(out.stoppedBy).toBe("prisma-airs");
    expect(out.notRun).toEqual([{ provider: "crowdstrike-aidr", reason: "Not run: Palo Alto Networks Prisma AIRS blocked the prompt" }]);
  });

  it("sequential: a fail-closed error stops it, a fail-open error does not", async () => {
    const closed = fakes({ "prisma-airs": { r: verdict("prisma-airs", "error") }, "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "allow") } });
    const c = await executePipeline([A, B], "sequential", false, closed.scan);
    expect(c.stoppedBy).toBe("prisma-airs");
    expect(c.notRun[0].reason).toMatch(/unavailable \(fail closed\)/);
    const open = fakes({
      "prisma-airs": { r: verdict("prisma-airs", "error", { failedOpen: true }) },
      "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "allow") },
    });
    const o = await executePipeline([A, B], "sequential", false, open.scan);
    expect(open.calls).toEqual(["prisma-airs", "crowdstrike-aidr"]);
    expect(o.stoppedBy).toBeNull();
  });

  it("parallel: runs every guardrail at the same time — wall clock is the slowest, not the sum", async () => {
    const f = fakes({
      "prisma-airs": { r: verdict("prisma-airs", "allow"), ms: 60 },
      "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "allow"), ms: 60 },
    });
    const t0 = Date.now();
    const out = await executePipeline([A, B], "parallel", false, f.scan);
    const wall = Date.now() - t0;
    expect(wall).toBeLessThan(110); // sequential would be ≥ 120
    expect(out.stoppedBy).toBeNull();
  });

  it("parallel: one block stops the turn, but every verdict is still reported, in configured order", async () => {
    const f = fakes({
      "prisma-airs": { r: verdict("prisma-airs", "allow"), ms: 30 },
      "crowdstrike-aidr": { r: verdict("crowdstrike-aidr", "block"), ms: 5 },
    });
    const out = await executePipeline([A, B], "parallel", false, f.scan);
    expect(out.stoppedBy).toBe("crowdstrike-aidr");
    expect(out.results.map((r) => [r.provider, r.outcome])).toEqual([
      ["prisma-airs", "allow"],
      ["crowdstrike-aidr", "block"],
    ]);
    expect(out.notRun).toEqual([]);
  });

  it("carries guardrail-only through, including with no guardrail enabled (edge-only test)", async () => {
    const out = await executePipeline([], "sequential", true, fakes({}).scan);
    expect(out).toMatchObject({ guardrailOnly: true, results: [], stoppedBy: null });
  });
});

describe("runPipeline", () => {
  // A D1 stand-in: the pipeline row for `first()`, the enabled provider rows for
  // `all()`. `secret: null` means "not set". Not `undefined`: passing undefined
  // to a parameter with a default silently applies the default.
  async function envWith(
    row: Record<string, unknown> | null,
    secret: string | null = SECRET,
    pipeline: Record<string, unknown> | null = null,
  ): Promise<Env> {
    return {
      GUARDRAIL_SECRET_KEY: secret ?? undefined,
      DB: {
        prepare: (sql: string) => ({
          first: async () => (sql.includes("guardrail_pipeline") ? pipeline : null),
          all: async () => ({ results: row ? [row] : [] }),
        }),
      } as unknown as D1Database,
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
    expect(await runPipeline(await envWith(null), { prompt: "p", model: "m", ray: null }, never)).toBeNull();
    expect(await runPipeline(await envWith(await storedRow(), null), { prompt: "p", model: "m", ray: null }, never)).toBeNull();
  });

  it("sends the decrypted key only to the configured region's official host", async () => {
    let seenUrl = "";
    let seenKey = "";
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seenUrl = url;
      seenKey = (init?.headers as Record<string, string>)["x-pan-token"];
      return Response.json({ action: "allow", category: "benign" });
    }) as typeof fetch;
    const r = await runPipeline(await envWith(await storedRow()), { prompt: "p", model: "m", ray: "abc" }, fetchImpl);
    expect(seenUrl).toBe("https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request");
    expect(seenKey).toBe("the-real-key");
    expect(r?.results[0].outcome).toBe("allow");
  });

  // The opt-in debug view. The raw body can quote the prompt and what the vendor found,
  // so it exists only when asked for, never includes the request (it carries the key),
  // and stripRaw() — what the x-external-guardrails header is built from — removes it.
  it("records the vendor's raw response only when asked, and stripRaw removes it", async () => {
    const body = { action: "block", category: "malicious", prompt_detected: { injection: true }, echo: "the prompt text" };
    const fetchImpl = (async () => Response.json(body)) as typeof fetch;
    const input = { prompt: "p", model: "m", ray: "abc" };
    const plain = await runPipeline(await envWith(await storedRow()), input, fetchImpl);
    expect(plain!.results[0].raw).toBeUndefined();

    const withRaw = await runPipeline(await envWith(await storedRow()), input, fetchImpl, { captureRaw: true });
    expect(withRaw!.results[0]).toMatchObject({ outcome: "block", raw: { status: 200, body, json: true, truncated: false } });
    // The verdict is parsed exactly as without capture.
    expect({ ...withRaw!.results[0], raw: undefined, latencyMs: 0 }).toEqual({ ...plain!.results[0], raw: undefined, latencyMs: 0 });
    // Never the request: the key is nowhere in what is recorded.
    expect(JSON.stringify(withRaw)).not.toContain("the-real-key");

    const stripped = stripRaw(withRaw!);
    expect(stripped.results[0].raw).toBeUndefined();
    expect(JSON.stringify(stripped)).not.toContain("the prompt text");
    expect(withRaw!.results[0].raw).toBeDefined(); // stripRaw copies, it does not mutate
  });

  it("keeps a non-JSON or oversized raw body as capped text, and an unreadable copy never costs the verdict", async () => {
    const text = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as typeof fetch;
    const a = await runPipeline(await envWith(await storedRow()), { prompt: "p", model: "m", ray: null }, text, { captureRaw: true });
    expect(a!.results[0]).toMatchObject({ outcome: "error", raw: { status: 502, body: "<html>bad gateway</html>", json: false } });

    const huge = (async () => new Response(JSON.stringify({ action: "allow", pad: "x".repeat(RAW_MAX_CHARS) }))) as typeof fetch;
    const b = await runPipeline(await envWith(await storedRow()), { prompt: "p", model: "m", ray: null }, huge, { captureRaw: true });
    expect(b!.results[0].outcome).toBe("allow");
    expect(b!.results[0].raw).toMatchObject({ json: false, truncated: true });
    expect((b!.results[0].raw!.body as string).length).toBe(RAW_MAX_CHARS);
  });

  it("marks an error as failed-open only when the fail mode says allow", async () => {
    const down = (async () => {
      throw new TypeError("down");
    }) as typeof fetch;
    const closed = await runPipeline(await envWith(await storedRow({ fail_mode: "block" })), { prompt: "p", model: "m", ray: null }, down);
    expect(closed!.results[0]).toMatchObject({ outcome: "error" });
    expect(closed!.results[0].failedOpen).toBeUndefined();
    expect(closed!.stoppedBy).toBe("prisma-airs");
    const open = await runPipeline(await envWith(await storedRow({ fail_mode: "allow" })), { prompt: "p", model: "m", ray: null }, down);
    expect(open!.results[0]).toMatchObject({ outcome: "error", failedOpen: true });
    expect(open!.stoppedBy).toBeNull();
  });

  it("reports a key that no longer decrypts (secret rotated) as an error, not a silent pass", async () => {
    const otherSecret = btoa(String.fromCharCode(...Array.from({ length: 32 }, () => 7)));
    const r = await runPipeline(await envWith(await storedRow(), otherSecret), { prompt: "p", model: "m", ray: null });
    expect(r!.results[0]).toMatchObject({ outcome: "error" });
    expect(r!.results[0].error).toMatch(/could not be decrypted/);
    expect(r!.stoppedBy).toBe("prisma-airs");
  });

  it("guardrail-only applies with nothing enabled, and even without the secret — it is about the model", async () => {
    const never = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const pipe = { mode: "sequential", guardrail_only: 1, provider_order: "" };
    const a = await runPipeline(await envWith(null, SECRET, pipe), { prompt: "p", model: "m", ray: null }, never);
    expect(a).toMatchObject({ guardrailOnly: true, results: [], stoppedBy: null });
    const b = await runPipeline(await envWith(await storedRow(), null, pipe), { prompt: "p", model: "m", ray: null }, never);
    expect(b).toMatchObject({ guardrailOnly: true, results: [] });
  });

  it("runs enabled providers in the STORED order, not the order D1 returns rows in", async () => {
    // Two enabled rows, returned AIRS-first. The stored order puts CrowdStrike
    // first and it blocks, which ends a sequential pipeline — so the only host
    // called is CrowdStrike's, and AIRS never runs.
    const aidrRow = await storedRow({
      provider: "crowdstrike-aidr",
      region: "eu-1",
      profile_name: "",
      api_key_enc: await encryptSecret("pts_token", SECRET, "crowdstrike-aidr"),
    });
    const rows = [await storedRow(), aidrRow];
    const env = {
      GUARDRAIL_SECRET_KEY: SECRET,
      DB: {
        prepare: (sql: string) => ({
          first: async () =>
            sql.includes("guardrail_pipeline") ? { mode: "sequential", guardrail_only: 0, provider_order: "crowdstrike-aidr,prisma-airs" } : null,
          all: async () => ({ results: rows }),
        }),
      } as unknown as D1Database,
    } as Env;
    const called: string[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      called.push(url);
      expect((init?.headers as Record<string, string>).authorization).toBe("Bearer pts_token");
      return Response.json({ status: "Success", result: { blocked: true, detectors: { malicious_prompt: { detected: true } } } });
    }) as typeof fetch;
    const r = await runPipeline(env, { prompt: "p", model: "m", ray: null }, fetchImpl);
    expect(called).toEqual(["https://api.eu-1.crowdstrike.com/aidr/aiguard/v1/guard_chat_completions"]);
    expect(r!.results.map((x) => [x.provider, x.outcome])).toEqual([["crowdstrike-aidr", "block"]]);
    expect(r!.stoppedBy).toBe("crowdstrike-aidr");
    expect(r!.notRun.map((x) => x.provider)).toEqual(["prisma-airs"]);
  });

  it("reads mode and order from the stored pipeline row", async () => {
    const fetchImpl = (async () => Response.json({ action: "allow", category: "benign" })) as typeof fetch;
    const pipe = { mode: "parallel", guardrail_only: 0, provider_order: "crowdstrike-aidr,prisma-airs" };
    const r = await runPipeline(await envWith(await storedRow(), SECRET, pipe), { prompt: "p", model: "m", ray: null }, fetchImpl);
    expect(r).toMatchObject({ mode: "parallel", guardrailOnly: false, stoppedBy: null });
  });

  // ── design J: the reply check ──────────────────────────────────────────────
  const REPLIES_ON = { mode: "sequential", guardrail_only: 0, provider_order: "", scan_replies: 1 };

  it("checks a reply only when the switch is on AND an enabled guardrail can check one", async () => {
    expect(willCheckReply(await loadGuardrailSetup(await envWith(await storedRow(), SECRET, REPLIES_ON)))).toBe(true);
    // Switch off (and a row from before migration 0008, with no column at all).
    expect(willCheckReply(await loadGuardrailSetup(await envWith(await storedRow(), SECRET, { ...REPLIES_ON, scan_replies: 0 })))).toBe(false);
    const { scan_replies: _, ...preMigration } = REPLIES_ON;
    expect(willCheckReply(await loadGuardrailSetup(await envWith(await storedRow(), SECRET, preMigration)))).toBe(false);
    // On, but only Cato is enabled, and Cato does not document reply checking: the
    // switch changes nothing, so the turn must not lose its streaming for nothing.
    const cato = await storedRow({ provider: "cato-ai-security", region: "global", api_key_enc: await encryptSecret("k", SECRET, "cato-ai-security") });
    expect(willCheckReply(await loadGuardrailSetup(await envWith(cato, SECRET, REPLIES_ON)))).toBe(false);
    expect(willCheckReply(null)).toBe(false);
  });

  it("sends the reply beside its prompt, and the prompt check never sends a reply", async () => {
    const bodies: Record<string, unknown>[] = [];
    const fetchImpl = (async (_u: string, init?: RequestInit) => {
      bodies.push(JSON.parse(init!.body as string));
      return Response.json({ action: "block", response_detected: { dlp: true } });
    }) as typeof fetch;
    const env = await envWith(await storedRow(), SECRET, REPLIES_ON);
    const setup = await loadGuardrailSetup(env);
    const rc = await runReplyCheck(env, setup, { prompt: "p", response: "the reply", model: "m", ray: null }, fetchImpl);
    expect(bodies[0].contents).toEqual([{ prompt: "p", response: "the reply" }]);
    expect(rc).toMatchObject({ direction: "reply", stoppedBy: "prisma-airs", guardrailOnly: false });
    expect(rc!.results[0].detected).toEqual(["dlp"]);
    // A stray `response` on the prompt check's input is dropped, never scanned as a prompt check.
    await runPipeline(env, { prompt: "p", response: "leak", model: "m", ray: null }, fetchImpl, { setup });
    expect(bodies[1].contents).toEqual([{ prompt: "p" }]);
  });

  // Datadog: both decrypted keys, each in its own header, to the chosen site only — and the second
  // ciphertext is bound to its slot, so the two cannot be swapped and still work.
  it("sends both Datadog keys to the configured site, and refuses swapped ciphertexts", async () => {
    const ddRow = async (over: Record<string, unknown> = {}) =>
      storedRow({
        provider: "datadog-ai-guard",
        region: "eu1",
        profile_name: "",
        api_key_enc: await encryptSecret("dd-api-key", SECRET, "datadog-ai-guard"),
        second_key_enc: await encryptSecret("dd-app-key", SECRET, secondKeyAad("datadog-ai-guard")),
        ...over,
      });
    let seen: { url: string; headers: Record<string, string> } | null = null;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      seen = { url, headers: init?.headers as Record<string, string> };
      return Response.json({ data: { id: "e1", type: "evaluations", attributes: { action: "ALLOW", is_blocking_enabled: true, tags: [] } } });
    }) as typeof fetch;
    const r = await runPipeline(await envWith(await ddRow()), { prompt: "p", model: "m", ray: "abc" }, fetchImpl);
    expect(r!.results[0]).toMatchObject({ provider: "datadog-ai-guard", outcome: "allow", scanId: "e1" });
    expect(seen!.url).toBe("https://app.datadoghq.eu/api/v2/ai-guard/evaluate");
    expect([seen!.headers["dd-api-key"], seen!.headers["dd-application-key"]]).toEqual(["dd-api-key", "dd-app-key"]);

    const never = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    // The API key's ciphertext copied into the second slot: its AAD does not match, so nothing is sent.
    const swapped = await ddRow({ second_key_enc: await encryptSecret("dd-api-key", SECRET, "datadog-ai-guard") });
    const s = await runPipeline(await envWith(swapped), { prompt: "p", model: "m", ray: null }, never);
    expect(s!.results[0]).toMatchObject({ outcome: "error", error: expect.stringMatching(/could not be decrypted/) });
    // A row with no second key (e.g. saved before migration 0009): an error for the fail mode, no call.
    const half = await ddRow({ second_key_enc: null });
    const h = await runPipeline(await envWith(half), { prompt: "p", model: "m", ray: null }, never);
    expect(h!.results[0]).toMatchObject({ outcome: "error", error: "No application key saved" });
  });

  it("no reply check → null, never an empty pass", async () => {
    const never = (async () => {
      throw new Error("must not be called");
    }) as typeof fetch;
    const env = await envWith(await storedRow(), SECRET, { ...REPLIES_ON, scan_replies: 0 });
    expect(await runReplyCheck(env, await loadGuardrailSetup(env), { prompt: "p", response: "r", model: "m", ray: null }, never)).toBeNull();
  });
});

describe("executePipeline — reply direction", () => {
  const A = { ...defaultConfig("prisma-airs"), enabled: true };
  const L = { ...defaultConfig("lakera-guard"), enabled: true };
  const CATO = { ...defaultConfig("cato-ai-security"), enabled: true };
  const allow: Scan = async (c) => ({ provider: c.provider, outcome: "allow", latencyMs: 1 });
  const blockAirs: Scan = async (c) => ({ provider: c.provider, outcome: c.provider === "prisma-airs" ? "block" : "allow", latencyMs: 1 });

  it("lists a guardrail that cannot check a reply as not run, with the reason — never as an allow", async () => {
    const out = await executePipeline([A], "parallel", false, allow, Date.now, "reply", [CATO]);
    expect(out.direction).toBe("reply");
    expect(out.results.map((r) => r.provider)).toEqual(["prisma-airs"]);
    expect(out.notRun).toEqual([
      { provider: "cato-ai-security", reason: expect.stringMatching(/Cato Networks AI Security does not check replies here/) },
    ]);
  });

  it("a sequential reply block names the reply, not the prompt", async () => {
    const out = await executePipeline([A, L], "sequential", false, blockAirs, Date.now, "reply");
    expect(out.stoppedBy).toBe("prisma-airs");
    expect(out.notRun).toEqual([{ provider: "lakera-guard", reason: "Not run: Palo Alto Networks Prisma AIRS blocked the reply" }]);
  });

  it("a prompt pipeline carries no direction (every result before design J)", async () => {
    expect((await executePipeline([A], "parallel", false, allow)).direction).toBeUndefined();
  });

  it("only documented vendors claim reply checking", () => {
    expect(PROVIDER_IDS.filter((p) => PROVIDERS[p].replyCheck)).toEqual([
      "prisma-airs",
      "crowdstrike-aidr",
      "lakera-guard",
      "datadog-ai-guard",
    ]);
  });

  it("validates the switch", () => {
    const v = validatePipelineUpdate({ scanReplies: true }, defaultPipeline());
    expect(v.ok && v.next.scanReplies).toBe(true);
    expect(validatePipelineUpdate({ scanReplies: "yes" }, defaultPipeline()).ok).toBe(false);
  });
});
