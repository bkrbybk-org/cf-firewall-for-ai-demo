// External guardrails: configuration, encrypted key storage, and the per-prompt
// forwarding step handleChat runs before the model.
//
// Design decisions, each one load-bearing:
//   - **Endpoints are an allowlist of the provider's official hosts**, chosen by
//     region — never free text. The API key travels in a request header, so a
//     typed URL would let anyone who can reach /api/external-guardrails (which on
//     prod includes the red-team scanner's Access service token, not only humans)
//     point the stored key at their own server. It also rules out SSRF.
//   - **The API key is write-only.** It is encrypted (AES-256-GCM) with the
//     GUARDRAIL_SECRET_KEY Worker secret before it reaches D1, and no endpoint
//     ever returns it — only `apiKeyLast4`. Without the secret the config refuses
//     to store a key at all rather than falling back to plaintext.
//   - **At most one provider is enabled**, enforced by a unique partial index in
//     D1 (migrations/0005), not just by the UI.
//   - **An error is never a verdict.** If the provider cannot be consulted, the
//     operator's fail mode decides: "block" (default, fail closed) stops the turn
//     and says the guardrail was unavailable; "allow" lets it through and marks
//     it `failedOpen` so the reply shows it was not scanned.

import { PRISMA_AIRS_REGIONS, PRISMA_AIRS_SCAN_PATH, scanPromptWithPrismaAirs } from "./prismaAirs";
import type { Env, ExternalGuardrailProvider, ExternalGuardrailResult } from "./types";

// ── provider registry ────────────────────────────────────────────────────────
interface ProviderSpec {
  label: string;
  supported: boolean;
  regions: readonly { id: string; label: string; url: string }[];
  defaultRegion: string;
  scanPath: string;
}

export const PROVIDERS: Record<ExternalGuardrailProvider, ProviderSpec> = {
  "prisma-airs": {
    label: "Palo Alto Networks Prisma AIRS",
    supported: true,
    regions: PRISMA_AIRS_REGIONS,
    defaultRegion: "us",
    scanPath: PRISMA_AIRS_SCAN_PATH,
  },
  // Listed so the page shows where the next integration goes. Not callable:
  // `supported: false` is rejected by validateUpdate before anything is stored.
  "crowdstrike-aidr": { label: "CrowdStrike AIDR", supported: false, regions: [], defaultRegion: "", scanPath: "" },
};

export const PROVIDER_IDS = Object.keys(PROVIDERS) as ExternalGuardrailProvider[];
export const FAIL_MODES = ["block", "allow"] as const;
export type FailMode = (typeof FAIL_MODES)[number];

const MAX_PROFILE_NAME = 200;
const MAX_API_KEY = 4096;

// ── stored row ↔ public config ───────────────────────────────────────────────
export interface StoredConfig {
  provider: ExternalGuardrailProvider;
  enabled: boolean;
  region: string;
  profileName: string;
  failMode: FailMode;
  apiKeyEnc: string | null;
  apiKeyLast4: string | null;
  updatedAt: number | null;
}

export function defaultConfig(provider: ExternalGuardrailProvider): StoredConfig {
  return {
    provider,
    enabled: false,
    region: PROVIDERS[provider].defaultRegion,
    profileName: "",
    failMode: "block",
    apiKeyEnc: null,
    apiKeyLast4: null,
    updatedAt: null,
  };
}

export function endpointFor(provider: ExternalGuardrailProvider, region: string): string {
  const spec = PROVIDERS[provider];
  const r = spec.regions.find((x) => x.id === region);
  return r ? r.url + spec.scanPath : "";
}

// What the client sees. Built field by field — never by spreading the stored
// row — so the encrypted key cannot leak through a field added later.
export function toPublicConfig(c: StoredConfig) {
  const spec = PROVIDERS[c.provider];
  return {
    provider: c.provider,
    label: spec.label,
    supported: spec.supported,
    enabled: c.enabled,
    region: c.region,
    endpoint: endpointFor(c.provider, c.region),
    regions: spec.regions.map((r) => ({ id: r.id, label: r.label, url: r.url })),
    profileName: c.profileName,
    failMode: c.failMode,
    apiKeySet: c.apiKeyEnc != null,
    apiKeyLast4: c.apiKeyLast4,
    updatedAt: c.updatedAt,
  };
}

// ── update validation (pure) ─────────────────────────────────────────────────
export type UpdateResult =
  | { ok: true; next: StoredConfig; newApiKey: string | null }
  | { ok: false; error: string };

// Applies a PUT body to the current stored config. Everything the client sends
// is checked here; the caller only encrypts `newApiKey` and writes `next`.
export function validateUpdate(body: unknown, current: StoredConfig): UpdateResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "Body must be a JSON object" };
  const b = body as Record<string, unknown>;
  const spec = PROVIDERS[current.provider];
  if (!spec.supported) return { ok: false, error: `${spec.label} is not supported yet` };

  const next: StoredConfig = { ...current };
  let newApiKey: string | null = null;

  if (b.region !== undefined) {
    if (typeof b.region !== "string" || !spec.regions.some((r) => r.id === b.region)) {
      return { ok: false, error: `region must be one of: ${spec.regions.map((r) => r.id).join(", ")}` };
    }
    next.region = b.region;
  }
  if (b.profileName !== undefined) {
    if (typeof b.profileName !== "string") return { ok: false, error: "profileName must be a string" };
    const name = b.profileName.trim();
    if (name.length > MAX_PROFILE_NAME) return { ok: false, error: `profileName exceeds ${MAX_PROFILE_NAME} characters` };
    next.profileName = name;
  }
  if (b.failMode !== undefined) {
    if (!(FAIL_MODES as readonly unknown[]).includes(b.failMode)) return { ok: false, error: 'failMode must be "block" or "allow"' };
    next.failMode = b.failMode as FailMode;
  }
  if (b.clearApiKey === true) {
    next.apiKeyEnc = null;
    next.apiKeyLast4 = null;
    // A provider with no key cannot scan anything, so leaving it "enabled"
    // would turn every chat into a fail-mode decision. Disable it instead.
    next.enabled = false;
  } else if (b.apiKey !== undefined) {
    if (typeof b.apiKey !== "string") return { ok: false, error: "apiKey must be a string" };
    const key = b.apiKey.trim();
    // Empty means "keep the existing key" — the form submits an empty field
    // whenever the user did not type a new one.
    if (key) {
      if (key.length > MAX_API_KEY) return { ok: false, error: `apiKey exceeds ${MAX_API_KEY} characters` };
      if (/\s/.test(key)) return { ok: false, error: "apiKey must not contain whitespace" };
      newApiKey = key;
      next.apiKeyLast4 = key.slice(-4);
    }
  }
  if (b.enabled !== undefined) {
    if (typeof b.enabled !== "boolean") return { ok: false, error: "enabled must be a boolean" };
    next.enabled = b.enabled;
  }
  // Refuse to enable something that cannot work, instead of letting every chat
  // turn fall through to the fail mode.
  if (next.enabled) {
    const hasKey = newApiKey != null || next.apiKeyEnc != null;
    if (!hasKey) return { ok: false, error: "Cannot enable: save an API key first" };
    if (!next.profileName) return { ok: false, error: "Cannot enable: an AI security profile name is required" };
  }
  return { ok: true, next, newApiKey };
}

// ── encryption (AES-256-GCM) ────────────────────────────────────────────────
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function importKey(secretB64: string): Promise<CryptoKey> {
  let raw: Uint8Array;
  try {
    raw = b64ToBytes(secretB64.trim());
  } catch {
    throw new Error("GUARDRAIL_SECRET_KEY is not valid base64");
  }
  if (raw.length !== 32) throw new Error(`GUARDRAIL_SECRET_KEY must decode to 32 bytes (got ${raw.length})`);
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// The provider id is bound in as additional authenticated data, so a ciphertext
// copied onto another provider's row fails to decrypt instead of being used.
export async function encryptSecret(plaintext: string, secretB64: string, aad: string): Promise<string> {
  const key = await importKey(secretB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, new TextEncoder().encode(plaintext)),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return bytesToB64(out);
}

export async function decryptSecret(blobB64: string, secretB64: string, aad: string): Promise<string> {
  const key = await importKey(secretB64);
  const blob = b64ToBytes(blobB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12), additionalData: new TextEncoder().encode(aad) },
    key,
    blob.slice(12),
  );
  return new TextDecoder().decode(pt);
}

// ── D1 ───────────────────────────────────────────────────────────────────────
interface Row {
  provider: string;
  enabled: number;
  region: string;
  profile_name: string | null;
  fail_mode: string;
  api_key_enc: string | null;
  api_key_last4: string | null;
  updated_at: number | null;
}

function fromRow(r: Row): StoredConfig | null {
  if (!(PROVIDER_IDS as string[]).includes(r.provider)) return null;
  const provider = r.provider as ExternalGuardrailProvider;
  return {
    provider,
    enabled: r.enabled === 1,
    region: r.region,
    profileName: r.profile_name ?? "",
    failMode: r.fail_mode === "allow" ? "allow" : "block",
    apiKeyEnc: r.api_key_enc,
    apiKeyLast4: r.api_key_last4,
    updatedAt: r.updated_at,
  };
}

// Every known provider, stored row or default.
export async function loadAll(db: D1Database): Promise<StoredConfig[]> {
  const { results } = await db.prepare("SELECT * FROM external_guardrails").all<Row>();
  const stored = new Map((results ?? []).map(fromRow).filter((c): c is StoredConfig => c != null).map((c) => [c.provider, c]));
  return PROVIDER_IDS.map((id) => stored.get(id) ?? defaultConfig(id));
}

export async function save(db: D1Database, c: StoredConfig): Promise<void> {
  const upsert = db
    .prepare(
      `INSERT INTO external_guardrails (provider, enabled, region, profile_name, fail_mode, api_key_enc, api_key_last4, updated_at)
       VALUES (?,?,?,?,?,?,?,?)
       ON CONFLICT(provider) DO UPDATE SET enabled = excluded.enabled, region = excluded.region,
         profile_name = excluded.profile_name, fail_mode = excluded.fail_mode, api_key_enc = excluded.api_key_enc,
         api_key_last4 = excluded.api_key_last4, updated_at = excluded.updated_at`,
    )
    .bind(c.provider, c.enabled ? 1 : 0, c.region, c.profileName, c.failMode, c.apiKeyEnc, c.apiKeyLast4, c.updatedAt);
  // Disable every other provider FIRST, in the same batch: the unique partial
  // index allows one enabled row, so the order is what makes switching
  // providers a single atomic step rather than a constraint violation.
  const statements = c.enabled
    ? [db.prepare("UPDATE external_guardrails SET enabled = 0 WHERE provider <> ? AND enabled = 1").bind(c.provider), upsert]
    : [upsert];
  await db.batch(statements);
}

// ── the forwarding step ──────────────────────────────────────────────────────
export interface ForwardInput {
  prompt: string;
  model: string;
  ray: string | null;
}

// null → no provider enabled (or the feature is not set up): chat proceeds
// exactly as before, with no external call and no added latency beyond one D1
// read. Otherwise the result, with `failedOpen` already resolved.
export async function forwardPrompt(
  env: Env,
  input: ForwardInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult | null> {
  if (!env.DB || !env.GUARDRAIL_SECRET_KEY) return null;
  let active: StoredConfig | null = null;
  try {
    const row = await env.DB.prepare("SELECT * FROM external_guardrails WHERE enabled = 1 LIMIT 1").first<Row>();
    active = row ? fromRow(row) : null;
  } catch {
    // Table missing (migration not applied) reads as "nothing enabled". An
    // ENABLED provider whose config cannot be read is handled below, as an error.
    return null;
  }
  if (!active || !active.apiKeyEnc) return null;

  const resolve = (r: ExternalGuardrailResult): ExternalGuardrailResult =>
    r.outcome === "error" && active!.failMode === "allow" ? { ...r, failedOpen: true } : r;

  let apiKey: string;
  try {
    apiKey = await decryptSecret(active.apiKeyEnc, env.GUARDRAIL_SECRET_KEY, active.provider);
  } catch {
    return resolve({
      provider: active.provider,
      outcome: "error",
      error: "Stored API key could not be decrypted — GUARDRAIL_SECRET_KEY changed since it was saved. Re-enter the key.",
      latencyMs: 0,
    });
  }

  if (active.provider === "prisma-airs") {
    const baseUrl = PROVIDERS[active.provider].regions.find((r) => r.id === active!.region)?.url;
    if (!baseUrl) return resolve({ provider: active.provider, outcome: "error", error: `Unknown region "${active.region}"`, latencyMs: 0 });
    return resolve(
      await scanPromptWithPrismaAirs(
        { baseUrl, apiKey, profileName: active.profileName, prompt: input.prompt, model: input.model, trId: input.ray ?? undefined },
        fetchImpl,
      ),
    );
  }
  return resolve({ provider: active.provider, outcome: "error", error: `${PROVIDERS[active.provider].label} is not supported yet`, latencyMs: 0 });
}

// Whether a result stops the turn: a block, or an error with fail-closed.
export function stopsTurn(r: ExternalGuardrailResult): boolean {
  return r.outcome === "block" || (r.outcome === "error" && !r.failedOpen);
}
