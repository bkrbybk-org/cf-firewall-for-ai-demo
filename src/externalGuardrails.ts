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
//   - **Any number of providers may be enabled; a pipeline decides how they run**
//     (migrations/0006 dropped 0005's one-enabled index). Sequential runs them
//     in the operator's order and stops at the first that stops the turn;
//     parallel runs them together and lets the model run only if every one lets
//     it through. Either way the edge WAF has already run (before this Worker),
//     and AI Gateway Guardrails run later, inside the model call — the pipeline
//     can only order what sits between the two, and the UI says so.
//   - **Guardrail-only mode stops before the model**, for testing the checks
//     without model cost. It must never look like a model answer.
//   - **An error is never a verdict.** If the provider cannot be consulted, the
//     operator's fail mode decides: "block" (default, fail closed) stops the turn
//     and says the guardrail was unavailable; "allow" lets it through and marks
//     it `failedOpen` so the reply shows it was not scanned.

import { CATO_GUARD_PATH, CATO_REGIONS, scanPromptWithCato } from "./catoGuard";
import { CISCO_AID_INSPECT_PATH, CISCO_AID_REGIONS, scanPromptWithCiscoAid } from "./ciscoAiDefense";
import { AIDR_GUARD_PATH, AIDR_REGIONS, scanPromptWithAidr } from "./crowdstrikeAidr";
import { LAKERA_GUARD_PATH, LAKERA_REGIONS, scanPromptWithLakera } from "./lakeraGuard";
import { PRISMA_AIRS_REGIONS, PRISMA_AIRS_SCAN_PATH, scanPromptWithPrismaAirs } from "./prismaAirs";
import { PublicError } from "./publicError";
import type {
  Env,
  ExternalGuardrailProvider,
  ExternalGuardrailResult,
  GuardrailPipelineConfig,
  GuardrailPipelineMode,
  GuardrailPipelineResult,
  GuardrailRawResponse,
} from "./types";

// ── provider registry ────────────────────────────────────────────────────────
interface ProviderSpec {
  label: string;
  // false → listed for context but rejected by validateUpdate before anything
  // is stored. Kept for the next integration, even though every provider in
  // the registry is supported today.
  supported: boolean;
  // Parser checked against a REAL payload from this vendor. An unverified provider can be
  // configured and tested (that is how it gets verified) and the page says it is unverified;
  // until then its verdict fields are what the vendor documents, not what it was seen to send.
  verified: boolean;
  regions: readonly { id: string; label: string; url: string }[];
  defaultRegion: string;
  scanPath: string;
  // Prisma AIRS names an AI security profile in every request and Lakera Guard a
  // project; CrowdStrike AIDR and Cisco AI Defense take the policy from the key, so
  // they have nothing to name. `profileLabel` is what the named thing is called.
  requiresProfile: boolean;
  profileLabel: string;
  keyLabel: string;
  vendor: string;
  // Response fields whose VALUE *Test connection* may show, when it is a bare token
  // (src/responseShape.ts). Only for a verdict that is a string with an undocumented
  // allow value; everything else stays names and types.
  revealPaths?: readonly string[];
}

export const PROVIDERS: Record<ExternalGuardrailProvider, ProviderSpec> = {
  "prisma-airs": {
    label: "Palo Alto Networks Prisma AIRS",
    supported: true,
    verified: true,
    regions: PRISMA_AIRS_REGIONS,
    defaultRegion: "us",
    scanPath: PRISMA_AIRS_SCAN_PATH,
    requiresProfile: true,
    profileLabel: "AI security profile name",
    keyLabel: "API key",
    vendor: "Palo Alto Networks",
  },
  "crowdstrike-aidr": {
    label: "CrowdStrike Falcon AIDR",
    supported: true,
    verified: true,
    regions: AIDR_REGIONS,
    defaultRegion: "us-1",
    scanPath: AIDR_GUARD_PATH,
    requiresProfile: false,
    profileLabel: "",
    keyLabel: "Collector token",
    vendor: "CrowdStrike",
  },
  // Built from the vendor docs; unverified until the admin runs Test connection with a real key and the
  // returned response shape matches the parser (PROGRESS.md plan, step 6).
  "cisco-ai-defense": {
    label: "Cisco AI Defense",
    supported: true,
    verified: false,
    regions: CISCO_AID_REGIONS,
    defaultRegion: "us",
    scanPath: CISCO_AID_INSPECT_PATH,
    requiresProfile: false,
    profileLabel: "",
    keyLabel: "API key",
    vendor: "Cisco",
  },
  "lakera-guard": {
    label: "Check Point Lakera Guard",
    supported: true,
    verified: false,
    regions: LAKERA_REGIONS,
    defaultRegion: "global",
    scanPath: LAKERA_GUARD_PATH,
    requiresProfile: true,
    profileLabel: "Project ID",
    keyLabel: "API key",
    vendor: "Lakera (Check Point)",
  },
  // The ALLOW is checked against real payloads (2026-10-06: `required_action: null`); the
  // BLOCK is still only Cato's console sample, so it stays unverified until a prompt the
  // Guard's policies act on has been seen. That verdict is a STRING
  // (`required_action.action_type`), so Test connection may show that one field's value.
  "cato-ai-security": {
    label: "Cato Networks AI Security",
    supported: true,
    verified: false,
    regions: CATO_REGIONS,
    defaultRegion: "global",
    scanPath: CATO_GUARD_PATH,
    requiresProfile: false,
    profileLabel: "",
    keyLabel: "API key",
    vendor: "Cato Networks",
    revealPaths: ["required_action.action_type"],
  },
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
    verified: spec.verified,
    enabled: c.enabled,
    region: c.region,
    endpoint: endpointFor(c.provider, c.region),
    regions: spec.regions.map((r) => ({ id: r.id, label: r.label, url: r.url })),
    profileName: c.profileName,
    requiresProfile: spec.requiresProfile,
    profileLabel: spec.profileLabel,
    keyLabel: spec.keyLabel,
    vendor: spec.vendor,
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
    if (!hasKey) return { ok: false, error: `Cannot enable: save ${spec.keyLabel === "API key" ? "an API key" : `a ${spec.keyLabel.toLowerCase()}`} first` };
    if (spec.requiresProfile && !next.profileName) {
      // "an AI security profile name" / "a project ID": lowercase the first letter
      // unless the word is an acronym, and pick the article from the result.
      const l = spec.profileLabel;
      const noun = /^[A-Z]{2}/.test(l) ? l : l.charAt(0).toLowerCase() + l.slice(1);
      return { ok: false, error: `Cannot enable: ${/^[aeiou]/i.test(noun) ? "an" : "a"} ${noun} is required` };
    }
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
    throw new PublicError("GUARDRAIL_SECRET_KEY is not valid base64");
  }
  if (raw.length !== 32) throw new PublicError(`GUARDRAIL_SECRET_KEY must decode to 32 bytes (got ${raw.length})`);
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
  await upsert.run();
}

// ── pipeline configuration ───────────────────────────────────────────────────
export const PIPELINE_MODES = ["sequential", "parallel"] as const satisfies readonly GuardrailPipelineMode[];

export function defaultPipeline(): GuardrailPipelineConfig {
  return { mode: "sequential", guardrailOnly: false, order: [...PROVIDER_IDS] };
}

// Stored order → a full permutation of the registry: unknown ids dropped,
// duplicates removed, providers missing from the stored list appended in
// registry order. A provider added in code later therefore always has a place,
// and a hand-edited row can never make a provider vanish from the pipeline.
export function normalizeOrder(stored: readonly string[]): ExternalGuardrailProvider[] {
  const seen = new Set<ExternalGuardrailProvider>();
  for (const id of stored) if ((PROVIDER_IDS as string[]).includes(id)) seen.add(id as ExternalGuardrailProvider);
  for (const id of PROVIDER_IDS) seen.add(id);
  return [...seen];
}

export type PipelineUpdateResult = { ok: true; next: GuardrailPipelineConfig } | { ok: false; error: string };

export function validatePipelineUpdate(body: unknown, current: GuardrailPipelineConfig): PipelineUpdateResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "Body must be a JSON object" };
  const b = body as Record<string, unknown>;
  const next: GuardrailPipelineConfig = { ...current, order: [...current.order] };
  if (b.mode !== undefined) {
    if (!(PIPELINE_MODES as readonly unknown[]).includes(b.mode)) return { ok: false, error: 'mode must be "sequential" or "parallel"' };
    next.mode = b.mode as GuardrailPipelineMode;
  }
  if (b.guardrailOnly !== undefined) {
    if (typeof b.guardrailOnly !== "boolean") return { ok: false, error: "guardrailOnly must be a boolean" };
    next.guardrailOnly = b.guardrailOnly;
  }
  if (b.order !== undefined) {
    // Strict on input (lenient only on read): an order that is not exactly a
    // permutation is a client bug, and silently "fixing" it would save an order
    // the operator never chose.
    const o = b.order;
    const valid =
      Array.isArray(o) &&
      o.length === PROVIDER_IDS.length &&
      new Set(o).size === o.length &&
      o.every((x) => typeof x === "string" && (PROVIDER_IDS as string[]).includes(x));
    if (!valid) return { ok: false, error: `order must list each of ${PROVIDER_IDS.join(", ")} exactly once` };
    next.order = o as ExternalGuardrailProvider[];
  }
  return { ok: true, next };
}

interface PipelineRow {
  mode: string;
  guardrail_only: number;
  provider_order: string;
}

function pipelineFromRow(r: PipelineRow | null): GuardrailPipelineConfig {
  if (!r) return defaultPipeline();
  return {
    mode: r.mode === "parallel" ? "parallel" : "sequential",
    guardrailOnly: r.guardrail_only === 1,
    order: normalizeOrder(r.provider_order ? r.provider_order.split(",") : []),
  };
}

// Missing table (migration 0006 not applied) reads as the defaults, which is
// exactly how the app behaved before the pipeline existed.
export async function loadPipeline(db: D1Database): Promise<GuardrailPipelineConfig> {
  try {
    return pipelineFromRow(await db.prepare("SELECT * FROM guardrail_pipeline WHERE id = 1").first<PipelineRow>());
  } catch (err) {
    if (/no such table/i.test(err instanceof Error ? err.message : String(err))) return defaultPipeline();
    throw err;
  }
}

export async function savePipeline(db: D1Database, p: GuardrailPipelineConfig): Promise<void> {
  await db
    .prepare(
      `INSERT INTO guardrail_pipeline (id, mode, guardrail_only, provider_order, updated_at) VALUES (1,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET mode = excluded.mode, guardrail_only = excluded.guardrail_only,
         provider_order = excluded.provider_order, updated_at = excluded.updated_at`,
    )
    .bind(p.mode, p.guardrailOnly ? 1 : 0, p.order.join(","), Date.now())
    .run();
}

// ── the forwarding step ──────────────────────────────────────────────────────
export interface ForwardInput {
  prompt: string;
  model: string;
  ray: string | null;
}

// Whether a result stops the turn: a block, or an error with fail-closed.
export function stopsTurn(r: ExternalGuardrailResult): boolean {
  return r.outcome === "block" || (r.outcome === "error" && !r.failedOpen);
}

// One provider's scan, with `failedOpen` already resolved. Never throws.
export type Scan = (c: StoredConfig) => Promise<ExternalGuardrailResult>;

// The pipeline itself, separated from D1 and fetch so its ordering and
// short-circuit rules can be tested with fake scans. `steps` are the ENABLED
// providers, already in the configured order.
export async function executePipeline(
  steps: StoredConfig[],
  mode: GuardrailPipelineMode,
  guardrailOnly: boolean,
  scan: Scan,
  now: () => number = Date.now,
): Promise<GuardrailPipelineResult> {
  const started = now();
  const results: ExternalGuardrailResult[] = [];
  const notRun: GuardrailPipelineResult["notRun"] = [];
  let stoppedBy: ExternalGuardrailProvider | null = null;

  if (mode === "parallel") {
    // Wait for ALL of them, not just the first block: each call is capped by its
    // own timeout, and the point of running two guardrails side by side is to
    // see both verdicts. Results keep configured order, not arrival order.
    results.push(...(await Promise.all(steps.map((s) => scan(s)))));
    stoppedBy = results.find(stopsTurn)?.provider ?? null;
  } else {
    for (let i = 0; i < steps.length; i++) {
      const r = await scan(steps[i]);
      results.push(r);
      if (stopsTurn(r)) {
        stoppedBy = r.provider;
        const label = PROVIDERS[r.provider].label;
        const why = r.outcome === "block" ? `${label} blocked the prompt` : `${label} was unavailable (fail closed)`;
        for (const s of steps.slice(i + 1)) notRun.push({ provider: s.provider, reason: `Not run: ${why}` });
        break;
      }
    }
  }
  return { mode, guardrailOnly, results, notRun, stoppedBy, latencyMs: now() - started };
}

// ── raw responses (opt-in, per request) ─────────────────────────────────────
// The chat card can show each vendor's response as it came back, for whoever asked
// (`includeRaw` on their own /api/chat call). What is recorded is the RESPONSE body
// only — never the request, which carries the API key — and it can quote the prompt
// and whatever the vendor detected (Cato's `detection_message` repeats the SSN). So it
// rides in that one JSON response and nowhere else: stripRaw() keeps it out of the
// x-external-guardrails header, and nothing that stores or exports a pipeline reads
// it (the prompt log stores no pipeline; saved runs and exports pick fields).
export const RAW_MAX_CHARS = 32_000;

async function readRaw(res: Response): Promise<GuardrailRawResponse> {
  const text = await res.clone().text();
  if (text.length > RAW_MAX_CHARS) return { status: res.status, body: text.slice(0, RAW_MAX_CHARS), json: false, truncated: true };
  try {
    return { status: res.status, body: JSON.parse(text), json: true, truncated: false };
  } catch {
    return { status: res.status, body: text, json: false, truncated: false };
  }
}

// Wraps one provider's fetch so its last response is kept. Best effort: reading the
// copy can never change or fail the verdict, which is parsed from the original.
function recordingFetch(base: typeof fetch, sink: { raw?: GuardrailRawResponse }): typeof fetch {
  return async (input, init) => {
    const res = await base(input, init);
    try {
      sink.raw = await readRaw(res);
    } catch {
      // no raw for this one; the verdict is unaffected
    }
    return res;
  };
}

export function stripRaw(p: GuardrailPipelineResult): GuardrailPipelineResult {
  return { ...p, results: p.results.map(({ raw: _raw, ...r }) => r) };
}

// The real scan for one stored provider config.
async function scanProvider(
  env: Env,
  c: StoredConfig,
  input: ForwardInput,
  fetchImpl: typeof fetch,
  captureRaw = false,
): Promise<ExternalGuardrailResult> {
  if (captureRaw) {
    const sink: { raw?: GuardrailRawResponse } = {};
    const r = await scanProvider(env, c, input, recordingFetch(fetchImpl, sink));
    return sink.raw ? { ...r, raw: sink.raw } : r;
  }
  const resolve = (r: ExternalGuardrailResult): ExternalGuardrailResult =>
    r.outcome === "error" && c.failMode === "allow" ? { ...r, failedOpen: true } : r;
  if (!c.apiKeyEnc) return resolve({ provider: c.provider, outcome: "error", error: "No API key saved", latencyMs: 0 });

  let apiKey: string;
  try {
    apiKey = await decryptSecret(c.apiKeyEnc, env.GUARDRAIL_SECRET_KEY!, c.provider);
  } catch {
    return resolve({
      provider: c.provider,
      outcome: "error",
      error: "Stored API key could not be decrypted — GUARDRAIL_SECRET_KEY changed since it was saved. Re-enter the key.",
      latencyMs: 0,
    });
  }

  return resolve(await scanWithKey(c, apiKey, input, fetchImpl));
}

// One provider's scan with an already-decrypted key. Shared by the pipeline and
// the Test connection endpoint so the two can never call a provider differently.
// The base URL comes ONLY from the provider's region allowlist.
export async function scanWithKey(
  c: StoredConfig,
  apiKey: string,
  input: ForwardInput,
  fetchImpl: typeof fetch = fetch,
): Promise<ExternalGuardrailResult> {
  const spec = PROVIDERS[c.provider];
  if (!spec.supported) return { provider: c.provider, outcome: "error", error: `${spec.label} is not supported yet`, latencyMs: 0 };
  const baseUrl = spec.regions.find((r) => r.id === c.region)?.url;
  if (!baseUrl) return { provider: c.provider, outcome: "error", error: `Unknown region "${c.region}"`, latencyMs: 0 };
  const ray = input.ray ?? undefined;
  switch (c.provider) {
    case "prisma-airs":
      return scanPromptWithPrismaAirs(
        { baseUrl, apiKey, profileName: c.profileName, prompt: input.prompt, model: input.model, trId: ray },
        fetchImpl,
      );
    case "crowdstrike-aidr":
      return scanPromptWithAidr({ baseUrl, token: apiKey, prompt: input.prompt, model: input.model, spanId: ray }, fetchImpl);
    // Both `verified: false` until a real payload has been seen (PROGRESS.md plan,
    // step 6) — the page says so; the parsers follow the vendors' docs.
    case "cisco-ai-defense":
      return scanPromptWithCiscoAid({ baseUrl, apiKey, prompt: input.prompt, transactionId: ray }, fetchImpl);
    case "lakera-guard":
      // The project is the policy, as Prisma AIRS's profile is: profileName holds it.
      return scanPromptWithLakera({ baseUrl, apiKey, projectId: c.profileName, prompt: input.prompt }, fetchImpl);
    case "cato-ai-security":
      // The ray as Cato's session id: one request per session, since the Worker has no
      // conversation id — but it joins Cato's console to the edge verdict and our log.
      return scanPromptWithCato({ baseUrl, apiKey, prompt: input.prompt, sessionId: ray }, fetchImpl);
  }
}

// null → nothing to do: no provider enabled and the model is not skipped (or
// the feature is not set up). Chat then proceeds exactly as before, with no
// external call and no added latency beyond the D1 reads.
export async function runPipeline(
  env: Env,
  input: ForwardInput,
  fetchImpl: typeof fetch = fetch,
  opts: { captureRaw?: boolean } = {},
): Promise<GuardrailPipelineResult | null> {
  if (!env.DB) return null;
  let pipeline: GuardrailPipelineConfig;
  let enabled: StoredConfig[] = [];
  try {
    pipeline = await loadPipeline(env.DB);
    // Without the secret no key can be decrypted, so nothing is scanned — but
    // guardrail-only still applies: it is about the model, not the providers.
    if (env.GUARDRAIL_SECRET_KEY) {
      const { results } = await env.DB.prepare("SELECT * FROM external_guardrails WHERE enabled = 1").all<Row>();
      const byId = new Map(
        (results ?? []).map(fromRow).filter((c): c is StoredConfig => c != null && c.enabled).map((c) => [c.provider, c]),
      );
      enabled = pipeline.order.flatMap((id) => byId.get(id) ?? []);
    }
  } catch {
    // Table missing (migration not applied) reads as "nothing enabled".
    return null;
  }
  if (enabled.length === 0 && !pipeline.guardrailOnly) return null;
  return executePipeline(enabled, pipeline.mode, pipeline.guardrailOnly, (c) =>
    scanProvider(env, c, input, fetchImpl, opts.captureRaw === true),
  );
}
