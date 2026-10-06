// Who may CHANGE the external-guardrail settings (Open bug #26).
//
// Prod sits behind Cloudflare Access, but Access lets in more than people: the
// red-team scanner's service token passes it too, so anything that passes Access
// could enable or disable a guardrail, change its region or fail mode, or replace
// a stored key. This gate narrows the WRITES — reading the settings stays open to
// anyone Access lets in — to a named list of people.
//
// How it decides, each step fail-closed once the list exists:
//   - GUARDRAIL_ADMIN_EMAILS unset → the gate is off and writes stay open, exactly as
//     before (so deploying this changes nothing until an operator opts in). The
//     settings API says so (`access.mode: "open"`), so the page never implies a
//     restriction that is not there.
//   - set → the request must carry Access's signed JWT (`Cf-Access-Jwt-Assertion`),
//     verified here: RS256 against the team's published keys, issuer = the team
//     domain, audience = this app's AUD, not expired. Trusting the header without
//     verifying it would let anything that reaches the Worker another way claim to
//     be an admin.
//   - a service token's JWT has a `common_name` and no `email`: it can read, never
//     write. That is the point of #26.
//   - the verified email must be on the list (case-insensitive).
// Facts checked 2026-10-06 against this app's real Access JWT (a service-token one):
// alg RS256 with a `kid`, iss "https://nttth.cloudflareaccess.com", one aud, claims
// type/iat/exp/iss/sub/aud/common_name — no email. Keys come from
// https://<team>/cdn-cgi/access/certs (Cloudflare's documented JWKS endpoint).

import type { Env } from "./types";

export interface AccessConfig {
  teamDomain: string; // "nttth.cloudflareaccess.com" — no scheme
  aud: string;
}

export interface AccessIdentity {
  email: string | null; // a person's login
  commonName: string | null; // a service token's client id
}

type Jwk = JsonWebKey & { kid?: string };
type FetchLike = (url: string) => Promise<Response>;

const KEY_TTL_MS = 10 * 60_000;
const SKEW_S = 60;
const keyCache = new Map<string, { at: number; keys: Jwk[] }>();

function b64urlBytes(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

function b64urlJson(s: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(new TextDecoder().decode(b64urlBytes(s))) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function teamKeys(teamDomain: string, fetchImpl: FetchLike, refresh: boolean, now: number): Promise<Jwk[]> {
  const hit = keyCache.get(teamDomain);
  if (hit && !refresh && now - hit.at < KEY_TTL_MS) return hit.keys;
  const res = await fetchImpl(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) return hit?.keys ?? [];
  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = Array.isArray(body.keys) ? body.keys : [];
  keyCache.set(teamDomain, { at: now, keys });
  return keys;
}

// The verified identity, or null for anything that is not a valid, current Access
// JWT for THIS app. Never throws.
export async function verifyAccessJwt(
  token: string,
  cfg: AccessConfig,
  fetchImpl: FetchLike = (u) => fetch(u),
  nowMs: number = Date.now(),
): Promise<AccessIdentity | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const header = b64urlJson(h);
    const claims = b64urlJson(p);
    if (!header || !claims || header.alg !== "RS256" || typeof header.kid !== "string") return null;

    const now = nowMs / 1000;
    if (claims.iss !== `https://${cfg.teamDomain}`) return null;
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(cfg.aud)) return null;
    if (typeof claims.exp !== "number" || claims.exp < now - SKEW_S) return null;
    if (typeof claims.nbf === "number" && claims.nbf > now + SKEW_S) return null;

    // An unknown kid may be a rotated key: refetch once before giving up.
    let jwk = (await teamKeys(cfg.teamDomain, fetchImpl, false, nowMs)).find((k) => k.kid === header.kid);
    if (!jwk) jwk = (await teamKeys(cfg.teamDomain, fetchImpl, true, nowMs)).find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlBytes(s), new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return null;
    return {
      email: typeof claims.email === "string" && claims.email ? claims.email : null,
      commonName: typeof claims.common_name === "string" ? claims.common_name : null,
    };
  } catch {
    return null;
  }
}

export function adminEmails(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(/[\s,]+/)
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
}

export type WriteAccess =
  | { canEdit: true; mode: "open" | "admin"; who: string | null }
  | { canEdit: false; mode: "admin"; who: string | null; reason: string };

export async function guardrailWriteAccess(
  request: Request,
  env: Pick<Env, "GUARDRAIL_ADMIN_EMAILS" | "ACCESS_TEAM_DOMAIN" | "ACCESS_AUD">,
  fetchImpl?: FetchLike,
  nowMs?: number,
): Promise<WriteAccess> {
  const admins = adminEmails(env.GUARDRAIL_ADMIN_EMAILS);
  if (admins.length === 0) return { canEdit: true, mode: "open", who: null };
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
    return {
      canEdit: false,
      mode: "admin",
      who: null,
      reason: "GUARDRAIL_ADMIN_EMAILS is set but ACCESS_TEAM_DOMAIN / ACCESS_AUD are not, so no login can be verified",
    };
  }
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { canEdit: false, mode: "admin", who: null, reason: "this request carries no Cloudflare Access login" };
  const id = await verifyAccessJwt(token, { teamDomain: env.ACCESS_TEAM_DOMAIN, aud: env.ACCESS_AUD }, fetchImpl, nowMs);
  if (!id) return { canEdit: false, mode: "admin", who: null, reason: "the Cloudflare Access login could not be verified" };
  if (!id.email) {
    return {
      canEdit: false,
      mode: "admin",
      who: id.commonName ? `service token ${id.commonName}` : "a service token",
      reason: "service tokens can read the guardrail settings but not change them",
    };
  }
  if (!admins.includes(id.email.toLowerCase())) {
    return { canEdit: false, mode: "admin", who: id.email, reason: `${id.email} is not a guardrail admin` };
  }
  return { canEdit: true, mode: "admin", who: id.email };
}

// Test hook: the key cache is module state.
export function _resetAccessKeyCache(): void {
  keyCache.clear();
}
