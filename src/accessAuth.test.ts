// The write gate for guardrail settings (#26). Tokens are signed here with a
// generated RSA key, served through a fake certs endpoint — no network.
import { beforeEach, describe, expect, it } from "vitest";
import { _resetAccessKeyCache, adminEmails, guardrailWriteAccess, requesterLabel, verifyAccessJwt, withRequester } from "./accessAuth";

const TEAM = "team.cloudflareaccess.com";
const AUD = "aud-123";
const NOW = 1_800_000_000_000;

const enc = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64url = (b: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function keypair(kid: string) {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = { ...((await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey), kid };
  return { kp, jwk };
}

async function sign(kp: CryptoKeyPair, kid: string, claims: Record<string, unknown>, alg = "RS256") {
  const h = enc({ alg, kid, typ: "JWT" });
  const p = enc(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

const claims = (o: Record<string, unknown> = {}) => ({
  iss: `https://${TEAM}`,
  aud: [AUD],
  exp: NOW / 1000 + 600,
  iat: NOW / 1000,
  email: "admin@example.com",
  ...o,
});

let A: Awaited<ReturnType<typeof keypair>>;
let calls = 0;
const certs = (keys: JsonWebKey[]) => async (url: string) => {
  calls++;
  expect(url).toBe(`https://${TEAM}/cdn-cgi/access/certs`);
  return Response.json({ keys });
};

beforeEach(async () => {
  _resetAccessKeyCache();
  calls = 0;
  A ??= await keypair("k1");
});

const cfg = { teamDomain: TEAM, aud: AUD };

describe("verifyAccessJwt", () => {
  it("accepts a valid token and returns the email", async () => {
    const t = await sign(A.kp, "k1", claims());
    expect(await verifyAccessJwt(t, cfg, certs([A.jwk]), NOW)).toEqual({ email: "admin@example.com", commonName: null });
  });

  it("rejects a forged signature, wrong issuer, wrong audience, expired, alg none", async () => {
    const B = await keypair("k1"); // same kid, different key: a forgery
    const f = certs([A.jwk]);
    expect(await verifyAccessJwt(await sign(B.kp, "k1", claims()), cfg, f, NOW)).toBeNull();
    expect(await verifyAccessJwt(await sign(A.kp, "k1", claims({ iss: "https://evil.cloudflareaccess.com" })), cfg, f, NOW)).toBeNull();
    expect(await verifyAccessJwt(await sign(A.kp, "k1", claims({ aud: ["other-app"] })), cfg, f, NOW)).toBeNull();
    expect(await verifyAccessJwt(await sign(A.kp, "k1", claims({ exp: NOW / 1000 - 3600 })), cfg, f, NOW)).toBeNull();
    const none = `${enc({ alg: "none", kid: "k1" })}.${enc(claims())}.`;
    expect(await verifyAccessJwt(none, cfg, f, NOW)).toBeNull();
    expect(await verifyAccessJwt("not-a-jwt", cfg, f, NOW)).toBeNull();
  });

  it("refetches the keys once for an unknown kid (rotation), and caches otherwise", async () => {
    const R = await keypair("k2");
    let keys: JsonWebKey[] = [A.jwk];
    const f = async (u: string) => certs(keys)(u);
    expect(await verifyAccessJwt(await sign(A.kp, "k1", claims()), cfg, f, NOW)).not.toBeNull();
    expect(await verifyAccessJwt(await sign(A.kp, "k1", claims()), cfg, f, NOW)).not.toBeNull();
    expect(calls).toBe(1);
    keys = [A.jwk, R.jwk];
    expect(await verifyAccessJwt(await sign(R.kp, "k2", claims()), cfg, f, NOW)).not.toBeNull();
    expect(calls).toBe(2);
  });
});

describe("guardrailWriteAccess", () => {
  const req = (token?: string) => new Request("https://x/api/external-guardrails", { headers: token ? { "cf-access-jwt-assertion": token } : {} });
  const env = (o: Record<string, string | undefined> = {}) => ({
    GUARDRAIL_ADMIN_EMAILS: "Admin@Example.com, second@example.com",
    ACCESS_TEAM_DOMAIN: TEAM,
    ACCESS_AUD: AUD,
    ...o,
  });

  it("is off (open) when no admin list is set — deploying it changes nothing", async () => {
    expect(await guardrailWriteAccess(req(), env({ GUARDRAIL_ADMIN_EMAILS: "" }))).toEqual({ canEdit: true, mode: "open", who: null });
  });

  it("lets a listed admin write, matching case-insensitively", async () => {
    const t = await sign(A.kp, "k1", claims());
    expect(await guardrailWriteAccess(req(t), env(), certs([A.jwk]), NOW)).toEqual({ canEdit: true, mode: "admin", who: "admin@example.com" });
  });

  it("refuses a service token, an unlisted person, no login, and a bad token", async () => {
    const f = certs([A.jwk]);
    const svc = await sign(A.kp, "k1", claims({ email: undefined, common_name: "abc.access" }));
    expect(await guardrailWriteAccess(req(svc), env(), f, NOW)).toMatchObject({ canEdit: false, who: "service token abc.access" });
    const other = await sign(A.kp, "k1", claims({ email: "intruder@example.com" }));
    expect(await guardrailWriteAccess(req(other), env(), f, NOW)).toMatchObject({ canEdit: false, who: "intruder@example.com" });
    expect(await guardrailWriteAccess(req(), env(), f, NOW)).toMatchObject({ canEdit: false, who: null });
    expect(await guardrailWriteAccess(req("x.y.z"), env(), f, NOW)).toMatchObject({ canEdit: false });
  });

  it("fails closed when the list is set but the Access config is missing", async () => {
    const t = await sign(A.kp, "k1", claims());
    expect(await guardrailWriteAccess(req(t), env({ ACCESS_AUD: undefined }), certs([A.jwk]), NOW)).toMatchObject({ canEdit: false });
  });
});

describe("adminEmails", () => {
  it("splits on commas and whitespace, lowercases, drops blanks", () => {
    expect(adminEmails(" A@x.com,b@x.com\n  c@x.com ,, ")).toEqual(["a@x.com", "b@x.com", "c@x.com"]);
    expect(adminEmails(undefined)).toEqual([]);
  });
});

describe("requesterLabel + withRequester — who is prompting, in AI Gateway metadata (2026-11-05)", () => {
  const req = (h: Record<string, string> = {}) => new Request("https://x/api/chat", { method: "POST", headers: h });
  const env = { ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD };

  it("names a verified person by email and a service token by its client id", async () => {
    const f = certs([A.jwk]);
    const person = await sign(A.kp, "k1", claims({ email: "alice@example.com" }));
    expect(await requesterLabel(req({ "cf-access-jwt-assertion": person }), env, f, NOW)).toBe("alice@example.com");
    const svc = await sign(A.kp, "k1", claims({ email: undefined, common_name: "abc.access" }));
    expect(await requesterLabel(req({ "cf-access-jwt-assertion": svc }), env, f, NOW)).toBe("service-token:abc.access");
  });

  it("is null without a verified login — the unsigned email header is never trusted", async () => {
    const f = certs([A.jwk]);
    expect(await requesterLabel(req({ "cf-access-authenticated-user-email": "spoof@example.com" }), env, f, NOW)).toBeNull();
    const forged = await sign((await keypair("k1")).kp, "k1", claims({ email: "spoof@example.com" }));
    expect(await requesterLabel(req({ "cf-access-jwt-assertion": forged }), env, f, NOW)).toBeNull();
    const t = await sign(A.kp, "k1", claims());
    expect(await requesterLabel(req({ "cf-access-jwt-assertion": t }), { ACCESS_TEAM_DOMAIN: TEAM }, f, NOW)).toBeNull();
  });

  it("puts the server entry first, drops a caller-supplied user, and keeps the 5-entry cap", () => {
    const five = { a: "1", b: "2", c: "3", d: "4", e: "5" };
    expect(withRequester(five, "alice@example.com", 5)).toEqual({ user: "alice@example.com", a: "1", b: "2", c: "3", d: "4" });
    expect(Object.keys(withRequester(five, "alice@example.com", 5)!)[0]).toBe("user");
    expect(withRequester({ User: "mallory", a: "1" }, null, 5)).toEqual({ a: "1" });
    expect(withRequester({ user: "mallory" }, "alice@example.com", 5)).toEqual({ user: "alice@example.com" });
    expect(withRequester(undefined, null, 5)).toBeUndefined();
    expect(withRequester({ user: "mallory" }, null, 5)).toBeUndefined();
  });
});
