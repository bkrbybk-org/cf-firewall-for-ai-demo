// Vendor-agnostic capabilities (2026-10-12): which of the eight capabilities in the Compliance matrix (compliance.ts
// MATRIX) each vendor in this demo has been OBSERVED to provide — Cloudflare and every external guardrail alike.
//
// Decided with the user: vendors are shown as observed, not graded. A full/partial grade per control is a claim about a
// vendor's product this app cannot check; what it CAN check is what each vendor actually did to traffic here. So:
//   - "seen": in the window, the vendor reported a detection this file classifies under the capability (or, for
//     output moderation, checked model replies). The detector names and counts are shown — the evidence, not a summary.
//   - "not-seen": the capability COULD show up in this vendor's data, and did not in the window. Never "does not have
//     it": the vendor may offer it and this demo's policy or traffic never exercised it.
//   - "unobservable": nothing this app records could show it for this vendor (e.g. a guardrail API's rate limiting).
//     Said as such, never folded into "not seen".
// Cloudflare is observed the same way, from the edge's own detections and the AI Gateway logs; its hand-written grades
// (compliance.ts) stay as a separate, labelled assessment.
//
// The classification is an EXACT-NAME table of detector names seen in real payloads (or fixed by the vendor's own
// documented taxonomy) — never a regex over free text. A name not in the table is "other": counted and listed, never
// guessed into a capability. Two documented category prefixes are used as prefixes: Lakera's `pii/` and
// `moderated_content/` (its `<category>/<type>` scheme, docs.lakera.ai). Cato's names are operator-set policy names
// ("<guard> - <policy> - <policy>"); only the built-in policy TYPE inside them is matched, from the user's Guards Policy.
import { MATRIX, type CapabilityId } from "./compliance";
import type { Analytics, ExternalGuardrailProvider, GatewayAnalytics, GuardrailVendorStats } from "./types";

export type VendorId = "cloudflare" | ExternalGuardrailProvider;

export const VENDOR_IDS: VendorId[] = [
  "cloudflare",
  "prisma-airs",
  "crowdstrike-aidr",
  "cisco-ai-defense",
  "lakera-guard",
  "cato-ai-security",
  "datadog-ai-guard",
];

// The external guardrails, in the order every vendor list in the app uses (the Worker's registry order).
export const EXTERNAL_VENDORS = VENDOR_IDS.filter((v): v is ExternalGuardrailProvider => v !== "cloudflare");

export type DetectionCapability = "prompt-injection" | "pii" | "unsafe-topics" | "custom-topics";

// Exact detector names → capability, per vendor. Sources: the names each parser emits (src/*.ts) and those seen live
// (PROGRESS.md; Analytics Engine, 2026-10-09…12).
const EXACT: Record<ExternalGuardrailProvider, Record<string, DetectionCapability>> = {
  // prompt_detected keys (PANW scan-service spec; injection, dlp, topic_violation seen live).
  "prisma-airs": { injection: "prompt-injection", dlp: "pii", toxic_content: "unsafe-topics", topic_violation: "custom-topics" },
  // AIDR detector names (aidr_openapi.json; all four seen live).
  "crowdstrike-aidr": {
    malicious_prompt: "prompt-injection",
    confidential_and_pii_entity: "pii",
    topic: "custom-topics",
  },
  // Cisco rule names (ai-defense-python-sdk; "Prompt Injection" seen live).
  "cisco-ai-defense": { "Prompt Injection": "prompt-injection", PII: "pii", PCI: "pii", PHI: "pii", Toxicity: "unsafe-topics" },
  // Lakera: prompt_attack seen live; pii/* and moderated_content/* by prefix below.
  "lakera-guard": { prompt_attack: "prompt-injection" },
  // Cato entity types (seen live: ID_NUMBER, EMAIL) — policy types matched below.
  "cato-ai-security": { ID_NUMBER: "pii", EMAIL: "pii", PHONE_NUMBER: "pii", CREDIT_CARD: "pii" },
  // Datadog AI Guard attack tags (its tracer's taxonomy; none seen live yet).
  "datadog-ai-guard": {
    jailbreak: "prompt-injection",
    "instruction-override": "prompt-injection",
    "indirect-prompt-injection": "prompt-injection",
    "system-prompt-extraction": "prompt-injection",
    "authority-override": "prompt-injection",
  },
};

// Cato policy TYPES (the user's Guards Policy, 2026-10-08) inside "<guard> - <type> - <type>".
const CATO_POLICY: Record<string, DetectionCapability> = {
  "Personal Identifiers": "pii",
  "Sensitive Identifiers": "pii",
  "Secrets & Passwords": "pii",
};

export function classifyDetection(provider: ExternalGuardrailProvider, name: string): DetectionCapability | null {
  const n = name.startsWith("prompt:") ? name.slice(7) : name; // a reply check's finding on the prompt
  if (Object.hasOwn(EXACT[provider], n)) return EXACT[provider][n];
  if (provider === "lakera-guard") {
    if (n.startsWith("pii/")) return "pii";
    if (n.startsWith("moderated_content/")) return "unsafe-topics";
  }
  if (provider === "cato-ai-security") {
    const parts = n.split(" - ");
    if (parts.length === 3 && parts[1] === parts[2] && Object.hasOwn(CATO_POLICY, parts[1])) return CATO_POLICY[parts[1]];
  }
  return null;
}

export type ObservedState = "seen" | "not-seen" | "unobservable";

export interface Observed {
  state: ObservedState;
  detail: string; // one line: what was seen, or why not
  evidence: { name: string; count: number }[]; // detector names behind a "seen", most first
}

export interface VendorObservation {
  vendor: VendorId;
  capabilities: Record<CapabilityId, Observed>;
  other: { name: string; count: number }[]; // detections this table does not classify — listed, never dropped
}

const DETECTION_CAPS: DetectionCapability[] = ["prompt-injection", "pii", "unsafe-topics", "custom-topics"];
const unobservable = (detail: string): Observed => ({ state: "unobservable", detail, evidence: [] });
const count = (n: number) => (Number.isInteger(n) ? n.toLocaleString() : `≈${Math.round(n).toLocaleString()}`);

// An external guardrail, from the verdict analytics (every source, so Red Team and scheduled runs count: this is
// "what the vendor is seen to detect", not evidence of protection in use).
export function observeGuardrail(provider: ExternalGuardrailProvider, stats: GuardrailVendorStats[], windowLabel: string): VendorObservation {
  const mine = stats.filter((s) => s.provider === provider);
  const byCap = new Map<DetectionCapability, Map<string, number>>();
  const other = new Map<string, number>();
  for (const s of mine) {
    for (const d of s.detections ?? s.topDetections) {
      const cap = classifyDetection(provider, d.name);
      const bucket = cap ? (byCap.get(cap) ?? new Map<string, number>()) : other;
      bucket.set(d.name, (bucket.get(d.name) ?? 0) + d.count);
      if (cap) byCap.set(cap, bucket);
    }
  }
  const checked = mine.reduce((n, s) => n + s.checked, 0);
  const caps = {} as Record<CapabilityId, Observed>;
  for (const c of DETECTION_CAPS) {
    const ev = [...(byCap.get(c) ?? new Map()).entries()].map(([name, n]) => ({ name, count: n })).sort((a, b) => b.count - a.count);
    caps[c] =
      ev.length > 0
        ? { state: "seen", detail: `${count(ev.reduce((n, e) => n + e.count, 0))} detections in the ${windowLabel}`, evidence: ev }
        : {
            state: "not-seen",
            detail: checked > 0 ? `none in ${count(checked)} checks in the ${windowLabel}` : `no checks in the ${windowLabel}`,
            evidence: [],
          };
  }
  const reply = mine.find((s) => s.dir === "reply");
  caps["output-moderation"] =
    reply && reply.checked > 0
      ? {
          state: "seen",
          detail: `checked ${count(reply.checked)} model replies in the ${windowLabel} · ${count(reply.block)} withheld`,
          evidence: (reply.detections ?? reply.topDetections).filter((d) => !d.name.startsWith("prompt:")),
        }
      : { state: "not-seen", detail: `no reply checked in the ${windowLabel}`, evidence: [] };
  caps["rate-limiting"] = unobservable("a guardrail API's own limits are not visible to this app");
  caps.logging = unobservable("the vendor's own console logs are not readable by this app");
  caps["provider-abstraction"] = unobservable("not a guardrail capability");
  return {
    vendor: provider,
    capabilities: caps,
    other: [...other.entries()].map(([name, n]) => ({ name, count: n })).sort((a, b) => b.count - a.count),
  };
}

// Cloudflare, from the edge's detections (/api/analytics) and the AI Gateway logs (/api/gateway-analytics).
export function observeCloudflare(edge: Analytics | null, gateway: GatewayAnalytics | null, windowLabel: string): VendorObservation {
  const edgeRead = !!edge?.configured;
  const gwRead = !!gateway?.configured && !gateway.error;
  const gwRequests = gateway?.requests ?? 0;
  const gwCached = gateway?.cachedRequests ?? 0;
  const gwModels = gateway?.byModel ?? [];
  const fromList = (list: { name: string; count: number }[] | undefined, what: string): Observed =>
    !edgeRead
      ? unobservable("edge analytics not configured")
      : list && list.length > 0
        ? { state: "seen", detail: `${what} in the ${windowLabel}`, evidence: list }
        : { state: "not-seen", detail: `none in the edge events read for the ${windowLabel}`, evidence: [] };
  const caps = {} as Record<CapabilityId, Observed>;
  caps["prompt-injection"] = !edgeRead
    ? unobservable("edge analytics not configured")
    : (edge!.aiScored ?? 0) > 0
      ? {
          state: "seen",
          detail: `${count(edge!.aiScored!)} requests scored for injection in the ${windowLabel}${edge!.truncated ? " (of the events read)" : ""}`,
          evidence: (edge!.scoreBuckets ?? []).map((b) => ({ name: `score ${b.label}`, count: b.count })),
        }
      : { state: "not-seen", detail: `no injection score in the edge events read for the ${windowLabel}`, evidence: [] };
  caps.pii = fromList(edge?.piiCategories, "PII categories detected");
  caps["unsafe-topics"] = fromList(edge?.unsafeTopics?.map((t) => ({ name: t.code, count: t.count })), "unsafe topics detected");
  caps["custom-topics"] = fromList(edge?.customTopics?.map((t) => ({ name: t.label, count: t.count })), "custom topics detected");
  // AI Gateway Guardrails' verdicts are not in the gateway logs API this app reads (README, Gateway tab).
  caps["output-moderation"] = unobservable("AI Gateway Guardrails verdicts are not in the gateway logs API");
  caps["rate-limiting"] = !gwRead
    ? unobservable("gateway logs not readable")
    : gwCached > 0
      ? { state: "seen", detail: `${count(gwCached)} cached responses in the ${windowLabel} (rate limits are not in the logs)`, evidence: [] }
      : { state: "not-seen", detail: `no cached response in the ${windowLabel}`, evidence: [] };
  caps.logging =
    gwRead && gwRequests > 0
      ? { state: "seen", detail: `${count(gwRequests)} gateway requests logged in the ${windowLabel}`, evidence: [] }
      : edgeRead && (edge!.totalEvents ?? 0) > 0
        ? { state: "seen", detail: `${count(edge!.totalEvents!)} edge security events in the ${windowLabel}`, evidence: [] }
        : { state: "not-seen", detail: `nothing logged in the ${windowLabel}`, evidence: [] };
  caps["provider-abstraction"] = !gwRead
    ? unobservable("gateway logs not readable")
    : gwModels.length > 0
      ? {
          state: "seen",
          detail: `${gwModels.length} model${gwModels.length === 1 ? "" : "s"} reached through the gateway in the ${windowLabel}`,
          evidence: gwModels.map((m) => ({ name: m.model, count: m.count })),
        }
      : { state: "not-seen", detail: `no gateway request in the ${windowLabel}`, evidence: [] };
  return { vendor: "cloudflare", capabilities: caps, other: [] };
}

// The capabilities a framework control maps to — MATRIX read the other way. A control no capability maps to is a
// governance control no vendor's traffic can show.
export function capabilitiesOf(frameworkId: string, controlId: string): CapabilityId[] {
  return MATRIX.filter((r) => (r.cells[frameworkId] ?? []).includes(controlId)).map((r) => r.id);
}

// A control is OBSERVED for a vendor when any capability it maps to was seen for that vendor.
export function observedFor(o: VendorObservation, frameworkId: string, controlId: string): CapabilityId[] {
  return capabilitiesOf(frameworkId, controlId).filter((c) => o.capabilities[c].state === "seen");
}
