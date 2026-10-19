// Compliance mapping page: how the AI security controls in this demo — Cloudflare's and each external guardrail's —
// support NIST AI RMF, ISO 42001, OWASP LLM Top 10, MITRE ATLAS, plus the Thai frameworks (Bank of Thailand AI risk
// policy, NCSA AI Security Guidelines). All mapping content lives in ../lib/compliance.ts — none inline here.
//
// Vendor-agnostic since 2026-10-12 (decided with the user): one picker — All vendors, Cloudflare, then each external
// guardrail — over the same capabilities and the same framework controls.
//   - Cloudflare's view is the page as it was: its hand-written, GRADED mapping (full / partial / supporting / out of
//     scope), product badges, and the live evidence chips (../lib/complianceEvidence.ts).
//   - Every vendor — Cloudflare too — is also OBSERVED (../lib/vendorCapabilities.ts): which capabilities its own data
//     shows it providing in this demo, with the detector names as evidence. External vendors are shown as observed
//     only, never graded: a grade would be a claim about their products this app cannot check.
//   - "not seen" is never "does not have it", and "unobservable" is never folded into "not seen".
//
// Evidence chips (Control.evidence) carry a live audit metric for a fixed window (EVIDENCE_HOURS); observation reads a
// longer one (OBSERVE_HOURS, every source) because it asks a different question: what has this vendor been seen to do.
// A failed or unconfigured fetch degrades quietly: the controls are static content and render regardless.
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ArrowRight, CircleDashed, CircleDot, ExternalLink, Info, Minus, ShieldCheck, ShieldHalf } from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { getAnalytics, getGatewayAnalytics, getGuardrailAnalytics, getModels, getPromptAnalytics } from "../lib/api";
import { providerFullLabel, providerLabel } from "../lib/guardrailView";
import {
  COVERAGE_HELP,
  COVERAGE_LABEL,
  FRAMEWORKS,
  MATRIX,
  PRODUCT_LABEL,
  shortControlId,
  type Control,
  type Coverage,
  type Evidence,
  type Framework,
  type Product,
} from "../lib/compliance";
import { resolveEvidence, resolveVendorEvidence } from "../lib/complianceEvidence";
import {
  capabilitiesOf,
  EXTERNAL_VENDORS,
  observeCloudflare,
  observedFor,
  observeGuardrail,
  VENDOR_IDS,
  type Observed,
  type VendorId,
  type VendorObservation,
} from "../lib/vendorCapabilities";
import type {
  Analytics,
  ExternalGuardrailProvider,
  GatewayAnalytics,
  GuardrailAnalytics,
  PromptAnalytics,
} from "../lib/types";

// Fixed rather than user-picked: this page is an audit artifact, not a dashboard, and a moving range would make "what
// did the reviewer see" unreproducible. 24h for evidence (the AnalyticsPage default); 7 days for observation.
const EVIDENCE_HOURS = 24;
const OBSERVE_HOURS = 168;
const OBSERVE_WINDOW = "last 7 days";

const COVERAGE_TONE: Record<Coverage, string> = {
  full: "border-cf-green/50 bg-cf-green/10 text-cf-green-ink",
  partial: "border-cf-amber/50 bg-cf-amber/10 text-cf-amber-ink",
  supporting: "border-cf-blue/50 bg-cf-blue/10 text-cf-blue-ink",
  none: "border-line bg-surface-2 text-subtle",
};
const COVERAGE_DOT: Record<Coverage, string> = {
  full: "bg-cf-green",
  partial: "bg-cf-amber",
  supporting: "bg-cf-blue",
  none: "bg-subtle",
};
const PRODUCT_TONE: Record<Product, string> = {
  "ai-security": "border-cf-blue/40 bg-cf-blue/10 text-cf-blue-ink",
  "ai-gateway": "border-cf-purple/40 bg-cf-purple/10 text-cf-purple",
  both: "border-accent/40 bg-accent/10 text-accent-ink",
  neither: "border-line bg-surface-2 text-subtle",
};

const COVERAGE_ORDER: Coverage[] = ["full", "partial", "supporting", "none"];

const vendorName = (v: VendorId) => (v === "cloudflare" ? "Cloudflare" : providerLabel(v));
const vendorFullName = (v: VendorId) => (v === "cloudflare" ? "Cloudflare (AI Security for Apps, AI Gateway)" : providerFullLabel(v));

function CoverageBadge({ c, prefix }: { c: Coverage; prefix?: string }) {
  return (
    <span
      title={COVERAGE_HELP[c]}
      className={`shrink-0 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${COVERAGE_TONE[c]}`}
    >
      {prefix}
      {COVERAGE_LABEL[c]}
    </span>
  );
}

function ProductBadge({ p }: { p: Product }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10.5px] font-semibold ${PRODUCT_TONE[p]}`}>
      {PRODUCT_LABEL[p]}
    </span>
  );
}

function Ref({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full border border-line bg-surface-2 px-2 py-0.5 font-mono text-[10.5px] text-muted">
      {children}
    </span>
  );
}

// One observed state as a glyph + word — never colour alone.
function ObsMark({ o, compact = false }: { o: Observed; compact?: boolean }) {
  const ev = o.evidence.slice(0, 6).map((e) => `${e.name} (${e.count})`).join(", ");
  const title = `${o.detail}${ev ? ` — ${ev}` : ""}`;
  if (o.state === "seen") {
    return (
      <span title={title} className="inline-flex items-center gap-1 text-[11px] font-semibold text-cf-green-ink">
        <CircleDot size={12} aria-hidden /> {compact ? "seen" : "observed"}
      </span>
    );
  }
  if (o.state === "not-seen") {
    return (
      <span title={title} className="inline-flex items-center gap-1 text-[11px] text-muted">
        <CircleDashed size={12} aria-hidden /> not seen
      </span>
    );
  }
  return (
    <span title={title} className="inline-flex items-center gap-1 text-[11px] text-subtle">
      <Minus size={12} aria-hidden /> {compact ? "n/a" : "not observable"}
    </span>
  );
}

// Cloudflare's evidence chip. Three states, deliberately distinct — see complianceEvidence.ts's header for why
// collapsing any two of them would be dishonest: "unconfigured" is nothing at all, "no-data" a muted note that the
// control simply wasn't exercised in this window, and "ok" the real measured value.
function EvidenceChip({
  evidence,
  analytics,
  promptAnalytics,
}: {
  evidence: Evidence;
  analytics: Analytics | null;
  promptAnalytics: PromptAnalytics | null;
}) {
  const r = resolveEvidence(evidence, analytics, promptAnalytics, EVIDENCE_HOURS);
  if (r.status === "unconfigured") return null;
  if (r.status === "no-data") {
    return (
      <div className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[11px] text-subtle">
        <Activity size={12} className="mt-0.5 shrink-0" />
        <span>No traffic to measure in the {r.windowLabel} — not exercised yet, not a failed control.</span>
      </div>
    );
  }
  return (
    <div
      className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-cf-blue/30 bg-cf-blue/[0.06] px-2.5 py-1.5 text-[11px] text-cf-blue-ink"
      title={r.floor ? "Row cap reached in this window — counts are a floor, not an exact total." : undefined}
    >
      <Activity size={12} className="mt-0.5 shrink-0" />
      <span>
        <b className="font-semibold">{r.headline}</b> · {r.windowLabel}
        {r.floor && " · floor (row cap reached)"}
        {/* How the numbers were obtained, when it changes what they claim (bug #22). */}
        {r.note && <span className="mt-0.5 block text-[10.5px] text-muted">{r.note}</span>}
      </span>
    </div>
  );
}

// An external vendor's own "protection in use" line, on its own view (compliance.ts `vendorInUse`).
function VendorInUseChip({ g, provider }: { g: GuardrailAnalytics | null; provider: ExternalGuardrailProvider }) {
  const r = resolveVendorEvidence(g, provider, providerLabel, EVIDENCE_HOURS);
  if (r.status === "unconfigured") return null;
  return (
    <div className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[11px] text-muted">
      <ShieldHalf size={12} className="mt-0.5 shrink-0" />
      <span>
        {r.status === "no-data" ? (
          <>{providerLabel(provider)} checked no chat prompt in the {r.windowLabel} — not exercised, not a failed control.</>
        ) : (
          <>
            <b className="font-semibold text-text">{r.headline}</b> · {r.windowLabel}
            {r.note && <span className="mt-0.5 block text-[10.5px] text-subtle">{r.note}</span>}
          </>
        )}
      </span>
    </div>
  );
}

function FrameworkTabs({ active, onPick }: { active: string; onPick: (id: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2">
      {FRAMEWORKS.map((f) => (
        <button
          key={f.id}
          type="button"
          onClick={() => onPick(f.id)}
          className={`rounded-full border px-3.5 py-1.5 text-[12.5px] transition ${
            f.id === active
              ? "border-accent bg-accent/12 font-bold text-accent-ink"
              : "border-line bg-surface text-muted hover:border-accent hover:text-text"
          }`}
        >
          {f.label}
        </button>
      ))}
    </div>
  );
}

function FrameworkHeader({ fw }: { fw: Framework }) {
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <h2 className="text-[14px] font-bold text-text">{fw.full}</h2>
        <a href={fw.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[11.5px] text-accent-ink hover:underline">
          reference <ExternalLink size={11} />
        </a>
      </div>
      <p className="mt-1 text-[12px] leading-relaxed text-muted">{fw.blurb}</p>
      {fw.note && <p className="mt-1.5 border-l-2 border-cf-amber/60 pl-2.5 text-[11.5px] leading-relaxed text-muted">{fw.note}</p>}
    </section>
  );
}

// Capability × framework: which controls each (vendor-neutral) capability maps to. `withCloudflare` adds Cloudflare's
// own implementation and graded coverage under each capability — on Cloudflare's view only.
function CapabilityControlMatrix({ withCloudflare }: { withCloudflare: boolean }) {
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">Capabilities → framework controls</h2>
      <div className="mt-0.5 text-[11.5px] text-muted">
        {withCloudflare
          ? "Each capability, how Cloudflare implements it (dot = Cloudflare's graded coverage), and the controls it maps to"
          : "Each capability, whoever provides it, and the controls it maps to in each framework"}
      </div>
      <div className="relative mt-3 overflow-x-auto">
        <table className="w-full min-w-[900px] border-collapse text-left">
          <thead>
            <tr className="border-b border-line-strong">
              <th className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">Capability</th>
              {FRAMEWORKS.map((f) => (
                <th key={f.id} className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">
                  {f.short}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MATRIX.map((row) => (
              <tr key={row.id} className="border-b border-line align-top last:border-0">
                <td className="px-2 py-2.5">
                  <div className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                    {withCloudflare && (
                      <span
                        title={`Cloudflare: ${COVERAGE_LABEL[row.cloudflare.coverage]}`}
                        className={`h-2 w-2 shrink-0 rounded-full ${COVERAGE_DOT[row.cloudflare.coverage]}`}
                      />
                    )}
                    {row.capability}
                  </div>
                  {withCloudflare && <div className="mt-0.5 pl-4 text-[11px] text-muted">{row.cloudflare.detail}</div>}
                </td>
                {FRAMEWORKS.map((f) => {
                  const ids = row.cells[f.id] ?? [];
                  return (
                    <td key={f.id} className="px-2 py-2.5">
                      {ids.length === 0 ? (
                        <span className="text-[11px] text-subtle">—</span>
                      ) : (
                        <div className="flex flex-col gap-0.5">
                          {ids.map((id) => (
                            <span key={id} title={id} className="font-mono text-[11px] text-text">
                              {shortControlId(id)}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {withCloudflare && (
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-muted">
          {COVERAGE_ORDER.map((c) => (
            <span key={c} className="flex items-center gap-1.5" title={COVERAGE_HELP[c]}>
              <span className={`h-2 w-2 rounded-full ${COVERAGE_DOT[c]}`} /> {COVERAGE_LABEL[c]}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

// All vendors: capability × vendor, observed.
function VendorCapabilityMatrix({ obs, onPick }: { obs: Record<VendorId, VendorObservation | null>; onPick: (v: VendorId) => void }) {
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">Capabilities observed, by vendor</h2>
      <div className="mt-0.5 text-[11.5px] text-muted">
        What each vendor's own data in this demo shows it doing · {OBSERVE_WINDOW} · every source (chat, Red Team, scheduled
        re-runs) · hover a cell for the evidence
      </div>
      <div className="relative mt-3 overflow-x-auto">
        <table className="w-full min-w-[900px] border-collapse text-left">
          <thead>
            <tr className="border-b border-line-strong">
              <th className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">Capability</th>
              {VENDOR_IDS.map((v) => (
                <th key={v} className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle">
                  <button type="button" onClick={() => onPick(v)} className="text-left uppercase hover:text-accent-ink" title={`Open ${vendorName(v)}'s view`}>
                    {vendorName(v)}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MATRIX.map((row) => (
              <tr key={row.id} className="border-b border-line align-top last:border-0">
                <td className="px-2 py-2.5 text-[12.5px] font-semibold text-text">{row.capability}</td>
                {VENDOR_IDS.map((v) => {
                  const o = obs[v];
                  return (
                    <td key={v} className="px-2 py-2.5">
                      {o ? <ObsMark o={o.capabilities[row.id]} compact /> : <span className="text-[11px] text-subtle">loading…</span>}
                      {v === "cloudflare" && (
                        <div className="mt-0.5 text-[10.5px] text-subtle" title={COVERAGE_HELP[row.cloudflare.coverage]}>
                          graded {COVERAGE_LABEL[row.cloudflare.coverage].toLowerCase()}
                        </div>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-muted">
        <span className="inline-flex items-center gap-1 text-cf-green-ink">
          <CircleDot size={12} aria-hidden /> seen — its data shows it, in the window
        </span>
        <span className="inline-flex items-center gap-1">
          <CircleDashed size={12} aria-hidden /> not seen — could show, did not; never "does not have it"
        </span>
        <span className="inline-flex items-center gap-1 text-subtle">
          <Minus size={12} aria-hidden /> n/a — nothing this app records could show it for this vendor
        </span>
      </div>
    </section>
  );
}

// A control card. On the All view: every vendor observed for it, plus Cloudflare's grade. On Cloudflare's view: the
// graded card as it always was. On a vendor's view: what was observed for it.
function ControlCard({
  fwId,
  c,
  view,
  obs,
  analytics,
  promptAnalytics,
  guardrails,
}: {
  fwId: string;
  c: Control;
  view: "all" | VendorId;
  obs: Record<VendorId, VendorObservation | null>;
  analytics: Analytics | null;
  promptAnalytics: PromptAnalytics | null;
  guardrails: GuardrailAnalytics | null;
}) {
  const caps = capabilitiesOf(fwId, c.id);
  const capName = (id: string) => MATRIX.find((r) => r.id === id)?.capability ?? id;
  return (
    <article className="animate-rise flex flex-col rounded-2xl border border-line bg-surface p-4 shadow-sm transition hover:border-line-strong">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-mono text-[11.5px] text-muted">{c.id}</div>
          <h3 className="mt-0.5 text-[13.5px] leading-snug font-semibold text-text">{c.title}</h3>
        </div>
        {view === "cloudflare" ? <CoverageBadge c={c.coverage} /> : view === "all" ? <CoverageBadge c={c.coverage} prefix="Cloudflare: " /> : null}
      </div>

      {view === "cloudflare" && (
        <>
          <p className="mt-2 flex-1 text-[12.5px] leading-relaxed text-muted">{c.how}</p>
          {c.evidence && <EvidenceChip evidence={c.evidence} analytics={analytics} promptAnalytics={promptAnalytics} />}
        </>
      )}

      {view === "all" && (
        <div className="mt-2 flex-1 text-[12px] text-muted">
          {caps.length === 0 ? (
            <span className="text-subtle">A governance control — no vendor's traffic can show it.</span>
          ) : (
            <>
              <div>Maps to: {caps.map(capName).join(", ")}</div>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {VENDOR_IDS.map((v) => {
                  const o = obs[v];
                  const seen = o ? observedFor(o, fwId, c.id) : [];
                  return seen.length > 0 ? (
                    <span
                      key={v}
                      title={`${vendorFullName(v)}: observed ${seen.map(capName).join(", ")} (${OBSERVE_WINDOW})`}
                      className="inline-flex items-center gap-1 rounded-full border border-cf-green/50 bg-cf-green/10 px-2 py-0.5 text-[10.5px] font-semibold text-cf-green-ink"
                    >
                      <CircleDot size={10} aria-hidden /> {vendorName(v)}
                    </span>
                  ) : null;
                })}
                {VENDOR_IDS.every((v) => !obs[v] || observedFor(obs[v]!, fwId, c.id).length === 0) && (
                  <span className="text-[11px] text-subtle">No vendor observed for it in the {OBSERVE_WINDOW}.</span>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {view !== "all" && view !== "cloudflare" && (
        <div className="mt-2 flex-1 text-[12px] text-muted">
          {(() => {
            const o = obs[view];
            if (!o) return <span className="text-subtle">loading…</span>;
            return observedFor(o, fwId, c.id).map((cap) => {
              const ob = o.capabilities[cap];
              return (
                <div key={cap} className="mb-1">
                  <span className="font-semibold text-text">{capName(cap)}</span> — {ob.detail}
                  {ob.evidence.length > 0 && (
                    <div className="mt-0.5 font-mono text-[11px] text-subtle">
                      {ob.evidence.slice(0, 6).map((e) => `${e.name} ${e.count}`).join(" · ")}
                    </div>
                  )}
                </div>
              );
            });
          })()}
          {c.evidence?.vendorInUse && <VendorInUseChip g={guardrails} provider={view} />}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {view === "cloudflare" && <ProductBadge p={c.product} />}
        {c.refs?.map((r) => <Ref key={r}>{r}</Ref>)}
        {/* The demo links show Cloudflare's features ("Try Guardrails" is AI Gateway's), so not on another vendor's view. */}
        {c.demo && (view === "all" || view === "cloudflare") && (
          <Link to={c.demo.to} className="ml-auto inline-flex items-center gap-1 text-[11.5px] text-accent-ink hover:underline">
            {c.demo.label} <ArrowRight size={12} />
          </Link>
        )}
      </div>
    </article>
  );
}

// One vendor's capability list: each with its state, detail and evidence; then what is unclassified.
function VendorCapabilityList({ o }: { o: VendorObservation | null }) {
  if (!o) return null;
  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <h2 className="text-[13px] font-bold text-text">What {vendorName(o.vendor)} was observed doing</h2>
      <div className="mt-0.5 text-[11.5px] text-muted">
        {OBSERVE_WINDOW} · every source · from its own data in this demo — observed, not graded
      </div>
      <ul className="mt-3 grid gap-2 md:grid-cols-2">
        {MATRIX.map((row) => {
          const ob = o.capabilities[row.id];
          return (
            <li key={row.id} className="rounded-xl border border-line bg-surface-2 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12.5px] font-semibold text-text">{row.capability}</span>
                <ObsMark o={ob} />
              </div>
              <div className="mt-0.5 text-[11.5px] text-muted">{ob.detail}</div>
              {ob.evidence.length > 0 && (
                <div className="mt-0.5 font-mono text-[11px] break-words text-subtle">
                  {ob.evidence.slice(0, 8).map((e) => `${e.name} ${e.count}`).join(" · ")}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {o.other.length > 0 && (
        <p className="mt-2.5 text-[11.5px] text-muted">
          <b className="text-text">Other detections, not mapped to a capability:</b>{" "}
          <span className="font-mono text-[11px]">{o.other.map((e) => `${e.name} ${e.count}`).join(" · ")}</span> — listed, never
          guessed into one.
        </p>
      )}
    </section>
  );
}

// Every capability unobservable: the verdict dataset could not be read, so nothing is known — not "not seen".
function unreadable(p: ExternalGuardrailProvider): VendorObservation {
  const u: Observed = { state: "unobservable", detail: "the verdict analytics could not be read", evidence: [] };
  return {
    vendor: p,
    capabilities: Object.fromEntries(MATRIX.map((r) => [r.id, u])) as VendorObservation["capabilities"],
    other: [],
  };
}

export function CompliancePage() {
  const [vendor, setVendor] = useState<"all" | VendorId>("all");
  const [active, setActive] = useState(FRAMEWORKS[0].id);
  // Evidence (24h): Cloudflare's chips and each vendor's in-use line.
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [promptAnalytics, setPromptAnalytics] = useState<PromptAnalytics | null>(null);
  const [guardrails, setGuardrails] = useState<GuardrailAnalytics | null>(null);
  // Observation (7 days, every source).
  const [edge7d, setEdge7d] = useState<Analytics | null>(null);
  const [gw7d, setGw7d] = useState<GatewayAnalytics | null>(null);
  const [gr7d, setGr7d] = useState<GuardrailAnalytics | null>(null);
  const [loaded, setLoaded] = useState({ edge: false, gw: false, gr: false });

  // Fetched once, best-effort. A failing call must not surface as an error state or a zero: it leaves its data null,
  // which the resolvers read as "unconfigured" / "unobservable".
  useEffect(() => {
    let cancelled = false;
    const done = (k: keyof typeof loaded) => () => !cancelled && setLoaded((l) => ({ ...l, [k]: true }));
    getAnalytics(EVIDENCE_HOURS)
      .then((d) => !cancelled && setAnalytics(d))
      .catch(() => {});
    getPromptAnalytics({ hours: EVIDENCE_HOURS })
      .then((d) => !cancelled && setPromptAnalytics(d))
      .catch(() => {});
    // Chat traffic only: Red Team runs and scheduled re-runs are benchmarks, not evidence of protection in use.
    getGuardrailAnalytics(EVIDENCE_HOURS, "chat")
      .then((d) => !cancelled && setGuardrails(d))
      .catch(() => {});
    getAnalytics(OBSERVE_HOURS)
      .then((d) => !cancelled && setEdge7d(d))
      .catch(() => {})
      .finally(done("edge"));
    getGuardrailAnalytics(OBSERVE_HOURS, "all")
      .then((d) => !cancelled && setGr7d(d))
      .catch(() => {})
      .finally(done("gr"));
    getModels()
      .then((m) => getGatewayAnalytics(m.defaultGateway || m.gateways?.[0]?.id || "", OBSERVE_HOURS))
      .then((d) => !cancelled && setGw7d(d))
      .catch(() => {})
      .finally(done("gw"));
    return () => {
      cancelled = true;
    };
  }, []);

  const obs = useMemo(() => {
    const out = {} as Record<VendorId, VendorObservation | null>;
    out.cloudflare = loaded.edge && loaded.gw ? observeCloudflare(edge7d, gw7d, OBSERVE_WINDOW) : null;
    for (const p of EXTERNAL_VENDORS) {
      // An unreadable verdict dataset makes every external vendor's capabilities unobservable, not "not seen".
      out[p] = !loaded.gr
        ? null
        : gr7d && !gr7d.error && gr7d.configured !== false && Array.isArray(gr7d.vendors)
          ? observeGuardrail(p, gr7d.vendors, OBSERVE_WINDOW)
          : unreadable(p);
    }
    return out;
  }, [loaded, edge7d, gw7d, gr7d]);

  const fw = FRAMEWORKS.find((f) => f.id === active) ?? FRAMEWORKS[0];
  const sorted = [...fw.controls].sort((a, b) => COVERAGE_ORDER.indexOf(a.coverage) - COVERAGE_ORDER.indexOf(b.coverage));
  // A vendor's view lists the controls its observed capabilities reach; the rest are folded below, with why.
  const vendorView: ExternalGuardrailProvider | null = vendor !== "all" && vendor !== "cloudflare" ? vendor : null;
  const vObs = vendorView ? obs[vendorView] : null;
  const reached = vendorView && vObs ? sorted.filter((c) => observedFor(vObs, fw.id, c.id).length > 0) : sorted;
  const unreached = vendorView && vObs ? sorted.filter((c) => observedFor(vObs, fw.id, c.id).length === 0) : [];

  return (
    <div className="flex h-full flex-col">
      <Header
        title="Compliance Mapping"
        subtitle={<>How the AI security controls in this demo — Cloudflare's and each external guardrail's — support six AI risk frameworks (global + Thailand)</>}
        actions={<ThemeToggle />}
      />

      <main className="relative min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            <Info size={16} className="mt-0.5 shrink-0 text-cf-blue-ink" />
            <p className="text-[12.5px] leading-relaxed text-muted">
              These products provide <b className="text-text">technical controls</b> that support the frameworks. Full
              compliance is an organizational program — governance, documentation and process — not a product. Every vendor
              is shown as <b className="text-text">observed</b>: what its own data in this demo shows it doing, with the
              detector names as evidence. Cloudflare's view also carries a <b className="text-text">graded</b> mapping
              written for this demo, including the controls it does <b className="text-text">not</b> address; the other
              vendors are not graded, because a grade would be a claim about their products this app cannot check.
            </p>
          </div>

          {/* Vendor picker: All, then Cloudflare (the demo runs on it), then each external guardrail. */}
          <div className="flex flex-wrap items-center gap-1.5 text-[12.5px]" role="tablist" aria-label="Vendor">
            {(["all", ...VENDOR_IDS] as ("all" | VendorId)[]).map((v) => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={vendor === v}
                onClick={() => setVendor(v)}
                className={`rounded-full border px-3 py-1.5 transition ${
                  vendor === v ? "border-accent bg-accent/15 font-bold text-accent-ink" : "border-line bg-surface text-muted hover:bg-surface-hover"
                }`}
              >
                {v === "all" ? "All vendors" : vendorName(v)}
              </button>
            ))}
          </div>

          {vendor === "all" && <VendorCapabilityMatrix obs={obs} onPick={setVendor} />}
          {vendor !== "all" && <VendorCapabilityList o={obs[vendor]} />}
          <CapabilityControlMatrix withCloudflare={vendor === "cloudflare"} />

          <FrameworkTabs active={active} onPick={setActive} />
          <FrameworkHeader fw={fw} />

          {vendorView && vObs && reached.length === 0 && (
            <p className="text-[12px] text-muted">
              No {fw.label} control is reached by a capability {vendorName(vendorView)} was observed providing in the{" "}
              {OBSERVE_WINDOW}.
            </p>
          )}
          <div className="grid gap-3 lg:grid-cols-2">
            {reached.map((c, i) => (
              <ControlCard
                // Key includes the view, framework and index: control ids are not unique within a framework.
                key={`${vendor}-${active}-${i}-${c.id}`}
                fwId={fw.id}
                c={c}
                view={vendor}
                obs={obs}
                analytics={analytics}
                promptAnalytics={promptAnalytics}
                guardrails={guardrails}
              />
            ))}
          </div>
          {vendorView && vObs && unreached.length > 0 && (
            <details className="rounded-2xl border border-line bg-surface px-4 py-3 text-[12px] text-muted shadow-sm">
              <summary className="cursor-pointer text-text">
                {unreached.length} {fw.label} control{unreached.length === 1 ? "" : "s"} not observed for {vendorName(vendorView)}
              </summary>
              <ul className="mt-2 flex flex-col gap-1">
                {unreached.map((c, i) => {
                  const caps = capabilitiesOf(fw.id, c.id);
                  return (
                    <li key={`${i}-${c.id}`}>
                      <span className="font-mono text-[11.5px] text-text">{c.id}</span> {c.title} —{" "}
                      {caps.length === 0
                        ? "a governance control: no vendor's traffic can show it"
                        : caps
                            .map((cap) => `${MATRIX.find((r) => r.id === cap)!.capability}: ${vObs.capabilities[cap].state.replace("-", " ")}`)
                            .join("; ")}
                    </li>
                  );
                })}
              </ul>
            </details>
          )}

          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 text-[11.5px] leading-relaxed text-muted shadow-sm">
            <ShieldCheck size={15} className="mt-0.5 shrink-0 text-cf-green-ink" />
            <p>
              Every observation above comes from traffic in this demo — load a matching prompt from the attack library and
              watch each layer's verdict, then check the same turn in{" "}
              <Link to="/analytics" className="text-accent-ink hover:underline">
                analytics
              </Link>
              , vendor by vendor. That request-to-evidence trail is what most of these controls actually ask for.
            </p>
          </div>
        </div>
      </main>

      <footer className="shrink-0 border-t border-line bg-surface px-5 py-2 text-[11.5px] text-muted">
        Framework text paraphrased for this demo · NIST AI RMF, OWASP and MITRE ATLAS are public · ISO/IEC 42001 is a
        paid standard (control group only) · Bank of Thailand and NCSA are Thai-language docs, section refs paraphrased.
      </footer>
    </div>
  );
}
