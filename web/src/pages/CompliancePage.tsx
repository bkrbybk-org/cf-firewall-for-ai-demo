// Compliance mapping page: how AI Security for Apps and AI Gateway support
// NIST AI RMF, ISO 42001, OWASP LLM Top 10, MITRE ATLAS, plus the Thai
// frameworks (Bank of Thailand AI risk policy, NCSA AI Security Guidelines).
// Overview matrix on top, framework tabs with per-control detail below.
// All content lives in ../lib/compliance.ts — no mappings inline here.
//
// Evidence chips: a handful of controls (compliance.ts Control.evidence)
// carry a live audit metric alongside their static prose, resolved by
// ../lib/complianceEvidence.ts from the same two analytics payloads the
// Analytics page uses. Fetched once here, for a fixed window (EVIDENCE_HOURS
// below) — this page is not the place for a range picker, it just states
// which window it used. A failed or unconfigured fetch degrades silently:
// the controls themselves are static content and render regardless: only the
// chip disappears.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ArrowRight, ExternalLink, Info, ShieldCheck } from "lucide-react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { getAnalytics, getPromptAnalytics } from "../lib/api";
import {
  COVERAGE_HELP,
  COVERAGE_LABEL,
  FRAMEWORKS,
  MATRIX,
  PRODUCT_LABEL,
  type Coverage,
  type Evidence,
  type Product,
} from "../lib/compliance";
import { resolveEvidence } from "../lib/complianceEvidence";
import type { Analytics, PromptAnalytics } from "../lib/types";

// Fixed rather than user-picked: this page is an audit artifact, not a
// dashboard, and a moving range would make "what did the reviewer see"
// unreproducible. 24h matches the AnalyticsPage default.
const EVIDENCE_HOURS = 24;

const COVERAGE_TONE: Record<Coverage, string> = {
  full: "border-cf-green/50 bg-cf-green/10 text-cf-green",
  partial: "border-cf-amber/50 bg-cf-amber/10 text-cf-amber",
  supporting: "border-cf-blue/50 bg-cf-blue/10 text-cf-blue",
  none: "border-line bg-surface-2 text-subtle",
};
const COVERAGE_DOT: Record<Coverage, string> = {
  full: "bg-cf-green",
  partial: "bg-cf-amber",
  supporting: "bg-cf-blue",
  none: "bg-subtle",
};
const PRODUCT_TONE: Record<Product, string> = {
  "ai-security": "border-cf-blue/40 bg-cf-blue/10 text-cf-blue",
  "ai-gateway": "border-cf-purple/40 bg-cf-purple/10 text-cf-purple",
  both: "border-accent/40 bg-accent/10 text-accent",
  neither: "border-line bg-surface-2 text-subtle",
};

const COVERAGE_ORDER: Coverage[] = ["full", "partial", "supporting", "none"];

function CoverageBadge({ c }: { c: Coverage }) {
  return (
    <span
      title={COVERAGE_HELP[c]}
      className={`shrink-0 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${COVERAGE_TONE[c]}`}
    >
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

// Renders one of three states, deliberately distinct — see
// complianceEvidence.ts's header for why collapsing any two of them would be
// dishonest: "unconfigured" is nothing at all (the card falls back to its
// static prose), "no-data" is a muted note that the control simply wasn't
// exercised in this window, and "ok" is the real measured value.
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
      className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-cf-blue/30 bg-cf-blue/[0.06] px-2.5 py-1.5 text-[11px] text-cf-blue"
      title={r.floor ? "Row cap reached in this window — counts are a floor, not an exact total." : undefined}
    >
      <Activity size={12} className="mt-0.5 shrink-0" />
      <span>
        <b className="font-semibold">{r.headline}</b> · {r.windowLabel}
        {r.floor && " · floor (row cap reached)"}
      </span>
    </div>
  );
}

export function CompliancePage() {
  const [active, setActive] = useState(FRAMEWORKS[0].id);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [promptAnalytics, setPromptAnalytics] = useState<PromptAnalytics | null>(null);

  // Fetched once, best-effort. Either call failing must not surface as an
  // error state or a zero — it just leaves analytics/promptAnalytics null,
  // which resolveEvidence already reads as "unconfigured" (render nothing).
  useEffect(() => {
    let cancelled = false;
    getAnalytics(EVIDENCE_HOURS)
      .then((d) => !cancelled && setAnalytics(d))
      .catch(() => {});
    getPromptAnalytics({ hours: EVIDENCE_HOURS })
      .then((d) => !cancelled && setPromptAnalytics(d))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const fw = FRAMEWORKS.find((f) => f.id === active) ?? FRAMEWORKS[0];
  const sorted = [...fw.controls].sort(
    (a, b) => COVERAGE_ORDER.indexOf(a.coverage) - COVERAGE_ORDER.indexOf(b.coverage),
  );

  return (
    <div className="flex h-full flex-col">
      <Header
        title="Compliance Mapping"
        subtitle={<>How AI Security for Apps and AI Gateway support six AI risk frameworks (global + Thailand)</>}
        actions={<ThemeToggle />}
      />

      <main className="min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            <Info size={16} className="mt-0.5 shrink-0 text-cf-blue" />
            <p className="text-[12.5px] leading-relaxed text-muted">
              Cloudflare provides <b className="text-text">technical controls</b> that support these frameworks. Full
              compliance is an organizational program — governance, documentation and process — not a product. Coverage
              below is graded honestly, including controls these products do <b className="text-text">not</b> address.
              A few controls also carry a live evidence chip — a measured count from this zone's own last{" "}
              {EVIDENCE_HOURS}h of traffic, not a claim about traffic in general.
            </p>
          </div>

          {/* Overview matrix */}
          <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
            <h2 className="text-[13px] font-bold text-text">Coverage at a glance</h2>
            <div className="mt-0.5 text-[11.5px] text-muted">
              Cloudflare capability → the controls it maps to in each framework
            </div>
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[900px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-line-strong">
                    <th className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">
                      Capability
                    </th>
                    {FRAMEWORKS.map((f) => (
                      <th key={f.id} className="px-2 py-2 text-[11px] font-semibold tracking-wide text-subtle uppercase">
                        {f.short}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {MATRIX.map((row) => (
                    <tr key={row.capability} className="border-b border-line align-top last:border-0">
                      <td className="px-2 py-2.5">
                        <div className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                          <span
                            title={COVERAGE_LABEL[row.coverage]}
                            className={`h-2 w-2 shrink-0 rounded-full ${COVERAGE_DOT[row.coverage]}`}
                          />
                          {row.capability}
                        </div>
                        <div className="mt-0.5 pl-4 text-[11px] text-muted">{row.detail}</div>
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
                                  <span key={id} className="font-mono text-[11px] text-text">
                                    {id}
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
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-muted">
              {COVERAGE_ORDER.map((c) => (
                <span key={c} className="flex items-center gap-1.5" title={COVERAGE_HELP[c]}>
                  <span className={`h-2 w-2 rounded-full ${COVERAGE_DOT[c]}`} /> {COVERAGE_LABEL[c]}
                </span>
              ))}
            </div>
          </section>

          {/* Framework tabs */}
          <div className="flex flex-wrap gap-2">
            {FRAMEWORKS.map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setActive(f.id)}
                className={`rounded-full border px-3.5 py-1.5 text-[12.5px] transition ${
                  f.id === active
                    ? "border-accent bg-accent/12 font-bold text-accent"
                    : "border-line bg-surface text-muted hover:border-accent hover:text-text"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Active framework */}
          <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <h2 className="text-[14px] font-bold text-text">{fw.full}</h2>
              <a
                href={fw.url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[11.5px] text-accent hover:underline"
              >
                reference <ExternalLink size={11} />
              </a>
            </div>
            <p className="mt-1 text-[12px] leading-relaxed text-muted">{fw.blurb}</p>
            {fw.note && (
              <p className="mt-1.5 border-l-2 border-cf-amber/60 pl-2.5 text-[11.5px] leading-relaxed text-muted">
                {fw.note}
              </p>
            )}
          </section>

          <div className="grid gap-3 lg:grid-cols-2">
            {sorted.map((c, i) => (
              <article
                // Key includes the framework + index: control ids are not unique
                // (a framework may list the same section twice, e.g. two threats
                // under one clause), and scoping the key to `active` gives each
                // tab a fresh card subtree instead of reconciling across frameworks.
                key={`${active}-${i}-${c.id}`}
                className="animate-rise flex flex-col rounded-2xl border border-line bg-surface p-4 shadow-sm transition hover:border-line-strong"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-mono text-[11.5px] text-muted">{c.id}</div>
                    <h3 className="mt-0.5 text-[13.5px] leading-snug font-semibold text-text">{c.title}</h3>
                  </div>
                  <CoverageBadge c={c.coverage} />
                </div>
                <p className="mt-2 flex-1 text-[12.5px] leading-relaxed text-muted">{c.how}</p>
                {c.evidence && (
                  <EvidenceChip evidence={c.evidence} analytics={analytics} promptAnalytics={promptAnalytics} />
                )}
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  <ProductBadge p={c.product} />
                  {c.refs?.map((r) => <Ref key={r}>{r}</Ref>)}
                  {c.demo && (
                    <Link
                      to={c.demo.to}
                      className="ml-auto inline-flex items-center gap-1 text-[11.5px] text-accent hover:underline"
                    >
                      {c.demo.label} <ArrowRight size={12} />
                    </Link>
                  )}
                </div>
              </article>
            ))}
          </div>

          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 text-[11.5px] leading-relaxed text-muted shadow-sm">
            <ShieldCheck size={15} className="mt-0.5 shrink-0 text-cf-green" />
            <p>
              Every mapping above is exercised by this demo — load a matching prompt from the attack library and watch
              the edge verdict, then check the same event in{" "}
              <Link to="/analytics" className="text-accent hover:underline">
                analytics
              </Link>
              . That request-to-evidence trail is what most of these controls actually ask for.
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
