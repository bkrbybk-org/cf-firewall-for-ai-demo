// Chat-side rendering of the external guardrail pipeline (Prisma AIRS, CrowdStrike AIDR):
// the card for a turn a guardrail stopped, the card for a guardrail-only turn
// (model deliberately not called), and the small per-result chips on a reply.
//
// Amber on purpose: red is the edge WAF, purple is AI Gateway Guardrails, and
// this is a third control that runs inside the Worker after both the edge scan
// and before the model. A colour of its own is what lets someone looking at a
// blocked turn tell which layer actually stopped it.
//
// Two layouts, chosen per viewer on /guardrails (lib/cardLayout.ts): "columns" — a
// headline, then one bordered mini card per vendor — and "compact", one row per vendor.
// Every fact comes from pipelineView() (lib/guardrailView.ts), so neither layout
// re-decides what a result means.
import { Fragment, useId, useState } from "react";
import { ChevronDown, ChevronRight, Shield, ShieldAlert } from "lucide-react";
import { GuardrailReportPanel } from "./GuardrailReportPanel";
import { DEFAULT_CARD_LAYOUT, type CardLayout } from "../lib/cardLayout";
import {
  GUARDRAIL_ONLY_HEADLINE,
  pipelineView,
  providerLabel,
  type PipelineView,
  type VendorView,
} from "../lib/guardrailView";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "../lib/types";

// Where this control sits — what the old card said in a paragraph, now carried by
// the header icon's tooltip and a screen-reader description so the card stays short.
const WHERE_IT_RUNS =
  "This check runs after the Cloudflare edge scan, inside the Worker — a separate control from both the edge WAF and AI Gateway Guardrails.";
const EXPLAIN_BLOCKED = `${WHERE_IT_RUNS} The prompt was not sent to the model.`;
// Guardrail-only is a test result, not an answer: no reply, tokens or cost exist, and
// AI Gateway Guardrails did not run either — they are part of the model call.
const EXPLAIN_GUARDRAIL_ONLY = `${WHERE_IT_RUNS} The model was not called, so there is no reply, no tokens and no cost. AI Gateway Guardrails did not run either — they are part of the model call.`;

const MAX_CHIPS = 3;

function pillClass(v: VendorView): string {
  if (v.state === "notRun") return "border-dashed border-line text-muted";
  // An allow that covers less than it reads (incomplete scan, redaction not applied)
  // is amber, never the green of a complete pass.
  if (v.state === "allow" && !v.partial) return "border-cf-green/50 bg-cf-green/10 text-cf-green";
  return "border-cf-amber/60 bg-cf-amber/10 text-cf-amber";
}

function VendorColumn({ v }: { v: VendorView }) {
  const [showAll, setShowAll] = useState(false);
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  const notRun = v.state === "notRun";
  const chips = showAll ? v.findings : v.findings.slice(0, MAX_CHIPS);
  const hidden = v.findings.length - MAX_CHIPS;
  return (
    <li
      className={`min-w-0 rounded-xl border p-2.5 ${
        notRun
          ? "border-dashed border-line"
          : v.decided
            ? "border-cf-amber bg-surface/70 ring-1 ring-cf-amber/30"
            : "border-line bg-surface/70"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span title={v.fullName} className="font-bold text-text">
          {v.name}
        </span>
        <span className={`rounded-full border px-2 py-px text-[10.5px] font-bold whitespace-nowrap ${pillClass(v)}`}>
          {v.stateLabel}
        </span>
        {v.decided && (
          <span
            title="This result is the one that stopped the turn"
            className="text-[10.5px] font-bold tracking-wider text-cf-amber uppercase"
          >
            decided
          </span>
        )}
      </div>

      {v.findings.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {chips.map((f) => (
            <span
              key={f}
              className="max-w-full rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold break-words text-cf-amber"
            >
              {f}
            </span>
          ))}
          {hidden > 0 && (
            <button
              type="button"
              onClick={() => setShowAll((s) => !s)}
              aria-expanded={showAll}
              className="rounded-full border border-line px-2 py-0.5 text-[10.5px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {showAll ? "show fewer" : `+${hidden} more`}
            </button>
          )}
        </div>
      )}

      {v.latencyMs != null && <div className="mt-1.5 font-mono text-[11px] text-muted">{v.latencyMs} ms</div>}

      {v.notes.length > 0 && (
        <ul className="mt-1.5 flex flex-col gap-1 text-[11.5px] text-cf-amber">
          {v.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}

      {v.details.length > 0 &&
        (notRun ? (
          // One short reason: shown outright, a collapsed disclosure would hide the
          // only thing worth saying about a guardrail that never ran.
          <DetailList details={v.details} className="mt-1.5" />
        ) : (
          <div className="mt-1.5">
            <button
              type="button"
              onClick={() => setOpen((o) => !o)}
              aria-expanded={open}
              aria-controls={detailsId}
              className="inline-flex items-center gap-1 rounded-md text-[11.5px] font-semibold text-muted transition-colors hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              details
            </button>
            {open && <DetailList id={detailsId} details={v.details} className="mt-1" />}
          </div>
        ))}
    </li>
  );
}

function DetailList({ details, className, id }: { details: VendorView["details"]; className?: string; id?: string }) {
  return (
    // The ids here are what you search for in the vendor's console (Strata Cloud
    // Manager, the Falcon console) to open its own report, so they are shown whole.
    <dl id={id} className={`grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-0.5 text-[11px] ${className ?? ""}`}>
      {details.map((d) => (
        <Fragment key={d.label}>
          <dt className="text-subtle">{d.label}</dt>
          <dd className={`m-0 ${d.mono ? "font-mono break-all text-text" : "break-words text-muted"}`}>{d.value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

// Shared frame: tone decides amber vs neutral, and the explanatory sentence lives in
// the icon's tooltip + a screen-reader description rather than as visible prose.
function CardShell({
  view,
  explainer,
  children,
}: {
  view: Pick<PipelineView, "headline" | "tone" | "subline">;
  explainer: string;
  children?: React.ReactNode;
}) {
  const headId = useId();
  const descId = useId();
  const warn = view.tone === "warning";
  return (
    // A definite width (not max-width) so the vendor grid below can query the card's
    // own size: the chat column is ~380px on a desktop split, where a viewport
    // breakpoint would still squeeze two columns side by side.
    <section
      aria-labelledby={headId}
      aria-describedby={descId}
      className={`animate-rise w-[min(92%,720px)] self-start rounded-2xl border p-4 text-sm shadow-sm ${
        warn ? "border-cf-amber/60 bg-cf-amber/10" : "border-line bg-surface-2"
      }`}
    >
      <div className="flex items-start gap-2">
        <span title={explainer} className={`mt-0.5 shrink-0 cursor-help ${warn ? "text-cf-amber" : "text-muted"}`}>
          {warn ? <ShieldAlert size={16} aria-hidden="true" /> : <Shield size={16} aria-hidden="true" />}
        </span>
        <div className="min-w-0">
          <div id={headId} className={`font-bold ${warn ? "text-cf-amber" : "text-text"}`}>
            {view.headline}
          </div>
          <div className="text-[11.5px] text-muted">{view.subline}</div>
        </div>
      </div>
      <span id={descId} className="sr-only">
        {explainer}
      </span>
      {children}
    </section>
  );
}

// Layout "compact rows" (option A): one line per vendor, every id and config name
// behind a single Details disclosure. Same view model as the columns, so the two
// cannot disagree on what a result means — only on how much of it is on screen.
// What compact does NOT hide: the decided marker, every finding (as text, not
// chips) and the honesty notes, which say a verdict covers less than it reads.
function CompactRow({ v }: { v: VendorView }) {
  const notRun = v.state === "notRun";
  const reason = notRun ? v.details.find((d) => d.label === "reason")?.value : undefined;
  return (
    <li className="min-w-0 py-1.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <span title={v.fullName} className={`font-bold ${notRun ? "text-muted" : "text-text"}`}>
          {v.name}
        </span>
        <span className={`rounded-full border px-2 py-px text-[10.5px] font-bold whitespace-nowrap ${pillClass(v)}`}>
          {v.stateLabel}
        </span>
        {v.decided && (
          <span
            title="This result is the one that stopped the turn"
            className="text-[10.5px] font-bold tracking-wider text-cf-amber uppercase"
          >
            decided
          </span>
        )}
        {v.findings.length > 0 && (
          <span className="min-w-0 text-[11.5px] font-semibold break-words text-cf-amber">{v.findings.join(", ")}</span>
        )}
        {/* A guardrail that never ran has one thing to say — why — so it stays on the row. */}
        {reason && <span className="min-w-0 text-[11.5px] break-words text-muted">{reason}</span>}
        {v.latencyMs != null && <span className="ml-auto font-mono text-[11px] text-muted">{v.latencyMs} ms</span>}
      </div>
      {v.notes.length > 0 && (
        <ul className="mt-0.5 flex flex-col gap-0.5 text-[11px] text-cf-amber">
          {v.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

function CompactDetails({ vendors }: { vendors: VendorView[] }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  // A notRun vendor's only detail is its reason, already on its row.
  const withDetails = vendors.filter((v) => v.state !== "notRun" && v.details.length > 0);
  if (withDetails.length === 0) return null;
  return (
    <div className="mt-1.5">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={id}
        className="inline-flex items-center gap-1 rounded-md text-[11.5px] font-semibold text-muted transition-colors hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        Details
      </button>
      {open && (
        <div id={id} className="mt-1 flex flex-col gap-2">
          {withDetails.map((v) => (
            <div key={v.provider} className="min-w-0">
              <div className="text-[11px] font-semibold text-text">{v.name}</div>
              <DetailList details={v.details} className="mt-0.5" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function PipelineBody({ view, layout }: { view: PipelineView; layout: CardLayout }) {
  const withReport = view.vendors.filter((v) => v.reportId);
  return (
    <>
      {view.caveat && <div className="mt-2 text-[11.5px] text-cf-amber">{view.caveat}</div>}
      {view.why && (
        <div className="mt-2 text-[11.5px] text-muted">
          <span className="font-semibold text-text">Where they differ:</span> {view.why}
        </div>
      )}
      {view.vendors.length > 0 && layout === "compact" && (
        <>
          <ul className="mt-2 divide-y divide-line border-y border-line">
            {view.vendors.map((v) => (
              <CompactRow key={v.provider} v={v} />
            ))}
          </ul>
          <CompactDetails vendors={view.vendors} />
        </>
      )}
      {view.vendors.length > 0 && layout === "columns" && (
        <div className="@container mt-3">
          <ul
            className={`grid grid-cols-1 gap-2 ${view.vendors.length > 1 ? "@[26rem]:grid-cols-2" : ""}`}
          >
            {view.vendors.map((v) => (
              <VendorColumn key={v.provider} v={v} />
            ))}
          </ul>
        </div>
      )}
      {/* Full width below the columns, not inside one: the report lists several
          detections with details, which a ~200px column would crush into
          word-per-line text, and the panel already names its vendor. */}
      {withReport.map((v) => (
        <GuardrailReportPanel key={v.reportId} reportId={v.reportId!} />
      ))}
    </>
  );
}

export function ExternalGuardrailBlockedCard({
  pipeline,
  layout = DEFAULT_CARD_LAYOUT,
}: {
  pipeline: GuardrailPipelineResult;
  layout?: CardLayout;
}) {
  const view = pipelineView(pipeline, "blocked");
  return (
    <CardShell view={view} explainer={EXPLAIN_BLOCKED}>
      <PipelineBody view={view} layout={layout} />
    </CardShell>
  );
}

// Guardrail-only mode: the prompt passed the edge and every enabled external
// guardrail and the model was deliberately NOT called. This is a test result,
// not an answer. Neutral unless a guardrail blocked or was unreachable — when
// nothing external ran, no amber control did anything.
export function GuardrailOnlyCard({
  pipeline,
  layout = DEFAULT_CARD_LAYOUT,
}: {
  pipeline?: GuardrailPipelineResult;
  layout?: CardLayout;
}) {
  if (!pipeline) {
    return (
      <CardShell
        view={{ headline: GUARDRAIL_ONLY_HEADLINE, tone: "neutral", subline: "model not called" }}
        explainer={EXPLAIN_GUARDRAIL_ONLY}
      >
        <div className="mt-2 text-[11px] text-muted">The response carried no pipeline detail.</div>
      </CardShell>
    );
  }
  const view = pipelineView(pipeline, "guardrailOnly");
  return (
    <CardShell view={view} explainer={EXPLAIN_GUARDRAIL_ONLY}>
      <PipelineBody view={view} layout={layout} />
    </CardShell>
  );
}

// Reply-metadata chips: one per provider result, from the pipeline that let the
// turn through. Renders nothing when there are no results (none enabled).
export function ExternalGuardrailBadges({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  return (
    <>
      {pipeline.results.map((r) => (
        <ExternalGuardrailBadge key={r.provider} result={r} />
      ))}
    </>
  );
}

// Reply-metadata chip for a turn the guardrail let through. Same size as the
// GUARDRAILS / ROUTE chips in Chat.tsx's meta row. A "block" or a fail-closed
// error never reaches here (those render the card), so they return nothing
// rather than a chip that would imply the reply was allowed.
export function ExternalGuardrailBadge({ result }: { result: ExternalGuardrailResult }) {
  const name = providerLabel(result.provider);
  if (result.outcome === "allow") {
    // An allow from a scan where a detection service timed out or errored only
    // covers what did run, so it gets the amber "partial" tone rather than the
    // green of a complete pass.
    // AIDR wanted part of the prompt redacted, but this app forwards the
    // original — so the model saw what AIDR would have masked. Amber, and said
    // in words, never a clean green pass.
    if (result.transformed) {
      return (
        <span
          title={`${name} redacted part of this prompt, but this app does not apply the redaction — the model received the original prompt.`}
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow · redaction not applied · {result.latencyMs} ms
        </span>
      );
    }
    if (result.incomplete) {
      return (
        <span
          title="Prisma AIRS returned a verdict, but at least one of its detection services timed out or errored — the allow covers only the checks that ran."
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow (incomplete scan){result.category ? ` · ${result.category}` : ""} · {result.latencyMs} ms
        </span>
      );
    }
    return (
      <span className="rounded-full border border-cf-green/60 bg-cf-green/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-green">
        {name} · allow
        {result.category ? ` · ${result.category}` : ""} · {result.latencyMs} ms
      </span>
    );
  }
  if (result.outcome === "error" && result.failedOpen) {
    return (
      <span
        title={result.error}
        className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
      >
        {name} unavailable — sent unscanned
      </span>
    );
  }
  return null;
}
