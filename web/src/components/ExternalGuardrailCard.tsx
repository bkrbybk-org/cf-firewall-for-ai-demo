// Chat-side rendering of the external guardrail pipeline (Prisma AIRS, CrowdStrike AIDR):
// the card for a turn a guardrail stopped, the card for a guardrail-only turn
// (model deliberately not called), and the small per-result chips on a reply.
//
// Amber on purpose: red is the edge WAF, purple is AI Gateway Guardrails, and
// this is a third control that runs inside the Worker after both the edge scan
// and before the model. A colour of its own is what lets someone looking at a
// blocked turn tell which layer actually stopped it.
//
// Three layouts, chosen per viewer in Settings → Your preferences (lib/cardLayout.ts): "columns" — a
// headline, then one bordered mini card per vendor — "compact", one row per vendor, and
// "table", one column per vendor and one row per field. Every fact comes from
// pipelineView() (lib/guardrailView.ts), so no layout re-decides what a result means.
import { Fragment, useEffect, useId, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Shield, ShieldAlert } from "lucide-react";
import { GuardrailRawResponses } from "./GuardrailRawResponses";
import { GuardrailReportPanel } from "./GuardrailReportPanel";
import { DEFAULT_CARD_LAYOUT, type CardLayout } from "../lib/cardLayout";
import {
  GUARDRAIL_ONLY_HEADLINE,
  pipelineView,
  providerLabel,
  vendorTableColumn,
  type PipelineView,
  type VendorView,
} from "../lib/guardrailView";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "../lib/types";

// Where this control sits — what the old card said in a paragraph, now carried by
// the header icon's tooltip and a screen-reader description so the card stays short.
const WHERE_IT_RUNS =
  "This check runs after the Cloudflare edge scan, inside the Worker — a separate control from both the edge WAF and AI Gateway Guardrails.";
const EXPLAIN_BLOCKED = `${WHERE_IT_RUNS} The prompt was not sent to the model.`;
// Design J: the reply check runs after the model, so the model did answer — and was paid
// for — but its reply never left the Worker.
const EXPLAIN_REPLY_WITHHELD =
  "This check runs inside the Worker after the model answered, on the model's reply. The model ran (its tokens and cost are real), but its reply was not shown — it never left the Worker.";
// Guardrail-only is a test result, not an answer: no reply, tokens or cost exist, and
// AI Gateway Guardrails did not run either — they are part of the model call.
const EXPLAIN_GUARDRAIL_ONLY = `${WHERE_IT_RUNS} The model was not called, so there is no reply, no tokens and no cost. AI Gateway Guardrails did not run either — they are part of the model call.`;

const MAX_CHIPS = 3;

// Verdicts are told apart by FILL AND SHAPE, not only hue. Amber stays this control's
// colour (red is the edge WAF, purple AI Gateway Guardrails), so a block cannot turn red
// here — and with every non-green verdict in amber outline, a block and a caveated allow
// read as the same thing side by side (reported 2026-10-06 on the table layout). Now:
//   block                      solid amber, dark text — the one filled pill
//   allow, complete            green outline
//   allow with a caveat        amber outline (redaction not applied, alerts only, incomplete)
//   no verdict (error)         DASHED amber outline — something to notice, but not a verdict
//   did not run                dashed grey
// Fill vs outline vs dashed survives colour blindness and greyscale; hue alone did not.
function pillClass(v: VendorView): string {
  if (v.state === "notRun") return "border-dashed border-line text-muted";
  if (v.state === "block") return "border-cf-amber bg-cf-amber text-[#1a1206]";
  if (v.state === "allow" && !v.partial) return "border-cf-green/50 bg-cf-green/10 text-cf-green";
  if (v.state === "allow") return "border-cf-amber/60 bg-cf-amber/10 text-cf-amber";
  return "border-dashed border-cf-amber/70 text-cf-amber";
}

// Findings in amber only when they caused a block. An allow's findings — what a
// vendor redacted or only alerted on — are information, not the reason for a stop,
// and painting them amber made an allow read like a block.
function findingText(v: VendorView): string {
  return v.state === "block" ? "font-semibold text-cf-amber" : "font-medium text-text";
}
function findingChip(v: VendorView): string {
  return v.state === "block"
    ? "border-cf-amber/60 bg-cf-amber/10 font-bold text-cf-amber"
    : "border-line bg-surface-2 font-semibold text-text";
}

// "decided": the one result that stopped the turn. "blocked independently": parallel mode,
// where two or more blocked and any one alone would have stopped it (VendorView.marker).
function Marker({ v }: { v: VendorView }) {
  if (!v.marker) return null;
  const independent = v.marker === "independent";
  return (
    <span
      title={
        independent
          ? "Ran in parallel with the others and blocked on its own — any one of these blocks would have stopped the turn"
          : "This result is the one that stopped the turn"
      }
      className="text-[10.5px] font-bold tracking-wider text-cf-amber uppercase"
    >
      {independent ? "blocked independently" : "decided"}
    </span>
  );
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
          : v.marker
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
        <Marker v={v} />
      </div>

      {v.findings.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {chips.map((f) => (
            <span
              key={f}
              className={`max-w-full rounded-full border px-2 py-0.5 text-[10.5px] break-words ${findingChip(v)}`}
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
        <Marker v={v} />
        {v.findings.length > 0 && (
          <span className={`min-w-0 text-[11.5px] break-words ${findingText(v)}`}>{v.findings.join(", ")}</span>
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

// Layout "table": one column per vendor, one row per field, so the vendors read side by
// side. Every cell comes from vendorTableColumn(), which keeps "found nothing" and "gave
// no verdict" apart. A row nobody has anything for (policy, reference, notes) is left out
// rather than drawn as a line of dashes. Five vendors outgrow a chat column, so the
// table scrolls sideways inside the card with the field names pinned — and SAYS so:
// macOS overlay scrollbars are invisible until used, so without the fade and the
// "N more" line a hidden fifth vendor simply looked absent.
//
// Detection names are vendor identifiers like `pii/us_social_security_number`; a break
// opportunity after each `/` and `_` lets them wrap at a separator instead of mid-word.
// Display only — ids (reference, policy) are never touched, since they get copied into
// a vendor's console search.
const breakable = (s: string) => s.replace(/([/_])/g, "$1\u200b");

// How many vendor columns are out of view on each side, and whether anything at all is
// clipped — re-measured on scroll and on resize. A column counts as "more" only when
// less than half of it shows: three columns with the last one's edge clipped read
// "1 more →" (2026-10-06) while all three were plainly on screen.
function useHiddenColumns(box: React.RefObject<HTMLDivElement | null>) {
  const [hidden, setHidden] = useState({ left: 0, right: 0, clippedLeft: false, clippedRight: false });
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => {
      const r = el.getBoundingClientRect();
      // The pinned field column covers the left edge, so "hidden on the left" is measured from its right side.
      const pinned = el.querySelector("thead th")?.getBoundingClientRect().right ?? r.left;
      const heads = [...el.querySelectorAll<HTMLElement>("thead th[data-vendor]")].map((th) => th.getBoundingClientRect());
      const shown = (h: DOMRect) => Math.max(0, Math.min(h.right, r.right) - Math.max(h.left, pinned)) / h.width;
      const next = {
        left: heads.filter((h) => h.left < pinned && shown(h) < 0.5).length,
        right: heads.filter((h) => h.right > r.right && shown(h) < 0.5).length,
        clippedLeft: el.scrollLeft > 1,
        clippedRight: el.scrollLeft + el.clientWidth < el.scrollWidth - 1,
      };
      setHidden((prev) =>
        prev.left === next.left &&
        prev.right === next.right &&
        prev.clippedLeft === next.clippedLeft &&
        prev.clippedRight === next.clippedRight
          ? prev
          : next,
      );
    };
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", measure);
      ro.disconnect();
    };
  }, [box]);
  return hidden;
}

function VendorTable({ vendors }: { vendors: VendorView[] }) {
  const boxRef = useRef<HTMLDivElement>(null);
  const hidden = useHiddenColumns(boxRef);
  const cols = vendors.map((v) => ({ v, c: vendorTableColumn(v) }));
  const cell = "border-t border-line px-2.5 py-1.5 align-top";
  const head = `${cell} sticky left-0 z-[1] bg-surface text-left text-[11px] font-semibold whitespace-nowrap text-subtle`;
  const dash = <span className="text-subtle">—</span>;
  const rows: { label: string; render: (x: (typeof cols)[number]) => React.ReactNode }[] = [
    {
      label: "Verdict",
      render: ({ v }) => (
        <div className="flex flex-col items-start gap-1">
          <span className={`rounded-full border px-2 py-px text-[10.5px] font-bold whitespace-nowrap ${pillClass(v)}`}>
            {v.stateLabel}
          </span>
          <Marker v={v} />
        </div>
      ),
    },
    {
      label: "Detections",
      render: ({ v, c }) =>
        Array.isArray(c.detections) ? (
          <ul className={`flex flex-col gap-0.5 ${findingText(v)}`}>
            {c.detections.map((d) => (
              <li key={d}>{breakable(d)}</li>
            ))}
          </ul>
        ) : c.detections === "—" ? (
          dash
        ) : (
          <span className="text-muted">{c.detections}</span>
        ),
    },
  ];
  if (cols.some(({ c }) => c.policy)) {
    rows.push({
      label: "Policy",
      render: ({ c }) => (c.policy ? <span className="font-mono text-[11px] break-all text-text">{c.policy}</span> : dash),
    });
  }
  if (cols.some(({ c }) => c.reference)) {
    rows.push({
      label: "Reference ID",
      // Each vendor's own field name: it is what you search for in that vendor's console.
      render: ({ c }) =>
        c.reference ? (
          <div>
            <div className="text-[10px] text-subtle">{c.reference.label}</div>
            <div className="font-mono text-[11px] break-all text-text">{c.reference.value}</div>
          </div>
        ) : (
          dash
        ),
    });
  }
  rows.push({ label: "Latency", render: ({ c }) => <span className="font-mono text-[11px] text-muted">{c.latency}</span> });
  if (cols.some(({ c }) => c.notes.length > 0)) {
    rows.push({
      label: "Notes",
      render: ({ c }) =>
        c.notes.length > 0 ? (
          <ul className="flex flex-col gap-1 text-[11px] text-cf-amber">
            {c.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        ) : (
          dash
        ),
    });
  }
  // Content-sized between 7.5rem and 11rem: a fixed 8rem made a three-sentence note
  // ~180px tall while a "—" column sat just as wide.
  const width = "w-max min-w-[7.5rem] max-w-[11rem]";
  // The column of the result that stopped the turn is tinted top to bottom, header included.
  const tint = (v: VendorView) => (v.marker ? "bg-cf-amber/[0.06]" : "");
  return (
    <div className="mt-3">
      {/* Not a scroller itself: it only anchors the edge fades, which must stay put while
          the table scrolls under them. */}
      <div className="relative">
        {/* `relative`: an overflow box must contain its own absolutely positioned
            descendants (CLAUDE.md, scroll containers). Focusable and named, so a keyboard
            user can scroll it — a scroll region with nothing focusable inside is otherwise
            unreachable without a mouse. */}
        <div
          ref={boxRef}
          tabIndex={0}
          role="region"
          aria-label="Guardrail results, one column per guardrail"
          className="relative overflow-x-auto rounded-xl border border-line bg-surface focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <table className="w-full border-collapse text-[11.5px]">
            <thead>
              <tr>
                <th scope="col" aria-label="Field" className="sticky left-0 z-[1] bg-surface px-2.5 py-1.5" />
                {cols.map(({ v }) => (
                  <th
                    key={v.provider}
                    data-vendor={v.provider}
                    scope="col"
                    title={v.fullName}
                    className={`px-2.5 py-1.5 text-left align-bottom font-bold ${tint(v)} ${v.state === "notRun" ? "text-muted" : "text-text"}`}
                  >
                    <div className={width}>{v.name}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.label}>
                  <th scope="row" className={head}>
                    {r.label}
                  </th>
                  {cols.map((x) => (
                    <td key={x.v.provider} className={`${cell} ${tint(x.v)}`}>
                      <div className={`${width} break-words`}>{r.render(x)}</div>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {hidden.clippedRight && (
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-px right-px w-10 rounded-r-xl bg-gradient-to-l from-surface to-transparent"
          />
        )}
      </div>
      {(hidden.clippedLeft || hidden.clippedRight) && (
        <p className="mt-1 text-right text-[11px] text-muted">
          <span className="text-subtle">Scroll sideways</span>
          {hidden.left > 0 && ` · ← ${hidden.left} more`}
          {hidden.right > 0 && ` · ${hidden.right} more →`}
          {hidden.left === 0 && hidden.right === 0 && (hidden.clippedRight ? " →" : " ←")}
        </p>
      )}
    </div>
  );
}

function PipelineBody({ view, layout, pipeline }: { view: PipelineView; layout: CardLayout; pipeline: GuardrailPipelineResult }) {
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
      {view.vendors.length > 0 && layout === "table" && <VendorTable vendors={view.vendors} />}
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
      <GuardrailRawResponses pipeline={pipeline} />
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
    <CardShell view={view} explainer={pipeline.direction === "reply" ? EXPLAIN_REPLY_WITHHELD : EXPLAIN_BLOCKED}>
      <PipelineBody view={view} layout={layout} pipeline={pipeline} />
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
      <PipelineBody view={view} layout={layout} pipeline={pipeline} />
    </CardShell>
  );
}

// Reply-metadata chips: one per provider result, from the pipeline that let the
// turn through. Renders nothing when there are no results (none enabled).
export function ExternalGuardrailBadges({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  return (
    <>
      {pipeline.results.map((r) => (
        <ExternalGuardrailBadge key={r.provider} result={r} reply={pipeline.direction === "reply"} />
      ))}
    </>
  );
}

// Reply-metadata chip for a turn the guardrail let through. Same size as the
// GUARDRAILS / ROUTE chips in Chat.tsx's meta row. A "block" or a fail-closed
// error never reaches here (those render the card), so they return nothing
// rather than a chip that would imply the reply was allowed.
// `reply` (design J): the chip is for the reply check, so it is named and worded for the reply.
export function ExternalGuardrailBadge({ result, reply = false }: { result: ExternalGuardrailResult; reply?: boolean }) {
  const name = reply ? `${providerLabel(result.provider)} (reply)` : providerLabel(result.provider);
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
          title={
            reply
              ? `${name} redacted part of this reply, but this app does not apply the redaction — the reply is shown as the model wrote it.`
              : `${name} redacted part of this prompt, but this app does not apply the redaction — the model received the original prompt.`
          }
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow · redaction not applied · {result.latencyMs} ms
        </span>
      );
    }
    // Lakera Guard in Detect mode: it logged detections but its project does not
    // block. Allow with alerts — amber, never the green of a clean pass.
    if (result.detectOnly) {
      const n = result.detected?.length ?? 0;
      return (
        <span
          title={`${name} ${result.provider === "cato-ai-security" ? "required no action" : "is in Detect mode"}: it logged ${n === 1 ? "a detection" : `${n} detections`} (${(result.detected ?? []).join(", ")}) but did not block.`}
          className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-0.5 text-[10.5px] font-bold text-cf-amber"
        >
          {name} · allow · {n} alert{n === 1 ? "" : "s"}
          {result.provider === "cato-ai-security" ? "" : " (Detect mode)"} · {result.latencyMs} ms
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
        {name} unavailable — {reply ? "reply shown unchecked" : "sent unscanned"}
      </span>
    );
  }
  return null;
}
