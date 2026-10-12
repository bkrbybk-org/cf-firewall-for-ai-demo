// Analytics → All vendors (vendor-agnostic, 2026-10-12): one row per vendor in this demo, Cloudflare's two products
// first (the demo runs on them), then every external guardrail — the same columns for all of them.
//
// The vendors do not all measure the same thing, and the table must not pretend they do:
//   - The edge records only requests a rule matched or scored — it has no "checks" count, and its rules act inline
//     (no outage, no call latency). AI Gateway logs every model call, but Guardrails' verdicts are not in the logs API.
//     The external guardrails record every check, its verdict and its round trip.
//   - So a cell the vendor's data cannot answer is "—" with the reason on hover — never 0, which would read as
//     "measured, and none". The traffic filter applies to the external guardrails only (the edge and the gateway cannot
//     tell a Red Team prompt from a chat one), and the note under the table says so.
//   - The marks travel: "≈" sampled, "≥" a floor, per source.
import { ArrowRight } from "lucide-react";
import { providerFullLabel } from "../../lib/guardrailView";
import { EXTERNAL_VENDORS } from "../../lib/vendorCapabilities";
import type {
  Analytics,
  ExternalGuardrailProvider,
  GatewayAnalytics,
  GuardrailAnalytics,
  GuardrailVendorStats,
} from "../../lib/types";
import { Card } from "./primitives";
import { SOURCE_LABEL } from "./GuardrailsTab";

export type VendorTab = "edge" | "gateway" | ExternalGuardrailProvider;

interface Cell {
  v: string; // the value, or "—"
  why?: string; // hover text: what it counts, or why there is nothing
}

interface Row {
  tab: VendorTab;
  vendor: string;
  layer: string;
  checks: Cell;
  blocks: Cell;
  flagged: Cell; // allowed with alerts (guardrails) / logged (edge)
  noVerdict: Cell;
  latency: Cell;
  note?: string;
}

const NA = (why: string): Cell => ({ v: "—", why });
const fmt = (mark: string, n: number) => `${mark}${Math.round(n).toLocaleString()}`;

export function edgeRow(edge: Analytics | null): Row {
  const base = { tab: "edge" as const, vendor: "Cloudflare AI Security for Apps", layer: "edge WAF, before the app" };
  const ai = edge?.aiSecurity;
  if (!edge?.configured || edge.error || !ai) {
    const why = !edge ? "loading" : edge.error ? `edge analytics error: ${edge.error}` : "edge analytics not configured";
    return { ...base, checks: NA(why), blocks: NA(why), flagged: NA(why), noVerdict: NA(why), latency: NA(why) };
  }
  // The AI Security rules' own tally (grouped, so uncapped; Cloudflare's estimates when sampled) — never zone-wide.
  const mark = ai.sampled ? "≈" : ai.capped ? "≥" : "";
  return {
    ...base,
    checks: NA("the edge records only the requests a rule matched or scored, so it has no count of requests checked"),
    blocks: { v: fmt(mark, ai.blocked), why: "requests the AI Security rules blocked (not other zone rules)" },
    flagged: { v: fmt(mark, ai.logged), why: "requests the AI Security rules logged without blocking" },
    noVerdict: NA("edge rules act inline — there is no outage to count"),
    latency: NA("inline at the edge — no separate call to time"),
    note: "every request to the hostname — cannot be split by traffic source",
  };
}

export function gatewayRow(gw: GatewayAnalytics | null): Row {
  const base = { tab: "gateway" as const, vendor: "Cloudflare AI Gateway", layer: "the model call" };
  if (!gw?.configured || gw.error) {
    const why = !gw ? "loading" : gw.error ? `gateway logs error: ${gw.error}` : "gateway logs not configured";
    return { ...base, checks: NA(why), blocks: NA(why), flagged: NA(why), noVerdict: NA(why), latency: NA(why) };
  }
  const mark = gw.truncated ? "≥" : "";
  return {
    ...base,
    checks: { v: fmt(mark, gw.requests ?? 0), why: `model calls through gateway ${gw.gatewayId ?? ""} (every call is logged)` },
    blocks: NA("AI Gateway Guardrails' verdicts are not in the gateway logs API this app reads"),
    flagged: NA("AI Gateway Guardrails' verdicts are not in the gateway logs API this app reads"),
    noVerdict: NA("gateway errors are failed model calls, not missing verdicts"),
    latency: NA("the gateway's latency is the model's, not a check's"),
    // No calls → no latency: "p50 0 ms" would be a measurement nobody made.
    note:
      (gw.requests ?? 0) > 0
        ? `${(gw.errors ?? 0).toLocaleString()} errors · p50 ${gw.p50Ms ?? "—"} ms model latency · one gateway, every source`
        : `no model call through gateway ${gw.gatewayId ?? ""} in the window`,
  };
}

export function guardrailRow(p: ExternalGuardrailProvider, gr: GuardrailAnalytics | null): Row {
  const base = { tab: p, vendor: providerFullLabel(p), layer: "external guardrail, before the model" };
  if (!gr || gr.configured === false || gr.error || !gr.totals) {
    const why = !gr ? "loading" : gr.error ? `verdict analytics error: ${gr.error}` : "verdict analytics not configured";
    return { ...base, checks: NA(why), blocks: NA(why), flagged: NA(why), noVerdict: NA(why), latency: NA(why) };
  }
  const mark = gr.sampled ? "≈" : gr.capped ? "≥" : "";
  const prompt: GuardrailVendorStats | undefined = gr.vendors.find((v) => v.provider === p && v.dir === "prompt");
  const reply = gr.vendors.find((v) => v.provider === p && v.dir === "reply");
  if (!prompt || prompt.checked === 0) {
    const why = "no prompt checked in this window (disabled, or no traffic)";
    return { ...base, checks: { v: "0", why }, blocks: NA(why), flagged: NA(why), noVerdict: NA(why), latency: NA(why) };
  }
  return {
    ...base,
    checks: { v: fmt(mark, prompt.checked), why: "prompts checked: block + allow + no verdict" },
    blocks: { v: fmt(mark, prompt.block), why: prompt.outvoted ? `${prompt.outvoted} outvoted (quorum mode)` : "prompts blocked" },
    flagged: { v: fmt(mark, prompt.alerts), why: "allowed with alerts: it saw something and did not block" },
    noVerdict: {
      v: fmt(mark, prompt.error + prompt.failedOpen),
      why: `${prompt.error} fail closed (turn stopped) · ${prompt.failedOpen} fail open (went on unchecked)`,
    },
    latency: prompt.p50Ms == null ? NA("nothing timed") : { v: `${Math.round(prompt.p50Ms)} ms`, why: `p50 over ${prompt.latencyN} timed checks` },
    note: reply && reply.checked > 0 ? `replies: ${fmt(mark, reply.checked)} checked · ${fmt(mark, reply.block)} withheld` : undefined,
  };
}

function Td({ c, strong }: { c: Cell; strong?: boolean }) {
  return (
    <td className={`py-2 pr-3 text-right font-mono tabular-nums ${c.v === "—" ? "text-subtle" : strong ? "font-bold text-text" : "text-muted"}`} title={c.why}>
      {c.v}
    </td>
  );
}

export function VendorsOverview({
  edge,
  gateway,
  guardrails,
  window,
  onPick,
}: {
  edge: Analytics | null;
  gateway: GatewayAnalytics | null;
  guardrails: GuardrailAnalytics | null;
  window: string;
  onPick: (t: VendorTab) => void;
}) {
  const rows = [edgeRow(edge), gatewayRow(gateway), ...EXTERNAL_VENDORS.map((p) => guardrailRow(p, guardrails))];
  return (
    <Card
      title="Every vendor, side by side"
      subtitle={`${window} · external guardrails: ${SOURCE_LABEL[guardrails?.source ?? "chat"]} · prompt checks (replies in the note)`}
    >
      {/* `relative`: the scroll box must contain its own absolutely positioned children (house style). */}
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[920px] border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-line text-left text-[11px] text-subtle">
              <th className="py-1.5 pr-3 font-semibold">Vendor</th>
              <th className="py-1.5 pr-3 font-semibold">Where it sits</th>
              <th className="py-1.5 pr-3 text-right font-semibold">checked</th>
              <th className="py-1.5 pr-3 text-right font-semibold">blocked</th>
              <th className="py-1.5 pr-3 text-right font-semibold" title="Allowed with alerts (guardrails) or logged (edge)">flagged, not blocked</th>
              <th className="py-1.5 pr-3 text-right font-semibold">no verdict</th>
              <th className="py-1.5 pr-3 text-right font-semibold">p50</th>
              <th className="py-1.5 font-semibold">note</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.tab} className="border-b border-line/60 align-top last:border-0">
                <td className="py-2 pr-3">
                  <button
                    type="button"
                    onClick={() => onPick(r.tab)}
                    className="inline-flex items-center gap-1 text-left font-semibold text-text hover:text-accent"
                    title={`Open ${r.vendor}'s page`}
                  >
                    {r.vendor} <ArrowRight size={12} className="shrink-0 text-subtle" />
                  </button>
                </td>
                <td className="py-2 pr-3 text-[11.5px] text-muted">{r.layer}</td>
                <Td c={r.checks} />
                <Td c={r.blocks} strong />
                <Td c={r.flagged} />
                <Td c={r.noVerdict} />
                <Td c={r.latency} />
                <td className="py-2 text-[11px] text-subtle">{r.note ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2.5 text-[11px] leading-relaxed text-subtle">
        A <b>—</b> means that vendor's data cannot answer the column — hover it for why — never zero. The edge sees every
        request to the hostname and the gateway every model call, whatever its source; the traffic filter narrows the
        external guardrails only. The vendors sit at different points of the request, so their counts are not shares of
        one total.
      </p>
    </Card>
  );
}
