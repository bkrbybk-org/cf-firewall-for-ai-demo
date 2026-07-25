// Prompt log tab: SQL-GROUP-BY rollups over the whole log, then the raw
// PII-redacted rows. Expanding a row shows the redacted reply plus the live
// edge verdict (joined by cf-ray via <Verdict>), so a prompt sits next to
// exactly what the edge detected on it.
import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ChevronDown,
  ChevronRight,
  MessagesSquare,
  Route,
  ShieldCheck,
  ShieldX,
  Trash2,
  UserSearch,
} from "lucide-react";
import { BarList, Card, Tile } from "./primitives";
import { EventSeries, PLOG_SERIES } from "./EventSeries";
import { Verdict } from "../Verdict";
import type { PromptAnalytics, PromptLog, PromptLogRow as PromptLogRowData } from "../../lib/types";

const OUTCOME_TONE: Record<string, string> = {
  reply: "border-cf-green/50 text-cf-green",
  guardrails: "border-cf-purple/50 text-cf-purple",
  error: "border-cf-red/50 text-cf-red",
};

function PromptLogRowView({ r }: { r: PromptLogRowData }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-line bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-[12px]"
      >
        {open ? <ChevronDown size={13} className="shrink-0 text-subtle" /> : <ChevronRight size={13} className="shrink-0 text-subtle" />}
        <span className="shrink-0 font-mono text-[11px] text-subtle tabular-nums">
          {new Date(r.ts).toLocaleString("en-GB", { hour12: false })}
        </span>
        <span className={`shrink-0 rounded-full border px-1.5 py-px text-[10px] font-semibold ${OUTCOME_TONE[r.outcome] ?? "border-line text-muted"}`}>
          {r.outcome}
        </span>
        <span className="shrink-0 rounded-full border border-line px-1.5 py-px text-[10px] text-muted">
          {r.route === "gateway" ? "AI Gateway" : "Workers AI"}
        </span>
        <span className="min-w-0 flex-1 truncate text-text">{r.prompt}</span>
        {r.redactions > 0 && (
          <span className="shrink-0 rounded-full border border-cf-amber/50 px-1.5 py-px text-[10px] font-semibold text-cf-amber">
            {r.redactions} redacted
          </span>
        )}
      </button>
      {open && (
        <div className="flex flex-col gap-2.5 border-t border-line px-3 py-2.5 text-[12px]">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">Prompt (redacted)</div>
            <div className="rounded-lg border border-line bg-bg px-2.5 py-1.5 whitespace-pre-wrap break-words text-text">
              {r.prompt}
            </div>
          </div>
          {r.reply != null ? (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-subtle">Reply (redacted)</div>
              <div className="rounded-lg border border-line bg-bg px-2.5 py-1.5 whitespace-pre-wrap break-words text-muted">
                {r.reply || "(empty)"}
              </div>
            </div>
          ) : (
            <div className="text-[11px] text-subtle">
              Reply not captured{r.outcome === "reply" ? " (streamed)" : ""}.
            </div>
          )}
          <div className="text-[11px] text-subtle">
            <span className="font-mono">{r.model}</span>
            {r.gatewayId && <> · gateway <span className="font-mono">{r.gatewayId}</span></>}
            {r.promptTokens != null && <> · {(r.promptTokens ?? 0) + (r.completionTokens ?? 0)} tok</>}
          </div>
          {/* The cf-ray join to the live edge verdict — the whole point. */}
          <Verdict ray={r.ray} prompt={r.prompt} />
        </div>
      )}
    </div>
  );
}

// Rollups over the whole prompt log (SQL GROUP BY in D1). Sits above the raw
// rows so the tab answers "what has been sent overall" before "what exactly".
function PromptStats({ a }: { a: PromptAnalytics }) {
  const total = a.total ?? 0;
  if (total === 0) return null;
  const withPii = a.withPii ?? 0;
  const piiPct = Math.round((withPii / total) * 100);
  const blocked = (a.byOutcome ?? []).find((o) => o.outcome === "guardrails")?.count ?? 0;
  const gateway = (a.byRoute ?? []).find((r) => r.route === "gateway")?.count ?? 0;
  const span =
    a.firstTs && a.lastTs
      ? `${new Date(a.firstTs).toLocaleString("en-GB", { hour12: false })} → ${new Date(a.lastTs).toLocaleString("en-GB", { hour12: false })}`
      : "";

  return (
    <>
      <div className="flex flex-wrap gap-3">
        <Tile
          label="prompts logged"
          value={total}
          icon={<MessagesSquare size={16} className="text-cf-blue" />}
          tone="border-cf-blue/40 bg-cf-blue/10"
        />
        <Tile
          label={`carried PII (${piiPct}%)`}
          value={withPii}
          icon={<UserSearch size={16} className="text-cf-purple" />}
          tone="border-cf-purple/40 bg-cf-purple/10"
        />
        <Tile
          label="guardrails-blocked"
          value={blocked}
          icon={<ShieldX size={16} className="text-cf-red" />}
          tone="border-cf-red/40 bg-cf-red/10"
        />
        <Tile
          label={`via AI Gateway (of ${total})`}
          value={gateway}
          icon={<Route size={16} className="text-cf-green" />}
          tone="border-cf-green/40 bg-cf-green/10"
        />
      </div>

      {(a.series ?? []).length > 0 && (
        <Card title="Prompts over time" subtitle={`per ${a.bucket === "day" ? "day" : "hour"} · by outcome${span ? ` · ${span}` : ""}`}>
          <EventSeries rows={a.series ?? []} bucket={a.bucket} defs={PLOG_SERIES} ariaLabel="Prompts over time" />
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Prompts by model" subtitle="with tokens consumed">
          <BarList
            rows={(a.byModel ?? []).map((m) => ({
              name: m.model,
              sub: `${m.promptTokens + m.completionTokens} tok`,
              count: m.count,
              barCls: "bg-cf-blue",
            }))}
          />
        </Card>
        <Card title="Route split" subtitle="Workers AI direct vs routed via AI Gateway">
          <BarList
            rows={(a.byRoute ?? []).map((r) => ({
              name: r.route === "gateway" ? "AI Gateway" : "Workers AI (direct)",
              count: r.count,
              barCls: r.route === "gateway" ? "bg-cf-green" : "bg-subtle",
            }))}
          />
        </Card>
      </div>

      {(a.repeated ?? []).length > 0 && (
        <Card
          title="Repeated prompts"
          subtitle="same text sent more than once — autopilot reruns and replayed attacks"
        >
          <BarList
            rows={(a.repeated ?? []).map((r) => ({
              name: r.prompt.length > 90 ? r.prompt.slice(0, 90) + "…" : r.prompt,
              sub: r.redactions > 0 ? `${r.redactions} redacted` : undefined,
              count: r.count,
              barCls: "bg-cf-amber",
            }))}
          />
        </Card>
      )}
    </>
  );
}

export function PromptLogTab({ d, a, onClear }: { d: PromptLog | null; a: PromptAnalytics | null; onClear: () => void }) {
  const [confirming, setConfirming] = useState(false);

  if (d?.configured === false)
    return (
      <Card title="Prompt log not configured">
        <p className="text-sm text-muted">
          Bind a D1 database as <code className="font-mono">DB</code> and apply the migration:
        </p>
        <pre className="mt-2 overflow-x-auto rounded-lg border border-line bg-bg p-2.5 font-mono text-[11px] text-muted">
          npx wrangler d1 migrations apply cf-ai-waf-demo-log --remote
        </pre>
      </Card>
    );
  if (d?.error)
    return (
      <Card title="Prompt log error">
        <p className="text-sm text-cf-red">{d.error}</p>
      </Card>
    );
  if (!d)
    return (
      <Card title="Loading…">
        <p className="text-sm text-muted">Reading prompt log…</p>
      </Card>
    );

  const rows = d.rows ?? [];
  return (
    <>
      {a && !a.error && <PromptStats a={a} />}

      <Card title="About this log" subtitle={`${d.total ?? 0} prompt${(d.total ?? 0) === 1 ? "" : "s"} stored`}>
        <p className="text-[12px] leading-relaxed text-muted">
          Every prompt that <b className="text-text">reached the Worker</b> is stored here with PII{" "}
          <b className="text-text">redacted</b> (card, IBAN, email, phone, IP, wallet, Thai national ID). Each row joins
          to the live edge verdict by <code className="font-mono">cf-ray</code> — expand one to see the detections that
          fired on that exact prompt. Edge-blocked (403) requests never reach the Worker, so they are not here; see the{" "}
          <b className="text-text">AI Security (edge)</b> tab for those.
          <br />
          <span className="text-subtle">
            Note: redaction protects this store only. AI Gateway still logs the raw prompt + response payload (visible in
            the dashboard) — that is a separate control.
          </span>
        </p>
        <div className="mt-3">
          {confirming ? (
            <span className="inline-flex items-center gap-2 text-[12px]">
              <span className="text-muted">Clear all {d.total ?? 0} rows?</span>
              <button
                type="button"
                onClick={() => {
                  setConfirming(false);
                  onClear();
                }}
                className="rounded-full bg-cf-red px-3 py-1 text-[11.5px] font-semibold text-white"
              >
                Yes, clear
              </button>
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="rounded-full border border-line px-3 py-1 text-[11.5px] text-muted hover:text-text"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={() => setConfirming(true)}
              disabled={rows.length === 0}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-muted transition hover:border-cf-red hover:text-cf-red disabled:opacity-50"
            >
              <Trash2 size={13} /> Clear log
            </button>
          )}
        </div>
      </Card>

      {rows.length === 0 ? (
        <Card title="No prompts logged yet">
          <div className="flex items-start gap-3 text-sm text-muted">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-cf-green" />
            <p>
              Send a prompt from the{" "}
              <Link to="/" className="text-accent hover:underline">
                Firewall page
              </Link>{" "}
              (either route) and it appears here. Local dev has no <code className="font-mono">cf-ray</code>, so the
              per-row verdict shows "pending".
            </p>
          </div>
        </Card>
      ) : (
        <div className="flex flex-col gap-2">
          {rows.map((r) => (
            <PromptLogRowView key={r.ray} r={r} />
          ))}
        </div>
      )}
    </>
  );
}
