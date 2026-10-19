// Settings → System → Deployment: the system settings that are NOT editable here.
// They are Worker vars, secrets and bindings, fixed when the Worker is deployed —
// shown read-only so an operator can see why a feature is off without opening
// wrangler.jsonc. Every value is read live from the running Worker
// (/api/external-guardrails and /api/models); nothing is assumed. A value the
// Worker does not report is said to be unknown, never guessed — e.g. whether
// CF_AIG_TOKEN is set is not exposed, so it is not listed.
import { useState, type ReactNode } from "react";
import type { ExternalGuardrailsState, GatewayOption, ModelsResponse } from "../../lib/types";
import { PROVIDER_LABELS } from "../../lib/guardrailView";
import { CLOUDFLARE_LINKS, type ProductLink } from "../../lib/productLinks";
import { ProductLinks } from "../ProductLinks";
import { PANEL } from "./primitives";

type Tone = "on" | "off" | "neutral" | "unknown";

function Value({ tone, children }: { tone: Tone; children: ReactNode }) {
  const cls =
    tone === "on"
      ? "border-cf-green/50 text-cf-green-ink"
      : tone === "off"
        ? "border-line-strong text-muted"
        : tone === "unknown"
          ? "border-dashed border-line-strong text-subtle"
          : "border-line text-text";
  return <span className={`inline-block rounded-full border px-2.5 py-0.5 text-[11.5px] font-semibold ${cls}`}>{children}</span>;
}

function Row({
  label,
  value,
  detail,
  setBy,
  product,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  setBy: ReactNode;
  product?: { name: string; links: ProductLink[] }; // the Cloudflare product behind the setting: console and docs
}) {
  return (
    <div className="grid gap-1.5 border-t border-line px-4 py-3 first:border-t-0 sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)_minmax(0,16rem)] sm:gap-4">
      <div className="min-w-0">
        <div className="text-[13px] font-semibold text-text">{label}</div>
        {product && (
          <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 text-[11px] text-subtle">
            {product.name}
            <ProductLinks product={`Cloudflare ${product.name}`} links={product.links} />
          </div>
        )}
      </div>
      <div className="min-w-0">
        {value}
        {detail && <div className="mt-1 text-[11.5px] leading-relaxed text-muted">{detail}</div>}
      </div>
      <div className="min-w-0 text-[11.5px] leading-relaxed text-subtle">
        <span className="sm:hidden">Set by: </span>
        {setBy}
      </div>
    </div>
  );
}

const code = (s: string) => <code className="font-mono text-[11px] text-muted">{s}</code>;

// The alert webhook's body shape (src/alertDelivery.ts), as the operator would name it.
const FORMAT_NAMES = { slack: "Slack", teams: "Teams", discord: "Discord", json: "generic JSON" } as const;

// An account can hold many gateways; the Worker lists the two demo gateways first,
// so the first few are the ones that matter and the rest wait behind a toggle.
const GATEWAYS_SHOWN = 3;
function GatewayList({ gateways }: { gateways: GatewayOption[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? gateways : gateways.slice(0, GATEWAYS_SHOWN);
  const rest = gateways.length - GATEWAYS_SHOWN;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {shown.map((g) => (
        <Value key={g.id} tone="neutral">
          {g.id}
          {g.guarded ? " · Guardrails" : ""}
        </Value>
      ))}
      {rest > 0 && (
        <button
          type="button"
          onClick={() => setAll((v) => !v)}
          aria-expanded={all}
          className="rounded-full px-1.5 text-[11.5px] font-semibold text-accent-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {all ? "Show fewer" : `+${rest} more`}
        </button>
      )}
    </span>
  );
}

export function DeploymentPanel({
  state,
  models,
  modelsErr,
}: {
  state: ExternalGuardrailsState | null;
  models: ModelsResponse | null;
  modelsErr: boolean;
}) {
  const unknown = <Value tone="unknown">{modelsErr ? "could not read" : "loading…"}</Value>;
  const log = models?.promptLog;
  return (
    <div className={PANEL}>
      <div className="hidden grid-cols-[minmax(0,14rem)_minmax(0,1fr)_minmax(0,16rem)] gap-4 px-4 pt-3 text-[10.5px] font-semibold tracking-wide text-subtle uppercase sm:grid">
        <div>Setting</div>
        <div>Value now</div>
        <div>Set by</div>
      </div>

      <Row
        label="Guardrail settings storage"
        value={
          state == null ? (
            <Value tone="unknown">loading…</Value>
          ) : state.configured ? (
            <Value tone="on">Ready</Value>
          ) : (
            <Value tone="off">Not set up</Value>
          )
        }
        detail={
          state && !state.configured
            ? state.setupHint || state.error
            : "Provider keys are stored encrypted in D1; they are never sent back to the browser."
        }
        setBy={<>D1 binding {code("DB")} and secret {code("GUARDRAIL_SECRET_KEY")}</>}
        product={{ name: "D1", links: CLOUDFLARE_LINKS.d1 }}
      />

      {/* #15 / #17. Both run on Cloudflare's schedule, not on a page load — so the panel says what is set up, and the
          last state the outage check stored, never a live "it ran". */}
      <Row
        label="Scheduled checks"
        value={
          !state?.automation ? (
            <Value tone="unknown">{state ? "not reported" : "loading…"}</Value>
          ) : (
            <span className="flex flex-wrap items-center gap-1.5">
              <Value tone="on">Re-run every 6h</Value>
              <Value tone={state.automation.alerts.webhook === "set" ? "on" : "off"}>
                Outage alerts:{" "}
                {state.automation.alerts.webhook === "set"
                  ? `webhook${state.automation.alerts.webhookFormat ? ` (${FORMAT_NAMES[state.automation.alerts.webhookFormat]})` : ""}`
                  : state.automation.alerts.webhook === "invalid"
                    ? "webhook invalid — logs only"
                    : "logs only"}
              </Value>
              {/* The smoke prompt's canary (src/smokeCanary.ts): a block here means the next npm run smoke:prod fails. */}
              {state.automation.smokeCanary && state.automation.smokeCanary.checked.length > 0 && (
                <Value tone={state.automation.smokeCanary.blockedBy.length ? "off" : "on"}>
                  {state.automation.smokeCanary.blockedBy.length
                    ? `Smoke prompt blocked by ${state.automation.smokeCanary.blockedBy.map((p) => PROVIDER_LABELS[p] ?? p).join(", ")}`
                    : "Smoke prompt: allowed by all"}
                </Value>
              )}
            </span>
          )
        }
        detail={
          state?.automation ? (
            <>
              Re-run: {state.automation.rerun.prompts} fixed prompts to every enabled guardrail (no model, no edge)
              {state.automation.rerun.replies
                ? `, and ${state.automation.rerun.replies} fixed prompt + reply pairs (a harmless reply, one with a test SSN) to those that can check a reply`
                : ""}
              , shown as "scheduled re-runs" on Analytics. Outage check: hourly, a vendor is <b>down</b> when at least{" "}
              {Math.round(state.automation.alerts.noVerdictRate * 100)}% of at least {state.automation.alerts.minChecks} checks
              in the last {state.automation.alerts.windowHours}h got no verdict; an alert is sent when that changes, and
              says so when the vendor rejected the key (HTTP 401/403).
              {state.automation.verdictWatch && (
                <>
                  {" "}
                  Verdict watch: after each re-run, an alert when a vendor's verdict on one of the fixed prompts changes and
                  holds for {state.automation.verdictWatch.confirmRuns} runs in a row
                  {state.automation.verdictWatch.tracked == null
                    ? " (its table could not be read)"
                    : ` — ${state.automation.verdictWatch.tracked} vendor × prompt pairs watched${
                        state.automation.verdictWatch.pending ? `, ${state.automation.verdictWatch.pending} awaiting a second run` : ""
                      }`}
                  .
                </>
              )}
              {state.automation.smokeCanary !== undefined && (
                <>
                  {" "}
                  Smoke canary: each re-run also sends the prod smoke test's prompt, and alerts the first time a vendor blocks
                  it — the smoke test's route checks would then fail.
                </>
              )}
              {state.automation.alerts.states.length > 0 && (
                <>
                  {" "}
                  Last stored:{" "}
                  {state.automation.alerts.states
                    .map((s) => `${s.provider} ${s.state} since ${new Date(s.since).toLocaleString()}`)
                    .join(" · ")}
                  .
                </>
              )}
            </>
          ) : undefined
        }
        setBy={
          <>
            Cron Triggers in {code("wrangler.jsonc")}; secret {code("ALERT_WEBHOOK_URL")} (https) for alerts, unset = Worker
            logs only. A Slack, Teams (Workflows) or Discord URL gets that service's format; {code("ALERT_WEBHOOK_FORMAT")}{" "}
            overrides it
          </>
        }
        product={{ name: "Cron Triggers", links: CLOUDFLARE_LINKS.cron }}
      />

      <Row
        label="Who can change system settings"
        value={
          !state?.access ? (
            <Value tone="unknown">{state ? "not reported" : "loading…"}</Value>
          ) : state.access.mode === "admin" ? (
            <Value tone="on">Listed admins only</Value>
          ) : (
            <Value tone="neutral">Anyone Cloudflare Access lets in</Value>
          )
        }
        detail="Your own preferences above are never restricted — they only change this browser."
        setBy={
          <>
            Secret {code("GUARDRAIL_ADMIN_EMAILS")}, checked against the Access login ({code("ACCESS_TEAM_DOMAIN")},{" "}
            {code("ACCESS_AUD")})
          </>
        }
        product={{ name: "Access", links: CLOUDFLARE_LINKS.access }}
      />

      <Row
        label="Prompt log"
        value={!models ? unknown : log?.enabled ? <Value tone="on">On</Value> : <Value tone="off">Off</Value>}
        detail={
          models
            ? `${log?.enabled ? "Stores" : "When on, stores"} every prompt that reaches the Worker, PII-redacted. Keeps the last ${
                log?.maxAgeDays ?? "?"
              } days, and only the newest ${log?.maxRows?.toLocaleString() ?? "?"} prompts.`
            : undefined
        }
        setBy={<>Var {code("PROMPT_LOG_ENABLED")} (exactly {code('"true"')}) and D1 binding {code("DB")}</>}
        product={{ name: "D1", links: CLOUDFLARE_LINKS.d1 }}
      />

      <Row
        label="AI Gateways"
        value={
          !models ? (
            unknown
          ) : models.gateways && models.gateways.length > 0 ? (
            <GatewayList gateways={models.gateways} />
          ) : (
            <Value tone="off">None configured</Value>
          )
        }
        detail={
          <>
            The gateways the chat's AI Gateway route can send through
            {models?.defaultGateway ? <> (default: {models.defaultGateway})</> : null}. "Guardrails" marks only the one
            named in {code("CF_AI_GATEWAY_GUARDED_ID")} — the AI Gateway API does not report which gateways have
            Guardrails on.
          </>
        }
        setBy={
          <>
            Listed live from the account ({code("CF_ACCOUNT_ID")}, {code("CF_ANALYTICS_TOKEN")} with AI Gateway Read); if
            that fails, vars {code("CF_AI_GATEWAY_ID")} and {code("CF_AI_GATEWAY_GUARDED_ID")}
          </>
        }
        product={{ name: "AI Gateway", links: CLOUDFLARE_LINKS.aiGateway }}
      />

      <Row
        label="Default model"
        value={!models ? unknown : <Value tone="neutral">{models.default}</Value>}
        detail={models ? `${models.models.length} models are allowed; the chat page picks among them.` : undefined}
        setBy={<>Code: {code("MODEL_REGISTRY")} in {code("src/models.ts")}</>}
        product={{ name: "Workers AI", links: CLOUDFLARE_LINKS.workersAi }}
      />
    </div>
  );
}
