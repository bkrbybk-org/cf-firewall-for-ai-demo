// Settings page (/settings; /guardrails until 2026-10-07). Two sections that must
// never be confused:
//  - Your preferences — saved in THIS browser only (components/settings/
//    PreferencesSection.tsx): theme, how the chat draws guardrail turns.
//  - System settings — shared by every user: the external guardrails (forwarding
//    of every /api/chat prompt to third-party guardrails, and how they run
//    together), stored in D1 behind /api/external-guardrails, plus a read-only
//    view of the Worker's deployment config (components/settings/DeploymentPanel).
//
// Two honesty rules shape the system half:
//  - The toggle shows the SERVER's state, never the click. Enabling is rejected
//    (HTTP 400) without a key (and, for Prisma AIRS, a profile), and a pipeline edit (mode, order,
//    guardrail-only) lives beside the providers in the same state, so every
//    response replaces the whole state and nothing is optimistic.
//  - The API key is write-only. It is held in an input's state only until a
//    save succeeds, then wiped; what the server reports back is just whether a
//    key exists and its last four characters.
import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronRight, Info, Loader2, Lock, LockOpen, Server, ShieldAlert } from "lucide-react";
import { DeploymentPanel } from "../components/settings/DeploymentPanel";
import { PreferencesSection } from "../components/settings/PreferencesSection";
import { Group, SectionHeader } from "../components/settings/primitives";
import { Header } from "../components/Header";
import { PipelineDiagram } from "../components/PipelineDiagram";
import { Switch } from "../components/Switch";
import { ThemeToggle } from "../components/ThemeToggle";
import { scanIdLabel } from "../lib/guardrailView";
import {
  getExternalGuardrails,
  getGuardrailAnalytics,
  getModels,
  saveExternalGuardrail,
  saveGuardrailPipeline,
  testExternalGuardrail,
} from "../lib/api";
import type {
  ExternalGuardrailConfig,
  ExternalGuardrailProvider,
  ExternalGuardrailsState,
  ExternalGuardrailTestResult,
  ExternalGuardrailUpdate,
  GuardrailAccess,
  GuardrailAnalytics,
  GuardrailPipelineUpdate,
  GuardrailTestSample,
  ModelsResponse,
} from "../lib/types";
import { healthText, vendorHealth, type VendorHealth } from "../lib/vendorHealth";

const INPUT_CLS =
  "w-full rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[13px] text-text placeholder:text-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50";
const BTN_CLS =
  "rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] font-semibold text-text transition-colors hover:border-line-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// A response that parsed as JSON but is not a usable state (e.g. a bare
// { error } from a 5xx) must not replace good state — it would blank the page.
function isState(s: unknown): s is ExternalGuardrailsState {
  return !!s && Array.isArray((s as ExternalGuardrailsState).providers);
}

// Where each vendor's policy lives — said in that vendor's own terms, so one
// provider's console is never named on another's card.
const PROFILE_HINT: Partial<Record<ExternalGuardrailProvider, string>> = {
  "prisma-airs": "The profile configured in Strata Cloud Manager. Prisma AIRS requires one.",
  "lakera-guard": "The project in the Lakera dashboard. Its policy, and whether it is in Enforce or Detect mode, decides the verdict.",
};
const POLICY_HINT: Partial<Record<ExternalGuardrailProvider, string>> = {
  "crowdstrike-aidr":
    "Set in the Falcon console on the collector this token belongs to — the app does not choose it. The policy that ran is shown on each verdict.",
  "cisco-ai-defense":
    "Set in AI Defense on the application connection this key belongs to — the app does not choose it.",
  "cato-ai-security":
    "Set in Cato on the API Guard this key belongs to — the app does not choose it. Either of the Guard's two keys works.",
  "datadog-ai-guard":
    "Set in Datadog under Security → AI Guard → Settings: blocking (off by default — then a DENY is only an alert), sensitivity and sensitive data scanning. Requests go out as service “cf-ai-waf-demo”, so a service policy can target this demo. The application key needs the ai_guard_evaluate scope.",
};

function AccessNote({ access }: { access: GuardrailAccess }) {
  if (!access.canEdit) {
    return (
      <div role="status" className="flex items-start gap-3 rounded-2xl border border-cf-amber/60 bg-cf-amber/10 px-4 py-3">
        <Lock size={16} className="mt-0.5 shrink-0 text-cf-amber" />
        <p className="text-[12.5px] leading-relaxed text-text">
          <b>Read-only.</b> Only guardrail admins can change these settings — {access.reason}.
          {access.who ? <span className="text-muted"> Signed in as {access.who}.</span> : null}
        </p>
      </div>
    );
  }
  if (access.mode === "admin") {
    return (
      <div className="flex items-start gap-2 px-1 text-[12px] leading-relaxed text-muted">
        <Lock size={13} className="mt-0.5 shrink-0 text-cf-green" />
        <span>
          Signed in as {access.who}, a guardrail admin — changes are restricted to the admin list.
        </span>
      </div>
    );
  }
  return (
    // One <span> for the sentence: as bare flex children, the text runs and the <code>
    // became separate columns and the sentence broke apart.
    <div className="flex items-start gap-2 px-1 text-[12px] leading-relaxed text-muted">
      <LockOpen size={13} className="mt-0.5 shrink-0 text-subtle" />
      <span>
        Anyone Cloudflare Access lets in can change these settings, service tokens included. Set the{" "}
        <code className="font-mono">GUARDRAIL_ADMIN_EMAILS</code> secret to restrict them.
      </span>
    </div>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return <div className="mt-1 text-[11px] leading-relaxed text-subtle">{children}</div>;
}

function FailModeOption({
  id,
  value,
  current,
  onChange,
  title,
  body,
  disabled,
}: {
  id: string;
  value: "block" | "allow";
  current: "block" | "allow";
  onChange: (v: "block" | "allow") => void;
  title: string;
  body: string;
  disabled: boolean;
}) {
  return (
    <label
      htmlFor={id}
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 ${
        current === value ? "border-accent/60 bg-accent/10" : "border-line bg-surface-2"
      }`}
    >
      <input
        id={id}
        type="radio"
        name={`${id.split(":")[0]}-failmode`}
        value={value}
        checked={current === value}
        disabled={disabled}
        onChange={() => onChange(value)}
        className="mt-0.5 accent-[var(--color-accent)]"
      />
      <span>
        <span className="block text-[12.5px] font-semibold text-text">{title}</span>
        <span className="block text-[11.5px] leading-relaxed text-muted">{body}</span>
      </span>
    </label>
  );
}

// The vendor response's shape (field names, types, true/false — never text), shown
// collapsed after a test. For an unverified provider this is the evidence: pasted
// back, it is compared with what the parser expects before the provider is marked
// verified (src/responseShape.ts says why it is safe to share).
function ResponseShape({ t }: { t: ExternalGuardrailTestResult }) {
  const [copied, setCopied] = useState(false);
  if (!t.responseShape) return null;
  const text = JSON.stringify({ provider: t.result.provider, sample: t.sample, ...t.responseShape }, null, 2);
  return (
    <details className="mt-1.5 text-[11.5px]" open={t.verified === false}>
      <summary className="cursor-pointer text-muted hover:text-text">
        Response shape — field names, types and true/false only, no text
        {t.verified === false && <b className="text-cf-amber"> · send this back to verify the parser</b>}
      </summary>
      <div className="mt-1 flex items-start gap-2">
        <pre className="max-h-56 flex-1 overflow-auto rounded-lg border border-line bg-surface-2 p-2 font-mono text-[10.5px] whitespace-pre text-muted">
          {text}
        </pre>
        <button
          type="button"
          onClick={() => void navigator.clipboard.writeText(text).then(() => setCopied(true))}
          className={BTN_CLS}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </details>
  );
}

function TestOutcome({ t }: { t: ExternalGuardrailTestResult }) {
  return (
    <div>
      <TestVerdict t={t} />
      <ResponseShape t={t} />
    </div>
  );
}

const TEST_SAMPLE_LABEL: Record<GuardrailTestSample, string> = {
  benign: "Connection works",
  attack: "Attack prompt",
  pii: "PII prompt",
  "reply-pii": "Reply with PII",
  "reply-benign": "Harmless reply",
};

function TestVerdict({ t }: { t: ExternalGuardrailTestResult }) {
  const r = t.result;
  // `ok` means the provider answered with a verdict. A failed test is shown as
  // the provider's own error, verbatim — never reworded into a verdict.
  if (t.ok) {
    return (
      <div className="flex items-start gap-1.5 text-[12px] text-cf-green">
        <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
        <span>
          {TEST_SAMPLE_LABEL[t.sample ?? "benign"]} — verdict{" "}
          <b className="font-mono">{r.action ?? r.outcome}</b>
          {r.detectOnly && <b className="text-cf-amber"> · alerts only</b>}
          {r.transformed && <b className="text-cf-amber"> · redaction requested, not applied</b>}
          {r.detected && r.detected.length > 0 && (
            <>
              {" "}
              · detected <b className="font-mono">{r.detected.join(", ")}</b>
            </>
          )}
          {r.category && (
            <>
              {" "}
              · category <b className="font-mono">{r.category}</b>
            </>
          )}{" "}
          · <b className="font-mono">{r.latencyMs} ms</b>
          {r.scanId && (
            <>
              {" "}
              · {scanIdLabel(r.provider)}{" "}
              <span className="font-mono break-all">{r.scanId}</span>
            </>
          )}
        </span>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-1.5 text-[12px] text-cf-red">
      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
      <span>
        Test failed
        {r?.httpStatus != null && (
          <>
            {" "}
            · HTTP <b className="font-mono">{r.httpStatus}</b>
          </>
        )}
        {r?.error && (
          <>
            {" "}
            · <span className="font-mono break-words">{r.error}</span>
          </>
        )}
      </span>
    </div>
  );
}

// The secret's name mid-sentence: "API key" keeps its acronym, "Collector token"
// reads lower-case. (Lower-casing everything once printed "api key".)
function keyWord(c: ExternalGuardrailConfig): string {
  return /^[A-Z]{2}/.test(c.keyLabel) ? c.keyLabel : c.keyLabel.toLowerCase();
}

// "an API key" / "a collector token" — each provider names its secret differently.
function aKey(c: ExternalGuardrailConfig): string {
  const name = keyWord(c);
  return `${/^[aeiou]/i.test(name) ? "an" : "a"} ${name}`;
}

function ProviderCard({
  config,
  onState,
  locked = false,
  open,
  onOpenChange,
  health,
}: {
  config: ExternalGuardrailConfig;
  // Is it answering? From the verdict data (lib/vendorHealth.ts); undefined while loading.
  health?: VendorHealth;
  locked?: boolean; // not a guardrail admin — read-only
  // A row in a collapsible list, closed by default (the page owns which are open,
  // so the in-page nav and deep links can open the one they point at).
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // Every successful response is handed up so the page re-renders ALL providers
  // and the traffic-flow diagram from the server's view, not from this card's.
  onState: (s: ExternalGuardrailsState) => void;
}) {
  const p: ExternalGuardrailProvider = config.provider;
  const [region, setRegion] = useState(config.region);
  const [profileName, setProfileName] = useState(config.profileName);
  const [failMode, setFailMode] = useState(config.failMode);
  const [apiKey, setApiKey] = useState("");
  const [secondKey, setSecondKey] = useState(""); // only used when config.secondKeyLabel is set
  const [toggleErr, setToggleErr] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false); // toggle / remove-key in flight
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<ExternalGuardrailTestResult | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);

  const dirty =
    region !== config.region ||
    profileName !== config.profileName ||
    failMode !== config.failMode ||
    apiKey !== "" ||
    secondKey !== "";
  // Every credential the provider needs is saved — one key, or both of a pair.
  const keysSet = config.apiKeySet && (!config.secondKeyLabel || !!config.secondKeySet);
  const saving = saveStatus === "saving";
  const regionInfo = config.regions.find((r) => r.id === region);
  const ids = `${p}:`;

  // Shared by every write: a rejected update comes back as { error } with no
  // usable state, so surface the message and leave what is on screen alone.
  async function send(update: ExternalGuardrailUpdate) {
    const s = await saveExternalGuardrail(update);
    if (isState(s) && !s.error) {
      onState(s);
      return null;
    }
    return s?.error || "Update was rejected by the server";
  }

  async function toggle(next: boolean) {
    setBusy(true);
    setToggleErr(null);
    try {
      const e = await send({ provider: p, enabled: next });
      if (e) setToggleErr(e);
    } catch (e) {
      setToggleErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setSaveStatus("saving");
    setSaveErr(null);
    const update: ExternalGuardrailUpdate = { provider: p, region, profileName, failMode };
    if (apiKey) update.apiKey = apiKey;
    if (secondKey) update.secondKey = secondKey;
    try {
      const e = await send(update);
      if (e) {
        setSaveErr(e);
        setSaveStatus("error");
        return;
      }
      setApiKey(""); // the typed key must not outlive a successful save
      setSecondKey("");
      setTest(null);
      setTestErr(null);
      setSaveStatus("saved");
    } catch (e) {
      setSaveErr(errMsg(e));
      setSaveStatus("error");
    }
  }

  async function removeKey() {
    const what = config.secondKeyLabel
      ? `${keyWord(config)} and ${config.secondKeyLabel.toLowerCase()}`
      : keyWord(config);
    if (!window.confirm(`Remove the saved ${config.label} ${what}? This also disables the guardrail.`)) return;
    setBusy(true);
    setSaveErr(null);
    try {
      const e = await send({ provider: p, clearApiKey: true });
      if (e) setSaveErr(e);
      else {
        setApiKey("");
        setSecondKey("");
        setTest(null);
        setSaveStatus("idle");
      }
    } catch (e) {
      setSaveErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function runTest(sample: GuardrailTestSample = "benign") {
    setTesting(true);
    setTest(null);
    setTestErr(null);
    try {
      const t = await testExternalGuardrail(p, sample);
      if (t && typeof t.ok === "boolean" && t.result) setTest(t);
      else setTestErr((t as { error?: string } | null)?.error || "Unexpected response from the test endpoint");
    } catch (e) {
      setTestErr(errMsg(e));
    } finally {
      setTesting(false);
    }
  }

  if (!config.supported) {
    return (
      <section className="rounded-xl border border-line bg-surface px-4 py-3 shadow-sm">
        <div className="flex items-center justify-between gap-3">
          <h4 className="text-[13px] font-bold text-text">{config.label}</h4>
          <span className="rounded-full border border-line bg-surface-2 px-2.5 py-0.5 text-[11px] font-semibold text-subtle">
            Not yet supported
          </span>
        </div>
      </section>
    );
  }

  const testDisabledReason = !config.apiKeySet
    ? `Save ${aKey(config)} first`
    : !keysSet
      ? `Save the ${config.secondKeyLabel!.toLowerCase()} first`
      : dirty
      ? "Save your changes first — the test uses the saved configuration"
      : "Scans a fixed benign prompt with the saved configuration";

  // The collapsed row's one-line summary: everything needed to scan five providers
  // without opening them. Saved values only — an unsaved edit in a closed row must
  // not read as the configuration in force.
  const savedRegion = config.regions.find((r) => r.id === config.region);
  const summary = [
    config.apiKeySet ? `${keyWord(config)} ••••${config.apiKeyLast4 ?? ""}` : `no ${keyWord(config)}`,
    config.secondKeyLabel
      ? config.secondKeySet
        ? `${config.secondKeyLabel.toLowerCase()} ••••${config.secondKeyLast4 ?? ""}`
        : `no ${config.secondKeyLabel.toLowerCase()}`
      : null,
    savedRegion?.label ?? config.region,
    config.requiresProfile || config.profileName ? config.profileName || `no ${config.profileLabel}` : null,
    config.failMode === "block" ? "fail closed" : "fail open",
  ].filter(Boolean) as string[];

  return (
    <section className="rounded-xl border border-line bg-surface shadow-sm">
      <div className="flex items-center gap-3 px-3 py-2.5 sm:px-4">
        {/* Accordion pattern: a heading that holds the toggle button. It sits OUTSIDE the
            locked fieldset, so a read-only viewer can still open a row and read it. */}
        <h4 className="m-0 min-w-0 flex-1">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={`${ids}body`}
            onClick={() => onOpenChange(!open)}
            className="flex w-full min-w-0 items-start gap-2 rounded-lg py-0.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <ChevronRight
              size={16}
              aria-hidden
              className={`mt-0.5 shrink-0 text-muted transition-transform ${open ? "rotate-90" : ""}`}
            />
            <span className="min-w-0">
              <span className="flex flex-wrap items-center gap-2 text-[13px] font-bold text-text">
                {config.label}
                {config.verified === false && (
                  <span
                    title="Built from the vendor's documentation; its response has not yet been checked against a real one. Run both tests and send back the response shape before relying on its verdicts."
                    className="rounded-full border border-cf-amber/60 bg-cf-amber/10 px-2 py-px text-[10.5px] font-semibold text-cf-amber"
                  >
                    unverified
                  </span>
                )}
              </span>
              <span className="mt-0.5 block text-[11.5px] font-normal leading-relaxed text-muted">
                {summary.join(" · ")}
                {config.updatedAt != null && (
                  <span className="text-subtle"> · saved {new Date(config.updatedAt).toLocaleString()}</span>
                )}
              </span>
              {health && (
                <span className="mt-0.5 flex items-start gap-1.5 text-[11.5px] font-normal leading-relaxed text-muted">
                  <span
                    aria-hidden
                    className={`mt-[5px] h-2 w-2 shrink-0 rounded-full ${
                      health.state === "ok" ? "bg-cf-green" : health.state === "degraded" ? "bg-cf-amber" : "bg-subtle"
                    }`}
                  />
                  <span>
                    <span className="sr-only">
                      {health.state === "ok" ? "Healthy: " : health.state === "degraded" ? "Degraded: " : ""}
                    </span>
                    {healthText(health, Date.now())}
                  </span>
                </span>
              )}
            </span>
          </button>
        </h4>
        {/* Not a guardrail admin: a disabled fieldset turns off the switch, and the body's
            own fieldset below does the same for the form (the page banner says why). */}
        <fieldset disabled={locked} className="m-0 shrink-0 border-0 p-0">
          <Switch
            checked={config.enabled}
            onChange={toggle}
            disabled={busy || saving}
            label={config.enabled ? "Enabled" : "Disabled"}
            title="Forward every chat prompt to this guardrail before the model runs"
          />
        </fieldset>
      </div>
      {/* Outside the body: a failed toggle in a closed row must still be seen. */}
      <div aria-live="polite" className="px-4 empty:hidden">
        {toggleErr && (
          <div className="mb-2.5 flex items-start gap-1.5 text-[12px] text-cf-red">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{toggleErr}</span>
          </div>
        )}
      </div>

      {/* `hidden`, not unmounted: closing a row keeps a typed key, unsaved edits and the
          last test result, so collapsing never throws work away. */}
      <div id={`${ids}body`} hidden={!open} className="border-t border-line px-4 pt-1 pb-4">
      <fieldset disabled={locked} className="m-0 min-w-0 border-0 p-0">
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <label htmlFor={`${ids}region`} className="mb-1 block text-[12px] font-semibold text-text">
            Region
          </label>
          <select
            id={`${ids}region`}
            value={region}
            disabled={saving}
            onChange={(e) => setRegion(e.target.value)}
            className={INPUT_CLS}
          >
            {config.regions.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label} — {r.url}
              </option>
            ))}
          </select>
          <div className="mt-1 font-mono text-[11px] break-all text-muted">
            {/* Shows the saved endpoint until the selection is saved, so it is
                never a claim about a region the server has not accepted. */}
            {regionInfo && region !== config.region ? `${regionInfo.url} (after save)` : config.endpoint}
          </div>
          <Hint>
            No free-text endpoint on purpose:{" "}
            {config.secondKeyLabel ? "both keys are" : `the ${keyWord(config)} is`} only ever sent to{" "}
            {config.vendor.endsWith("s") ? `${config.vendor}'` : `${config.vendor}'s`} official{" "}
            {config.regions.length === 1 ? "host" : "hosts"}.
          </Hint>
        </div>

        {config.requiresProfile ? (
          <div>
            <label htmlFor={`${ids}profile`} className="mb-1 block text-[12px] font-semibold text-text">
              {config.profileLabel || "AI security profile name"}
            </label>
            <input
              id={`${ids}profile`}
              type="text"
              value={profileName}
              disabled={saving}
              onChange={(e) => setProfileName(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              className={INPUT_CLS}
            />
            <Hint>{PROFILE_HINT[config.provider] ?? "Required by this provider."}</Hint>
          </div>
        ) : (
          <div>
            <div className="mb-1 text-[12px] font-semibold text-text">Policy</div>
            {/* No field: the policy is attached to the key in the vendor's console, so
                there is nothing to name per request. */}
            <Hint>{POLICY_HINT[config.provider] ?? "Set in the vendor's console on this key — the app does not choose it."}</Hint>
          </div>
        )}

        <div className="lg:col-span-2">
          <label htmlFor={`${ids}key`} className="mb-1 block text-[12px] font-semibold text-text">
            {config.keyLabel}
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <input
              id={`${ids}key`}
              type="password"
              autoComplete="off"
              value={apiKey}
              disabled={saving}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                config.apiKeySet ? `Enter a new ${keyWord(config)} to replace the saved one` : `Paste ${aKey(config)}`
              }
              className={`${INPUT_CLS} max-w-md`}
            />
            {(config.apiKeySet || config.secondKeySet) && (
              <button type="button" onClick={removeKey} disabled={busy || saving} className={BTN_CLS}>
                Remove{" "}
                {config.secondKeyLabel
                  ? "keys"
                  : config.keyLabel === "API key"
                    ? "key"
                    : config.keyLabel.split(" ").pop()!.toLowerCase()}
              </button>
            )}
          </div>
          <div className="mt-1 text-[11.5px] text-muted">
            {config.apiKeySet ? (
              <>
                Saved — ends in <span className="font-mono">••••{config.apiKeyLast4}</span>
              </>
            ) : (
              "Not set"
            )}
          </div>
          <Hint>
            Write-only: the {keyWord(config)} is encrypted at rest and never shown again. Leave empty to
            keep the saved one.
          </Hint>
        </div>

        {config.secondKeyLabel ? (
          <div className="lg:col-span-2">
            <label htmlFor={`${ids}key2`} className="mb-1 block text-[12px] font-semibold text-text">
              {config.secondKeyLabel}
            </label>
            <input
              id={`${ids}key2`}
              type="password"
              autoComplete="off"
              value={secondKey}
              disabled={saving}
              onChange={(e) => setSecondKey(e.target.value)}
              placeholder={
                config.secondKeySet
                  ? `Enter a new ${config.secondKeyLabel.toLowerCase()} to replace the saved one`
                  : `Paste the ${config.secondKeyLabel.toLowerCase()}`
              }
              className={`${INPUT_CLS} max-w-md`}
            />
            <div className="mt-1 text-[11.5px] text-muted">
              {config.secondKeySet ? (
                <>
                  Saved — ends in <span className="font-mono">••••{config.secondKeyLast4}</span>
                </>
              ) : (
                "Not set"
              )}
            </div>
            <Hint>
              {config.label} needs both keys. Write-only and encrypted at rest, like the {keyWord(config)}; leave
              empty to keep the saved one.
            </Hint>
          </div>
        ) : null}

        <fieldset className="lg:col-span-2" disabled={saving}>
          <legend className="mb-1 text-[12px] font-semibold text-text">
            If {config.label} is unreachable or errors
          </legend>
          <div className="grid gap-2 sm:grid-cols-2">
            <FailModeOption
              id={`${ids}fail-block`}
              value="block"
              current={failMode}
              onChange={setFailMode}
              disabled={saving}
              title="Block the prompt — fail closed"
              body="Safer: nothing reaches the model unchecked. An outage makes chat stop working."
            />
            <FailModeOption
              id={`${ids}fail-allow`}
              value="allow"
              current={failMode}
              onChange={setFailMode}
              disabled={saving}
              title="Let it through unscanned — fail open"
              body="Chat keeps working during an outage, but those prompts skip this guardrail."
            />
          </div>
        </fieldset>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={save}
          disabled={saving || busy || !dirty}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-1.5 text-[12.5px] font-semibold text-white transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving && <Loader2 size={13} className="animate-spin" />}
          {saving ? "Saving…" : "Save"}
        </button>
        <button
          type="button"
          onClick={() => void runTest("benign")}
          title={testDisabledReason}
          disabled={testing || saving || busy || dirty || !keysSet}
          className={BTN_CLS}
        >
          {testing ? "Testing…" : "Test connection"}
        </button>
        {/* A known injection: shows what this vendor's BLOCK response looks like —
            the case an unverified parser most needs checking against. */}
        <button
          type="button"
          onClick={() => void runTest("attack")}
          title="Scans a fixed, well-known prompt-injection string with the saved configuration"
          disabled={testing || saving || busy || dirty || !keysSet}
          className={BTN_CLS}
        >
          Test with an attack prompt
        </button>
        {/* PII is where vendors answer with something other than allow/block (Cato:
            "anonymize_action"), so it gets its own fixed sample — the SSN from Cato's own
            API docs, a long-published example number, not a person's. */}
        <button
          type="button"
          onClick={() => void runTest("pii")}
          title="Scans a fixed prompt containing a well-known example SSN (from Cato's API docs) with the saved configuration"
          disabled={testing || saving || busy || dirty || !keysSet}
          className={BTN_CLS}
        >
          Test with a PII prompt
        </button>
        {/* Design J's verification: a fixed prompt WITH a fixed model reply, sent as the
            reply check sends it — the payload that turns "documented" into "verified".
            Only where the vendor documents checking replies. */}
        {config.replyCheck && (
          <button
            type="button"
            onClick={() => void runTest("reply-pii")}
            title="Sends a fixed prompt with a fixed model REPLY that contains a void sample SSN (078-05-1120), the way the reply check does"
            disabled={testing || saving || busy || dirty || !keysSet}
            className={BTN_CLS}
          >
            Test a reply (PII)
          </button>
        )}
        {config.replyCheck && (
          <button
            type="button"
            onClick={() => void runTest("reply-benign")}
            title="Sends a fixed prompt with a harmless fixed model reply, the way the reply check does"
            disabled={testing || saving || busy || dirty || !keysSet}
            className={BTN_CLS}
          >
            Test a reply (harmless)
          </button>
        )}
        <span className="text-[11px] text-subtle">Tests the saved configuration, not unsaved edits.</span>
        <div aria-live="polite" className="text-[12px]">
          {saveStatus === "saved" && !dirty && <span className="text-cf-green">Saved.</span>}
          {saveStatus === "error" && saveErr && <span className="text-cf-red">{saveErr}</span>}
        </div>
      </div>
      {saveStatus !== "error" && saveErr && (
        <div className="mt-2 text-[12px] text-cf-red" role="status">
          {saveErr}
        </div>
      )}

      <div aria-live="polite" className="mt-3 empty:hidden">
        {test && <TestOutcome t={test} />}
        {testErr && (
          <div className="flex items-start gap-1.5 text-[12px] text-cf-red">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span className="font-mono break-words">{testErr}</span>
          </div>
        )}
      </div>
      </fieldset>
      </div>
    </section>
  );
}

// In-page navigation. Scrolls the page's own scroll box with scrollTo — never
// scrollIntoView, which also scrolls every ancestor (CLAUDE.md, scroll containers).
type NavItem = { id: string; label: string; indent?: boolean };

function scrollToId(main: HTMLElement | null, id: string) {
  const el = document.getElementById(id);
  if (!main || !el) return;
  const top = el.getBoundingClientRect().top - main.getBoundingClientRect().top + main.scrollTop - 12;
  main.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
}

function SettingsNav({ items, onGo }: { items: NavItem[]; onGo: (id: string) => void }) {
  return (
    <nav aria-label="Settings sections" className="sticky top-0 hidden w-52 shrink-0 self-start pt-1 lg:block">
      <ul className="flex flex-col gap-0.5">
        {items.map((it) => (
          <li key={it.id}>
            <a
              href={`#${it.id}`}
              onClick={(e) => {
                e.preventDefault();
                onGo(it.id);
                history.replaceState(null, "", `#${it.id}`);
              }}
              className={`block rounded-lg px-2.5 py-1.5 transition hover:bg-surface-2 hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                it.indent ? "pl-5 text-[12px] text-muted" : "text-[12.5px] font-semibold text-text"
              }`}
            >
              {it.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function SettingsPage() {
  const [state, setState] = useState<ExternalGuardrailsState | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [models, setModels] = useState<ModelsResponse | null>(null);
  const [modelsErr, setModelsErr] = useState(false);
  const mainRef = useRef<HTMLElement | null>(null);
  // Providers are a collapsible list, all closed on arrival: five full forms made the
  // page a long scroll to reach anything. Not remembered — every visit starts scannable.
  const [openRows, setOpenRows] = useState<Set<ExternalGuardrailProvider>>(new Set());
  const setRowOpen = (p: ExternalGuardrailProvider, on: boolean) =>
    setOpenRows((prev) => {
      const next = new Set(prev);
      if (on) next.add(p);
      else next.delete(p);
      return next;
    });
  // Jump to a section; a provider target opens its row first and scrolls once it has
  // rendered open, so the jump lands on the form rather than on a row about to grow.
  const go = (id: string) => {
    const provider = id.startsWith("provider-") ? (id.slice("provider-".length) as ExternalGuardrailProvider) : null;
    if (provider) {
      setRowOpen(provider, true);
      requestAnimationFrame(() => scrollToId(mainRef.current, id));
    } else scrollToId(mainRef.current, id);
  };

  useEffect(() => {
    getModels()
      .then(setModels)
      .catch(() => setModelsErr(true));
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    setLoadErr(null);
    return getExternalGuardrails()
      .then((s) => {
        if (isState(s)) setState(s);
        else setLoadErr((s as { error?: string } | null)?.error || "Unexpected response from /api/external-guardrails");
      })
      .catch((e) => setLoadErr(errMsg(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Vendor health: the last 24h of verdicts, all traffic, read once per visit. undefined = still loading (no line
  // shown); null = could not be read (each row then says "health unknown", never "healthy").
  const [verdicts, setVerdicts] = useState<GuardrailAnalytics | null | undefined>(undefined);
  useEffect(() => {
    getGuardrailAnalytics(24, "all")
      .then((d) => setVerdicts(d))
      .catch(() => setVerdicts(null));
  }, []);

  // Shared by the diagram's writes. A rejected update comes back as { error }
  // with no usable state, so hand the message back and leave the page alone.
  const accept = (s: (ExternalGuardrailsState & { error?: string }) | null): string | null => {
    if (isState(s) && !s.error) {
      setState(s);
      return null;
    }
    return s?.error || "Update was rejected by the server";
  };
  const toggleProvider = async (provider: ExternalGuardrailProvider, enabled: boolean) =>
    accept(await saveExternalGuardrail({ provider, enabled }));
  const savePipeline = async (update: GuardrailPipelineUpdate) => accept(await saveGuardrailPipeline(update));

  const providers = state?.configured ? state.providers.filter((c) => c.supported) : [];
  const nav: NavItem[] = [
    { id: "prefs", label: "Your preferences" },
    { id: "pref-appearance", label: "Appearance", indent: true },
    { id: "pref-chat", label: "Chat display", indent: true },
    { id: "system", label: "System settings" },
    ...(state?.configured && state.pipeline ? [{ id: "traffic-flow", label: "Traffic flow", indent: true }] : []),
    ...providers.map((c) => ({ id: `provider-${c.provider}`, label: c.label, indent: true })),
    { id: "deployment", label: "Deployment", indent: true },
  ];

  // Deep links (/settings#traffic-flow, and /guardrails → #system) land on their
  // section once the content it needs has rendered.
  const ready = !loading;
  useEffect(() => {
    const id = window.location.hash.slice(1);
    if (ready && id) go(id);
    // `go` is stable in behaviour; re-running on its identity would re-scroll on every render.
  }, [ready]);

  return (
    <div className="flex h-full flex-col">
      <Header
        title="Settings"
        subtitle={<>Your preferences for this browser, and the system configuration every user shares</>}
        actions={<ThemeToggle />}
      />

      {/* `relative`: the scroll box contains its sr-only/absolute descendants (CLAUDE.md, scroll containers). */}
      <main ref={mainRef} className="relative min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] gap-6">
          <SettingsNav items={nav} onGo={go} />

          <div className="flex min-w-0 flex-1 flex-col gap-8">
            <PreferencesSection />

            <section aria-labelledby="system" className="flex flex-col gap-4">
              <SectionHeader
                id="system"
                icon={<Server size={18} />}
                title="System settings"
                scope="Shared — every user"
                scopeTone="system"
              >
                Stored on the server. A change here applies at once to every chat, the Red Team runner and every viewer —
                not just this browser.
              </SectionHeader>

              {/* Who may change these settings (#26) — attached to the settings it governs,
                  and said up front rather than discovered through a failed save. */}
              {state?.access && <AccessNote access={state.access} />}

              {loading && !state && (
                <div className="flex items-center gap-2 text-[12.5px] text-muted" aria-live="polite">
                  <Loader2 size={14} className="animate-spin" /> Loading…
                </div>
              )}

              {loadErr && (
                <div
                  role="alert"
                  className="flex flex-wrap items-center gap-3 rounded-2xl border border-cf-red/50 bg-cf-red/10 px-4 py-3 text-[12.5px] text-cf-red"
                >
                  <AlertTriangle size={16} className="shrink-0" />
                  <span className="min-w-0 flex-1 break-words">Could not load external guardrail settings: {loadErr}</span>
                  <button type="button" onClick={load} disabled={loading} className={BTN_CLS}>
                    Retry
                  </button>
                </div>
              )}

              {state && !state.configured && (
                // Not an error to retry: the Worker is missing its encryption secret
                // or D1 binding, and no form can work until an operator fixes that.
                <div className="flex items-start gap-3 rounded-2xl border border-cf-amber/60 bg-cf-amber/10 px-4 py-3">
                  <ShieldAlert size={18} className="mt-0.5 shrink-0 text-cf-amber" />
                  <div>
                    <div className="text-[13px] font-bold text-cf-amber">External guardrails are not set up</div>
                    <p className="mt-1 text-[12.5px] leading-relaxed text-text">
                      {state.setupHint || state.error || "The Worker is missing the configuration this feature needs."}
                    </p>
                  </div>
                </div>
              )}

              {state?.configured && (
                <div className="flex items-start gap-3 rounded-2xl border border-cf-amber/40 bg-cf-amber/[0.06] px-4 py-3">
                  <Info size={16} className="mt-0.5 shrink-0 text-cf-amber" />
                  <p className="text-[12.5px] leading-relaxed text-muted">
                    An enabled external guardrail sees <b className="text-text">every prompt sent through /api/chat</b>,
                    before the model runs, on both the direct and the AI Gateway route. The Cloudflare edge WAF still
                    scans first. <b className="text-text">Prompts leave Cloudflare and go to the third party</b> — only
                    enable one for data you are willing to share with it.
                  </p>
                </div>
              )}

              {/* `pipeline` guard: a Worker older than this bundle sends providers
                  without it, and the diagram would throw on the missing config. */}
              {state?.configured && state.pipeline && (
                // The diagram carries its own "Traffic flow" heading and explanation.
                <div id="traffic-flow" className="scroll-mt-4">
                  <PipelineDiagram state={state} onToggle={toggleProvider} onPipeline={savePipeline} />
                </div>
              )}

              {state?.configured && (
                <Group
                  id="providers"
                  title="Providers"
                  hint={
                    <span className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                      <span>
                        Each vendor's key, region and failure handling — open a row to edit or test it. Test connection
                        sends a fixed prompt with the saved configuration.
                      </span>
                      <span className="flex gap-3">
                        {(["Expand all", "Collapse all"] as const).map((label) => (
                          <button
                            key={label}
                            type="button"
                            onClick={() =>
                              setOpenRows(
                                label === "Expand all" ? new Set(providers.map((c) => c.provider)) : new Set(),
                              )
                            }
                            className="text-[11.5px] font-semibold text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                          >
                            {label}
                          </button>
                        ))}
                      </span>
                    </span>
                  }
                >
                  <ul className="flex flex-col gap-2">
                    {state.providers.map((c) => (
                      <li key={c.provider} id={`provider-${c.provider}`} className="min-w-0 scroll-mt-4">
                        <ProviderCard
                          // Keyed by provider only: re-keying on updatedAt would remount the
                          // card after every save and wipe its "Saved." and test result.
                          config={c}
                          onState={setState}
                          locked={state.access?.canEdit === false}
                          open={openRows.has(c.provider)}
                          onOpenChange={(on) => setRowOpen(c.provider, on)}
                          health={verdicts === undefined ? undefined : vendorHealth(c.provider, verdicts)}
                        />
                      </li>
                    ))}
                  </ul>
                </Group>
              )}

              <Group
                id="deployment"
                title="Deployment"
                hint="Read-only. These are Worker variables, secrets and bindings, fixed when the Worker is deployed — change them with wrangler, not here. Values are read live from the running Worker."
              >
                <DeploymentPanel state={state} models={models} modelsErr={modelsErr} />
              </Group>
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}

