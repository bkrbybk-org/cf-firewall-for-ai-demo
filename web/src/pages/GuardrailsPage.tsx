// External guardrails page: configure forwarding of every /api/chat prompt to
// third-party guardrails (Palo Alto Networks Prisma AIRS, CrowdStrike Falcon
// AIDR) and how they run together. State lives in D1 behind
// /api/external-guardrails — this page only renders and edits it.
//
// Two honesty rules shape the code:
//  - The toggle shows the SERVER's state, never the click. Enabling is rejected
//    (HTTP 400) without a key (and, for Prisma AIRS, a profile), and a pipeline edit (mode, order,
//    guardrail-only) lives beside the providers in the same state, so every
//    response replaces the whole state and nothing is optimistic.
//  - The API key is write-only. It is held in an input's state only until a
//    save succeeds, then wiped; what the server reports back is just whether a
//    key exists and its last four characters.
import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, Loader2, Lock, LockOpen, ShieldAlert } from "lucide-react";
import { CardLayoutPicker } from "../components/CardLayoutPicker";
import { Header } from "../components/Header";
import { PipelineDiagram } from "../components/PipelineDiagram";
import { Switch } from "../components/Switch";
import { ThemeToggle } from "../components/ThemeToggle";
import { scanIdLabel } from "../lib/guardrailView";
import {
  getExternalGuardrails,
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
  GuardrailPipelineUpdate,
} from "../lib/types";

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
      <div className="flex items-center gap-2 px-1 text-[12px] text-muted">
        <Lock size={13} className="shrink-0 text-cf-green" /> Signed in as {access.who}, a guardrail admin — changes are
        restricted to the admin list.
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 px-1 text-[12px] text-muted">
      <LockOpen size={13} className="shrink-0 text-subtle" /> Anyone Cloudflare Access lets in can change these settings,
      service tokens included. Set the <code className="font-mono">GUARDRAIL_ADMIN_EMAILS</code> secret to restrict them.
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

function TestOutcome({ t }: { t: ExternalGuardrailTestResult }) {
  const r = t.result;
  // `ok` means the provider answered with a verdict. A failed test is shown as
  // the provider's own error, verbatim — never reworded into a verdict.
  if (t.ok) {
    return (
      <div className="flex items-start gap-1.5 text-[12px] text-cf-green">
        <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
        <span>
          Connection works — verdict <b className="font-mono">{r.action ?? r.outcome}</b>
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

// "an API key" / "a collector token" — each provider names its secret differently.
function aKey(c: ExternalGuardrailConfig): string {
  const name = c.keyLabel === "API key" ? c.keyLabel : c.keyLabel.toLowerCase();
  return `${/^[aeiou]/i.test(name) ? "an" : "a"} ${name}`;
}

function ProviderCard({
  config,
  onState,
  locked = false,
}: {
  config: ExternalGuardrailConfig;
  locked?: boolean; // not a guardrail admin — read-only
  // Every successful response is handed up so the page re-renders ALL providers
  // and the traffic-flow diagram from the server's view, not from this card's.
  onState: (s: ExternalGuardrailsState) => void;
}) {
  const p: ExternalGuardrailProvider = config.provider;
  const [region, setRegion] = useState(config.region);
  const [profileName, setProfileName] = useState(config.profileName);
  const [failMode, setFailMode] = useState(config.failMode);
  const [apiKey, setApiKey] = useState("");
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
    apiKey !== "";
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
    try {
      const e = await send(update);
      if (e) {
        setSaveErr(e);
        setSaveStatus("error");
        return;
      }
      setApiKey(""); // the typed key must not outlive a successful save
      setTest(null);
      setTestErr(null);
      setSaveStatus("saved");
    } catch (e) {
      setSaveErr(errMsg(e));
      setSaveStatus("error");
    }
  }

  async function removeKey() {
    if (!window.confirm(`Remove the saved ${config.label} ${config.keyLabel.toLowerCase()}? This also disables the guardrail.`)) return;
    setBusy(true);
    setSaveErr(null);
    try {
      const e = await send({ provider: p, clearApiKey: true });
      if (e) setSaveErr(e);
      else {
        setApiKey("");
        setTest(null);
        setSaveStatus("idle");
      }
    } catch (e) {
      setSaveErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setTesting(true);
    setTest(null);
    setTestErr(null);
    try {
      const t = await testExternalGuardrail(p);
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
      <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-[13px] font-bold text-text">{config.label}</h2>
          <span className="rounded-full border border-line bg-surface-2 px-2.5 py-0.5 text-[11px] font-semibold text-subtle">
            Not yet supported
          </span>
        </div>
      </section>
    );
  }

  const testDisabledReason = !config.apiKeySet
    ? `Save ${aKey(config)} first`
    : dirty
      ? "Save your changes first — the test uses the saved configuration"
      : "Scans a fixed benign prompt with the saved configuration";

  return (
    <section className="rounded-2xl border border-line bg-surface p-4 shadow-sm">
      {/* Not a guardrail admin: a disabled fieldset turns off every control in the
          card together (the page banner says why). */}
      <fieldset disabled={locked} className="m-0 min-w-0 border-0 p-0">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[13px] font-bold text-text">{config.label}</h2>
          {config.updatedAt != null && (
            <div className="mt-0.5 text-[11.5px] text-muted">
              Last saved {new Date(config.updatedAt).toLocaleString()}
            </div>
          )}
        </div>
        <Switch
          checked={config.enabled}
          onChange={toggle}
          disabled={busy || saving}
          label={config.enabled ? "Enabled" : "Disabled"}
          title="Forward every chat prompt to this guardrail before the model runs"
        />
      </div>
      <div aria-live="polite" className="min-h-0">
        {toggleErr && (
          <div className="mt-2 flex items-start gap-1.5 text-[12px] text-cf-red">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{toggleErr}</span>
          </div>
        )}
      </div>

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
            No free-text endpoint on purpose: the {config.keyLabel.toLowerCase()} is only ever sent to {config.vendor}'s
            official hosts.
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
                config.apiKeySet ? `Enter a new ${config.keyLabel.toLowerCase()} to replace the saved one` : `Paste ${aKey(config)}`
              }
              className={`${INPUT_CLS} max-w-md`}
            />
            {config.apiKeySet && (
              <button type="button" onClick={removeKey} disabled={busy || saving} className={BTN_CLS}>
                Remove {config.keyLabel === "API key" ? "key" : config.keyLabel.split(" ").pop()!.toLowerCase()}
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
            Write-only: the {config.keyLabel.toLowerCase()} is encrypted at rest and never shown again. Leave empty to
            keep the saved one.
          </Hint>
        </div>

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
          onClick={runTest}
          title={testDisabledReason}
          disabled={testing || saving || busy || dirty || !config.apiKeySet}
          className={BTN_CLS}
        >
          {testing ? "Testing…" : "Test connection"}
        </button>
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
    </section>
  );
}

export function GuardrailsPage() {
  const [state, setState] = useState<ExternalGuardrailsState | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="flex h-full flex-col">
      <Header
        title="External Guardrails"
        subtitle={<>Forward each chat prompt to a third-party guardrail before the model runs</>}
        actions={<ThemeToggle />}
      />

      <main className="min-h-0 flex-1 overflow-y-auto p-4">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
          <div className="flex items-start gap-3 rounded-2xl border border-line bg-surface px-4 py-3 shadow-sm">
            <Info size={16} className="mt-0.5 shrink-0 text-cf-amber" />
            <p className="text-[12.5px] leading-relaxed text-muted">
              When enabled, <b className="text-text">every prompt sent through /api/chat is forwarded to the provider
              before the model runs</b>, on both the direct and the AI Gateway route. The Cloudflare edge WAF still
              scans first. <b className="text-text">Prompts leave Cloudflare and are sent to the third party</b> — only
              enable this for data you are willing to share with them. Any number of guardrails can be active; the
              traffic flow below sets how they run.
            </p>
          </div>

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

          {/* Who may change these settings (#26). Said up front rather than discovered
              through a failed save; "open" is said too, so no restriction is implied. */}
          {state?.access && <AccessNote access={state.access} />}

          {/* `pipeline` guard: a Worker older than this bundle sends providers
              without it, and the diagram would throw on the missing config. */}
          {state?.configured && state.pipeline && (
            <PipelineDiagram state={state} onToggle={toggleProvider} onPipeline={savePipeline} />
          )}

          {/* Shown whatever the server state: it is a browser-side preference. */}
          <CardLayoutPicker />
          {state?.configured && (
            <div className="grid items-start gap-4 xl:grid-cols-2">
              {state.providers.map((c) => (
                <ProviderCard
                  // Keyed by provider only: re-keying on updatedAt would remount the
                  // card after every save and wipe its "Saved." and test result.
                  key={c.provider}
                  config={c}
                  onState={setState}
                  locked={state.access?.canEdit === false}
                />
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
