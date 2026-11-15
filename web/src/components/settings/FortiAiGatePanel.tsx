// Settings → System → FortiAIGate: connection settings for Fortinet's self-hosted inline AI gateway
// (src/fortiAiGate.ts). It is a PROXY, not an external guardrail, so it sits apart from the Providers list and
// never joins the pipeline. Its Enabled switch offers it as a third chat route (/api/chat with fortiaigate: true);
// Test connection shows the evidence that route was built from (status, response shape, block message seen).
import { useEffect, useId, useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronRight, Info, Loader2, ShieldAlert } from "lucide-react";
import { getFortiAiGate, saveFortiAiGate, testFortiAiGate } from "../../lib/api";
import { Switch } from "../Switch";
import type { FortiAiGateState, FortiAiGateTestResponse, FortiAiGateTestSample, FortiAiGateUpdate } from "../../lib/types";

const INPUT_CLS =
  "w-full rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[13px] text-text placeholder:text-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50";
const BTN_CLS =
  "rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] font-semibold text-text transition-colors hover:border-line-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50";
const PRIMARY_CLS =
  // The same as the providers' Save button: dark text on the accent, which is what clears 4.5:1.
  "inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-1.5 text-[12.5px] font-semibold text-[#1a1206] transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg disabled:cursor-not-allowed disabled:opacity-50";

const OUTCOME_TEXT: Record<NonNullable<FortiAiGateTestResponse["result"]>["outcome"], string> = {
  replied: "The model replied through FortiAIGate",
  block_message_seen: "FortiAIGate's block message came back",
  access_redirect: "Cloudflare Access redirected the request",
  unauthorized: "Refused — check the virtual key",
  http_error: "Answered with an error",
  unreachable: "No answer",
};

function Hint({ children }: { children: React.ReactNode }) {
  return <p className="mt-1 text-[11.5px] leading-relaxed text-muted">{children}</p>;
}

function Saved({ set, last4, at }: { set: boolean; last4: string | null; at?: number | null }) {
  return (
    <div className="mt-1 text-[11.5px] text-muted">
      {set ? (
        <>
          Saved — ends in <span className="font-mono">••••{last4}</span>
          {at != null && <span className="text-subtle"> · {new Date(at).toLocaleString()}</span>}
        </>
      ) : (
        "Not set"
      )}
    </div>
  );
}

export function FortiAiGatePanel({ open, onOpenChange }: { open: boolean; onOpenChange: (on: boolean) => void }) {
  const ids = useId();
  const [state, setState] = useState<FortiAiGateState | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [models, setModels] = useState("");
  const [blockMessage, setBlockMessage] = useState("");
  const [virtualKey, setVirtualKey] = useState("");
  const [accessId, setAccessId] = useState("");
  const [accessSecret, setAccessSecret] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testModel, setTestModel] = useState("");
  const [testing, setTesting] = useState<FortiAiGateTestSample | null>(null);
  const [test, setTest] = useState<FortiAiGateTestResponse | null>(null);

  const adopt = (s: FortiAiGateState) => {
    setState(s);
    const c = s.config;
    if (!c) return;
    setBaseUrl(c.baseUrl ?? "");
    setModels(c.models.join("\n"));
    setBlockMessage(c.blockMessage);
    setTestModel((m) => (c.models.includes(m) ? m : (c.models[0] ?? "")));
  };

  useEffect(() => {
    getFortiAiGate()
      .then(adopt)
      .catch((e: unknown) => setLoadErr(e instanceof Error ? e.message : String(e)));
  }, []);

  const c = state?.config;
  const locked = state?.access?.canEdit === false || !state?.configured;
  const modelList = models
    .split(/[\n,]/)
    .map((m) => m.trim())
    .filter(Boolean);
  const dirty =
    !!c &&
    (baseUrl.trim() !== (c.baseUrl ?? "") ||
      modelList.join("\n") !== c.models.join("\n") ||
      blockMessage.trim() !== c.blockMessage ||
      virtualKey.trim() !== "" ||
      accessId.trim() !== "" ||
      accessSecret.trim() !== "");

  const send = async (update: FortiAiGateUpdate, done: string) => {
    setSaving(true);
    setSaveMsg(null);
    try {
      const s = await saveFortiAiGate(update);
      if (s.error || !s.config) {
        setSaveMsg({ ok: false, text: s.error || "Update was rejected by the server" });
      } else {
        adopt(s);
        setVirtualKey("");
        setAccessId("");
        setAccessSecret("");
        setSaveMsg({ ok: true, text: done });
      }
    } catch (e) {
      setSaveMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  };

  const save = () => {
    if (!c) return;
    const u: FortiAiGateUpdate = {};
    if (baseUrl.trim() !== (c.baseUrl ?? "")) u.baseUrl = baseUrl.trim() || null;
    if (modelList.join("\n") !== c.models.join("\n")) u.models = modelList;
    if (blockMessage.trim() !== c.blockMessage) u.blockMessage = blockMessage.trim() || null;
    if (virtualKey.trim()) u.virtualKey = virtualKey.trim();
    if (accessId.trim() || accessSecret.trim()) {
      u.accessClientId = accessId.trim();
      u.accessClientSecret = accessSecret.trim();
    }
    void send(u, "Saved.");
  };

  const runTest = async (sample: FortiAiGateTestSample) => {
    setTesting(sample);
    setTest(null);
    try {
      setTest(await testFortiAiGate(testModel, sample));
    } catch (e) {
      setTest({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      setTesting(null);
    }
  };

  const canTest = !!c?.baseUrl && c.virtualKeySet && c.models.length > 0 && !dirty;
  const r = test?.result;

  // The closed row's one-line summary, like a vendor row's: what is saved, never a secret.
  const summary = c
    ? [
        c.baseUrl ? c.baseUrl.replace(/^https:\/\//, "") : "no URL",
        c.models.length ? `${c.models.length} model${c.models.length === 1 ? "" : "s"}` : "no model",
        c.virtualKeySet ? `virtual key ••••${c.virtualKeyLast4}` : "no virtual key",
        c.accessSet ? "Access token saved" : "no Access token",
        ...(c.enabled && c.vendorsObserve ? ["vendors observe only"] : []),
      ]
    : [];

  return (
    <section className="rounded-xl border border-line bg-surface shadow-sm">
      <div className="flex items-center gap-3 px-3 py-2.5 sm:px-4">
      <h4 className="m-0 min-w-0 flex-1">
        {/* Accordion pattern, as the vendor rows: a heading holding the toggle, outside the locked fieldset so a
            read-only viewer can still open it and read it. */}
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
              FortiAIGate
              <span
                title="Requests go through it to the model; it does not check a prompt on its own, so it is not part of the pipeline."
                className="rounded-full border border-line bg-surface-2 px-2 py-px text-[10.5px] font-semibold text-muted"
              >
                inline proxy
              </span>
              {c?.enabled && (
                <span
                  title="The chat page offers FortiAIGate as a third route, next to Workers AI and AI Gateway."
                  className="rounded-full border border-cf-purple/60 bg-cf-purple/10 px-2 py-px text-[10.5px] font-semibold text-cf-purple"
                >
                  chat route
                </span>
              )}
            </span>
            <span className="mt-0.5 block text-[11.5px] font-normal leading-relaxed text-muted">
              {summary.length ? summary.join(" · ") : loadErr ? "Could not load" : "Loading…"}
              {c?.updatedAt != null && <span className="text-subtle"> · saved {new Date(c.updatedAt).toLocaleString()}</span>}
            </span>
          </span>
        </button>
      </h4>
      {/* Outside the heading button, like the vendor rows; a non-admin viewer gets it disabled. */}
      {c && (
        <Switch
          checked={c.enabled}
          onChange={(on) => void send({ enabled: on }, on ? "Enabled — the chat page now offers the FortiAIGate route." : "Disabled.")}
          disabled={locked || saving}
          label={c.enabled ? "Enabled" : "Disabled"}
          title="Offer FortiAIGate as a third chat route, next to Workers AI and AI Gateway"
        />
      )}
      </div>

      <div id={`${ids}body`} hidden={!open} className="border-t border-line">
      <p className="m-0 px-3 pt-3 text-[11.5px] leading-relaxed text-muted sm:px-4">
        Fortinet's self-hosted AI gateway. Unlike the vendors above it does not return a verdict on its own: the request
        goes <b className="text-text">through</b> it to the model it fronts (here AWS Bedrock), and its policy acts on the
        way. So it is never part of the guardrail pipeline, the scheduled re-runs or the vendor analytics. Reached through a
        Cloudflare Tunnel; prompts leave Cloudflare for your AWS account.
      </p>

      {loadErr && (
        <div role="alert" className="flex items-center gap-2 px-4 py-3 text-[12.5px] text-cf-red">
          <AlertTriangle size={15} className="shrink-0" /> Could not load FortiAIGate settings: {loadErr}
        </div>
      )}
      {!state && !loadErr && (
        <div className="flex items-center gap-2 px-4 py-3 text-[12.5px] text-muted" aria-live="polite">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      )}
      {state && !state.configured && (
        <div className="flex items-start gap-2 px-4 py-3 text-[12.5px] text-cf-amber-ink">
          <ShieldAlert size={15} className="mt-0.5 shrink-0" />
          <span>{state.setupHint || state.error || "Not set up on this Worker."}</span>
        </div>
      )}

      {c && (
        <fieldset disabled={locked} className="m-0 min-w-0 border-0 p-0">
          {/* Saved at once, like Enabled: it changes what the vendors may do, not a connection setting. */}
          <div className="mx-3 mt-3 flex flex-wrap items-start justify-between gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2.5 sm:mx-4">
            <div className="min-w-0 flex-1">
              <div className="text-[12px] font-semibold text-text">External guardrails observe only on this route</div>
              <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
                On: on the FortiAIGate route, the enabled vendors still check the prompt and the reply, and their verdicts
                are shown, logged and scored — but they <b className="text-text">never stop the turn, withhold the reply or
                redact</b>, so FortiAIGate sees every prompt and the two can be compared on the same traffic. A vendor block
                shows as &ldquo;would have blocked&rdquo;. Workers AI and AI Gateway turns are unaffected. Off: the vendors
                can stop the turn before it reaches FortiAIGate.
              </p>
            </div>
            <Switch
              checked={c.vendorsObserve === true}
              onChange={(on) => void send({ vendorsObserve: on }, on ? "Vendors now observe only on the FortiAIGate route." : "Vendors can stop FortiAIGate turns again.")}
              disabled={locked || saving}
              label={c.vendorsObserve ? "Observe only" : "Can stop"}
              title="External guardrails observe only on the FortiAIGate route"
            />
          </div>
          <div className="grid gap-4 px-3 py-3 sm:px-4 lg:grid-cols-2">
            <div className="lg:col-span-2">
              <label htmlFor={`${ids}url`} className="mb-1 block text-[12px] font-semibold text-text">
                Base URL
              </label>
              <input
                id={`${ids}url`}
                type="url"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={c.allowedHostSuffix ? `https://fortiaigate.${c.allowedHostSuffix}` : "Not available on this Worker"}
                className={`${INPUT_CLS} max-w-md font-mono`}
              />
              <Hint>
                The Cloudflare Tunnel hostname, origin only — the app adds <code>/ai/openai/v1/chat/completions</code>.{" "}
                {c.allowedHostSuffix ? (
                  <>
                    Must be <b className="text-text">{c.allowedHostSuffix}</b> or a subdomain of it: the virtual key and the
                    Access token are sent there, so any other host is refused.
                  </>
                ) : (
                  <>FORTIAIGATE_ALLOWED_HOST_SUFFIX is not set on the Worker, so no URL can be saved.</>
                )}
              </Hint>
            </div>

            <div>
              <label htmlFor={`${ids}models`} className="mb-1 block text-[12px] font-semibold text-text">
                Models
              </label>
              <textarea
                id={`${ids}models`}
                rows={3}
                spellCheck={false}
                value={models}
                onChange={(e) => setModels(e.target.value)}
                placeholder="One public model name per line, as FortiAIGate's Model Catalog shows it"
                className={`${INPUT_CLS} font-mono`}
              />
              <Hint>Public model names from FortiAIGate (provider slug + model). Up to 20.</Hint>
            </div>

            <div>
              <label htmlFor={`${ids}block`} className="mb-1 block text-[12px] font-semibold text-text">
                Block message
              </label>
              <textarea
                id={`${ids}block`}
                rows={3}
                maxLength={500}
                value={blockMessage}
                onChange={(e) => setBlockMessage(e.target.value)}
                className={INPUT_CLS}
              />
              <Hint>
                Your organisation's FortiAIGate block message, exactly as set there ({c.blockMessageIsDefault ? "Fortinet's default" : "changed from Fortinet's default"}).
                Test connection reports whether it came back; it is never shown from a response.
              </Hint>
            </div>

            <div>
              <label htmlFor={`${ids}vk`} className="mb-1 block text-[12px] font-semibold text-text">
                Virtual key
              </label>
              <input
                id={`${ids}vk`}
                type="password"
                autoComplete="off"
                value={virtualKey}
                onChange={(e) => setVirtualKey(e.target.value)}
                placeholder={c.virtualKeySet ? "Enter a new virtual key to replace the saved one" : "Paste the FortiAIGate virtual key"}
                className={`${INPUT_CLS} max-w-md`}
              />
              <Saved set={c.virtualKeySet} last4={c.virtualKeyLast4} at={c.virtualKeySavedAt} />
              <Hint>Sent as <code>Authorization: Bearer</code>. Write-only and encrypted at rest; leave empty to keep it.</Hint>
            </div>

            <div>
              <div className="mb-1 text-[12px] font-semibold text-text">Cloudflare Access service token</div>
              <div className="flex flex-col gap-2">
                <input
                  aria-label="Access client ID"
                  type="password"
                  autoComplete="off"
                  value={accessId}
                  onChange={(e) => setAccessId(e.target.value)}
                  placeholder={c.accessSet ? "New client ID (replaces the saved token)" : "Client ID"}
                  className={`${INPUT_CLS} max-w-md`}
                />
                <input
                  aria-label="Access client secret"
                  type="password"
                  autoComplete="off"
                  value={accessSecret}
                  onChange={(e) => setAccessSecret(e.target.value)}
                  placeholder={c.accessSet ? "New client secret" : "Client secret"}
                  className={`${INPUT_CLS} max-w-md`}
                />
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-[11.5px] text-muted">
                {c.accessSet ? (
                  <>
                    <span>
                      Saved — ID ends in <span className="font-mono">••••{c.accessClientIdLast4}</span>, secret in{" "}
                      <span className="font-mono">••••{c.accessClientSecretLast4}</span>
                    </span>
                    <button
                      type="button"
                      onClick={() => void send({ clearAccess: true }, "Access token removed.")}
                      disabled={saving}
                      className="font-semibold text-accent-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      Remove
                    </button>
                  </>
                ) : (
                  "Not set"
                )}
              </div>
              <Hint>
                For the tunnel hostname's Access application (a Service Auth policy). Both halves together. Use a token of
                its own, not the one scripts use for this app.
              </Hint>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 border-t border-line px-3 py-2.5 sm:px-4">
            <button type="button" onClick={save} disabled={!dirty || saving} className={PRIMARY_CLS}>
              {saving ? "Saving…" : "Save"}
            </button>
            {saveMsg && (
              <span role="status" className={`text-[12px] ${saveMsg.ok ? "text-cf-green-ink" : "text-cf-red"}`}>
                {saveMsg.text}
              </span>
            )}
            {c.updatedAt != null && <span className="text-[11.5px] text-subtle">saved {new Date(c.updatedAt).toLocaleString()}</span>}
          </div>

          <div className="border-t border-line px-3 py-3 sm:px-4">
            <div className="flex flex-wrap items-end gap-2">
              <div>
                <label htmlFor={`${ids}tm`} className="mb-1 block text-[12px] font-semibold text-text">
                  Test connection
                </label>
                <select
                  id={`${ids}tm`}
                  value={testModel}
                  onChange={(e) => setTestModel(e.target.value)}
                  disabled={c.models.length === 0}
                  className={`${INPUT_CLS} w-auto max-w-xs font-mono`}
                >
                  {c.models.length === 0 && <option value="">No model saved</option>}
                  {c.models.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
              <button type="button" onClick={() => void runTest("benign")} disabled={!canTest || testing != null} className={BTN_CLS}>
                {testing === "benign" ? "Sending…" : "Send “Reply with OK.”"}
              </button>
              <button type="button" onClick={() => void runTest("attack")} disabled={!canTest || testing != null} className={BTN_CLS}>
                {testing === "attack" ? "Sending…" : "Send a known injection"}
              </button>
            </div>
            <Hint>
              {dirty
                ? "Save first — the test uses the saved settings."
                : canTest
                  ? "A fixed prompt, through FortiAIGate to the model, with the saved settings. The result shows the status and the response's shape (field names and types, never text) — the evidence the chat route is checked against."
                  : "Needs a saved base URL, virtual key and model."}
            </Hint>

            {test?.error && !r && (
              <div role="alert" className="mt-2 flex items-start gap-2 text-[12.5px] text-cf-red">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" /> {test.error}
              </div>
            )}
            {r && (
              <div className="mt-2 rounded-lg border border-line bg-surface-2 px-3 py-2 text-[12.5px]" role="status">
                <div className="flex items-start gap-2">
                  {test?.ok ? (
                    <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-cf-green-ink" />
                  ) : (
                    <Info size={15} className="mt-0.5 shrink-0 text-cf-amber-ink" />
                  )}
                  <div className="min-w-0">
                    <div className="font-semibold text-text">{OUTCOME_TEXT[r.outcome]}</div>
                    <div className="text-[11.5px] text-muted">
                      {r.status != null ? `HTTP ${r.status}` : "no HTTP status"} · {r.latencyMs} ms · {r.model} ·{" "}
                      {r.sample === "attack" ? "known injection" : "“Reply with OK.”"}
                      {r.replyChars != null && ` · reply of ${r.replyChars} characters`}
                      {r.accessUsed ? " · with Access token" : " · no Access token"}
                    </div>
                    {r.error && <div className="mt-0.5 text-[11.5px] text-text">{r.error}</div>}
                    {r.headerNames.length > 0 && (
                      <div className="mt-0.5 text-[11.5px] text-muted">
                        Headers: <span className="font-mono">{r.headerNames.join(", ")}</span>
                      </div>
                    )}
                  </div>
                </div>
                {r.responseShape != null && (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-[11.5px] font-semibold text-accent-ink">Response shape</summary>
                    {/* `relative`: a scroll box holds its own absolute/sr-only descendants (CLAUDE.md). */}
                    <pre className="relative mt-1 max-h-64 overflow-auto rounded bg-surface px-2 py-1 font-mono text-[11px] text-text">
                      {JSON.stringify(r.responseShape, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            )}
          </div>
        </fieldset>
      )}
      </div>
    </section>
  );
}
