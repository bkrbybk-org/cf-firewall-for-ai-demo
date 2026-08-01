// Every per-request AI Gateway REST setting, in one place. All of these are
// cf-aig-* headers the Worker forwards on the gateway's REST call — see
// https://developers.cloudflare.com/ai-gateway/usage/rest-api/ — so none of
// them do anything on a direct Workers AI call. The panel itself is hidden
// on that route rather than just dimmed, since there is nothing to preview.
import type { GatewayBackoff } from "../lib/api";
import { MAX_METADATA_ENTRIES, parseMetadata } from "../lib/metadata";
import { Switch } from "./Switch";

const MAX_ATTEMPTS_CAP = 5;
const MAX_RETRY_DELAY_MS = 5000;
const MAX_CACHE_KEY_LEN = 128;

// Out-of-range while typing shows a live error but doesn't fight the
// keystroke; onBlur silently clamps so what's left in the field (and what
// gets sent) is always valid — the Worker enforces the same caps server-side,
// so this is UX, not the only guard.
function rangeError(num: number | null, min?: number, max?: number): string | null {
  if (num == null) return null;
  if (!Number.isInteger(num)) return "whole number only";
  if (min != null && num < min) return `min ${min}`;
  if (max != null && num > max) return `max ${max}`;
  return null;
}

function NumberField({
  label,
  value,
  onChange,
  placeholder,
  min,
  max,
  title,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  min?: number;
  max?: number;
  title?: string;
}) {
  const num = value.trim() === "" ? null : Number(value);
  const error = value.trim() === "" ? null : Number.isNaN(num) ? "not a number" : rangeError(num, min, max);

  return (
    <label className="flex flex-col gap-1" title={title}>
      <span className="text-[11.5px] text-muted">{label}</span>
      <input
        type="number"
        inputMode="numeric"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={() => {
          if (value.trim() === "" || Number.isNaN(num)) return;
          const clamped = Math.max(min ?? -Infinity, Math.min(max ?? Infinity, Math.round(num as number)));
          if (clamped !== num) onChange(String(clamped));
        }}
        placeholder={placeholder}
        min={min}
        max={max}
        aria-invalid={error != null}
        className={`w-full rounded-lg border bg-surface-2 px-2.5 py-1.5 text-[13px] text-text outline-none transition focus:border-accent ${
          error ? "border-cf-red" : "border-line"
        }`}
      />
      {error && <span className="text-[10.5px] text-cf-red">{error}</span>}
    </label>
  );
}

export interface GatewaySettingsValue {
  metadata: string; // "k=v,k=v" raw input
  skipCache: boolean;
  cacheTtl: string; // seconds, raw input — "" = unset
  cacheKey: string;
  collectLog: "" | "on" | "off"; // "" = gateway default
  requestTimeoutMs: string;
  maxAttempts: string;
  retryDelayMs: string;
  backoff: "" | GatewayBackoff;
}

export function GatewaySettingsPanel({
  active,
  value,
  onChange,
}: {
  /** true when the route toggle is on AI Gateway — panel renders nothing otherwise */
  active: boolean;
  value: GatewaySettingsValue;
  onChange: (next: GatewaySettingsValue) => void;
}) {
  if (!active) return null;
  const set = <K extends keyof GatewaySettingsValue>(k: K, v: GatewaySettingsValue[K]) => onChange({ ...value, [k]: v });

  const pairs = Object.entries(parseMetadata(value.metadata) ?? {});
  const dropped = value.metadata.split(",").filter((p) => p.includes("=")).length - pairs.length;
  const cacheKeyTooLong = value.cacheKey.length > MAX_CACHE_KEY_LEN;

  return (
    <div className="animate-rise border-t border-line p-4">
      <div className="mb-1 text-[11.5px] font-bold uppercase tracking-wider text-subtle">AI Gateway settings</div>
      <div className="mb-3 text-xs leading-relaxed text-muted">
        Per-request <span className="font-mono">cf-aig-*</span> headers, sent only on this route — a direct Workers AI
        call has no gateway to configure.
      </div>

      <div className="mb-3">
        <span className="text-[11.5px] text-muted">Metadata</span>
        <input
          type="text"
          value={value.metadata}
          onChange={(e) => set("metadata", e.target.value)}
          placeholder="plan=paid, team=telco"
          aria-label="Request metadata as key=value pairs"
          className="mt-1 w-full rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[13px] text-text outline-none transition focus:border-accent"
        />
        {pairs.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {pairs.map(([k, v]) => (
              <span
                key={k}
                className="inline-flex items-center gap-1 rounded-full border border-line bg-surface-2 px-2 py-0.5 text-[11px]"
              >
                <span className="text-subtle">{k}</span>
                <span className="font-mono text-text">{v}</span>
              </span>
            ))}
          </div>
        ) : (
          <p className="mt-1.5 text-[11px] text-subtle">
            <span className="font-mono">key=value</span>, comma-separated. Max {MAX_METADATA_ENTRIES}.
          </p>
        )}
        {dropped > 0 && (
          <p className="mt-1.5 text-[11px] text-cf-amber">
            Only the first {MAX_METADATA_ENTRIES} entries are sent — AI Gateway ignores the rest.
          </p>
        )}
      </div>

      <div className="mb-3">
        <Switch
          checked={value.skipCache}
          onChange={(v) => set("skipCache", v)}
          label="skip cache"
          title="Bypass the gateway cache for this request"
        />
      </div>

      <div className="grid grid-cols-2 gap-2.5">
        <NumberField
          label="Cache TTL (s)"
          value={value.cacheTtl}
          onChange={(v) => set("cacheTtl", v)}
          placeholder="gateway default"
          min={1}
          title="cf-aig-cache-ttl — cache time-to-live for this response, in seconds"
        />
        <label className="flex flex-col gap-1" title="cf-aig-cache-key — custom cache key for this request">
          <span className="text-[11.5px] text-muted">Cache key</span>
          <input
            type="text"
            value={value.cacheKey}
            onChange={(e) => set("cacheKey", e.target.value)}
            onBlur={() => {
              if (cacheKeyTooLong) set("cacheKey", value.cacheKey.slice(0, MAX_CACHE_KEY_LEN));
            }}
            placeholder="auto"
            aria-invalid={cacheKeyTooLong}
            className={`w-full rounded-lg border bg-surface-2 px-2.5 py-1.5 text-[13px] text-text outline-none transition focus:border-accent ${
              cacheKeyTooLong ? "border-cf-red" : "border-line"
            }`}
          />
          {cacheKeyTooLong && <span className="text-[10.5px] text-cf-red">max {MAX_CACHE_KEY_LEN} chars</span>}
        </label>

        <label className="flex flex-col gap-1" title="cf-aig-collect-log — override the gateway's default logging for this request">
          <span className="text-[11.5px] text-muted">Collect log</span>
          <select
            value={value.collectLog}
            onChange={(e) => set("collectLog", e.target.value as GatewaySettingsValue["collectLog"])}
            className="w-full rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[13px] text-text outline-none transition focus:border-accent"
          >
            <option value="">gateway default</option>
            <option value="on">on</option>
            <option value="off">off</option>
          </select>
        </label>
        <NumberField
          label="Timeout (ms)"
          value={value.requestTimeoutMs}
          onChange={(v) => set("requestTimeoutMs", v)}
          placeholder="none"
          min={1}
          title="cf-aig-request-timeout — abort the request after this many milliseconds"
        />

        <NumberField
          label={`Max attempts (≤${MAX_ATTEMPTS_CAP})`}
          value={value.maxAttempts}
          onChange={(v) => set("maxAttempts", v)}
          placeholder="1"
          min={1}
          max={MAX_ATTEMPTS_CAP}
          title={`cf-aig-max-attempts — retry attempts on failure, max ${MAX_ATTEMPTS_CAP}`}
        />
        <NumberField
          label="Retry delay (ms)"
          value={value.retryDelayMs}
          onChange={(v) => set("retryDelayMs", v)}
          placeholder="0"
          min={0}
          max={MAX_RETRY_DELAY_MS}
          title={`cf-aig-retry-delay — delay between retries, max ${MAX_RETRY_DELAY_MS}ms`}
        />
      </div>

      <label className="mt-2.5 flex flex-col gap-1" title="cf-aig-backoff — retry backoff strategy">
        <span className="text-[11.5px] text-muted">Backoff</span>
        <select
          value={value.backoff}
          onChange={(e) => set("backoff", e.target.value as GatewaySettingsValue["backoff"])}
          className="w-full rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-[13px] text-text outline-none transition focus:border-accent"
        >
          <option value="">gateway default</option>
          <option value="constant">constant</option>
          <option value="linear">linear</option>
          <option value="exponential">exponential</option>
        </select>
      </label>
    </div>
  );
}
