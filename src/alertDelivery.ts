// Where every alert goes (#17 outage alerts, 2026-10-18 verdict changes): one webhook the operator sets as a secret
// (ALERT_WEBHOOK_URL); until it is set, an alert is only a line in the Worker's logs and nothing leaves Cloudflare
// (decided with the user, 2026-10-12). Shared so both alerts obey the same rules:
//   - only an https URL to a public host is ever called; anything else is refused and logged as such, without the value;
//   - a payload names vendors, prompt ids, labels and counts — the callers build it from those only, never from an
//     error text, a prompt or a vendor's message;
//   - delivery never throws: an alert that cannot be sent is logged, and the check that raised it carries on.

import type { Env } from "./types";

const WEBHOOK_TIMEOUT_MS = 5000;

export function webhookUrl(raw: string | undefined): URL | null {
  if (!raw) return null;
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "https:" || /^(localhost|127\.|10\.|192\.168\.|\[)/.test(u.hostname)) return null;
    return u;
  } catch {
    return null;
  }
}

export type Delivery = "webhook" | "log" | "failed";

// `event` names the log line ("guardrail_alert", "guardrail_verdict_change"); `payload` must carry a `text`.
export async function deliverAlert(
  env: Env,
  event: string,
  payload: { text: string } & Record<string, unknown>,
  deps: { fetchImpl?: typeof fetch; log?: (line: unknown) => void } = {},
): Promise<Delivery> {
  const log = deps.log ?? ((line: unknown) => console.log(line));
  const fetchImpl = deps.fetchImpl ?? fetch;
  const url = webhookUrl(env.ALERT_WEBHOOK_URL);
  if (env.ALERT_WEBHOOK_URL && !url) {
    log({ event, note: "ALERT_WEBHOOK_URL is set but is not an https URL to a public host — not called", ...payload });
    return "log";
  }
  if (!url) {
    log({ event, note: "ALERT_WEBHOOK_URL is not set — logged only", ...payload });
    return "log";
  }
  try {
    const r = await fetchImpl(url.toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    });
    const delivered: Delivery = r.ok ? "webhook" : "failed";
    log({ event, delivered, status: r.status, ...payload });
    return delivered;
  } catch (err) {
    log({ event, delivered: "failed", error: err instanceof Error ? err.name : "error", ...payload });
    return "failed";
  }
}
