// Where every alert goes (#17 outage alerts, 2026-10-18 verdict changes): one webhook the operator sets as a secret
// (ALERT_WEBHOOK_URL); until it is set, an alert is only a line in the Worker's logs and nothing leaves Cloudflare
// (decided with the user, 2026-10-12). Shared so both alerts obey the same rules:
//   - only an https URL to a public host is ever called; anything else is refused and logged as such, without the value;
//   - a payload names vendors, prompt ids, labels and counts — the callers build it from those only, never from an
//     error text, a prompt or a vendor's message;
//   - delivery never throws: an alert that cannot be sent is logged, and the check that raised it carries on.
//
// The body takes the shape the receiver expects (2026-10-19), picked from the URL's host unless ALERT_WEBHOOK_FORMAT
// says otherwise — so a Slack, Teams or Discord URL works pasted as is. Shapes from each vendor's own docs, 2026-10-19:
//   - slack   — `{text}` (docs.slack.dev, incoming webhooks: `text` is required, `no_text` without it; answers 200 "ok").
//               Hosts hooks.slack.com and, for GovSlack, hooks.slack-gov.com.
//   - discord — `{content}`, at most 2000 characters (docs.discord.com, Execute Webhook; 204 without ?wait=true), with
//               `allowed_mentions: {parse: []}` so no text can ever ping a channel. Host discord.com / discordapp.com,
//               path /api/webhooks/….
//   - teams   — a Workflows ("When a Teams webhook request is received") message: `{type: "message", attachments:
//               [{contentType: "application/vnd.microsoft.card.adaptive", content: <AdaptiveCard>}]}`, as Microsoft's own
//               sample sends it (learn.microsoft.com, add-incoming-webhook). The standard template reads `attachments`,
//               and fails without them. Hosts *.logic.azure.com and *.powerplatform.com (Workflows), *.webhook.office.com
//               (the retiring connectors).
//   - json    — anything else: the payload as built, `{text, …structured fields}`.
// Only the shape changes: every format carries the same text, made of names and counts only.

import type { Env } from "./types";

const WEBHOOK_TIMEOUT_MS = 5000;

export const WEBHOOK_FORMATS = ["slack", "teams", "discord", "json"] as const;
export type WebhookFormat = (typeof WEBHOOK_FORMATS)[number];

const endsWith = (host: string, suffix: string) => host === suffix.slice(1) || host.endsWith(suffix);

export function webhookFormat(url: URL, override?: string): WebhookFormat {
  const o = override?.trim().toLowerCase();
  if (o && (WEBHOOK_FORMATS as readonly string[]).includes(o)) return o as WebhookFormat;
  const h = url.hostname.toLowerCase();
  if (h === "hooks.slack.com" || h === "hooks.slack-gov.com") return "slack";
  if ((h === "discord.com" || h === "discordapp.com") && url.pathname.startsWith("/api/webhooks/")) return "discord";
  if (endsWith(h, ".logic.azure.com") || endsWith(h, ".powerplatform.com") || endsWith(h, ".webhook.office.com")) return "teams";
  return "json";
}

const DISCORD_MAX = 2000;

export function formatBody(format: WebhookFormat, payload: { text: string } & Record<string, unknown>): unknown {
  switch (format) {
    case "slack":
      return { text: payload.text };
    case "discord":
      return {
        content: payload.text.length > DISCORD_MAX ? payload.text.slice(0, DISCORD_MAX - 1) + "…" : payload.text,
        allowed_mentions: { parse: [] },
      };
    case "teams": {
      const [title, ...lines] = payload.text.split("\n");
      return {
        type: "message",
        attachments: [
          {
            contentType: "application/vnd.microsoft.card.adaptive",
            contentUrl: null,
            content: {
              $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
              type: "AdaptiveCard",
              version: "1.2",
              body: [
                { type: "TextBlock", text: title, weight: "Bolder", wrap: true },
                ...lines.map((text) => ({ type: "TextBlock", text, wrap: true })),
              ],
            },
          },
        ],
      };
    }
    case "json":
      return payload;
  }
}

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
  const format = webhookFormat(url, env.ALERT_WEBHOOK_FORMAT);
  try {
    const r = await fetchImpl(url.toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(formatBody(format, payload)),
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    });
    const delivered: Delivery = r.ok ? "webhook" : "failed";
    log({ event, delivered, format, status: r.status, ...payload });
    return delivered;
  } catch (err) {
    log({ event, delivered: "failed", format, error: err instanceof Error ? err.name : "error", ...payload });
    return "failed";
  }
}
