// Alert delivery (2026-10-19): the body takes the receiver's shape — Slack, Teams Workflows, Discord, or generic JSON —
// picked from the host unless ALERT_WEBHOOK_FORMAT overrides it. Pinned: look-alike hosts are never mistaken for a real
// service; each shape matches its vendor's docs; every shape carries the same text; the URL is never logged.
import { describe, expect, it } from "vitest";
import { deliverAlert, formatBody, webhookFormat } from "./alertDelivery";
import type { Env } from "./types";

const u = (s: string) => new URL(s);
const payload = { text: "cf-ai-waf-demo — external guardrail health\n🔑 Cato REJECTED THE KEY: 12 of 12 checks", alerts: [{ provider: "cato-ai-security" }] };

describe("webhookFormat", () => {
  it("recognises each service by its own host, and nothing that only looks like it", () => {
    expect(webhookFormat(u("https://hooks.slack.com/services/T/B/x"))).toBe("slack");
    expect(webhookFormat(u("https://hooks.slack-gov.com/services/T/B/x"))).toBe("slack");
    expect(webhookFormat(u("https://discord.com/api/webhooks/1/abc"))).toBe("discord");
    expect(webhookFormat(u("https://discordapp.com/api/webhooks/1/abc"))).toBe("discord");
    expect(webhookFormat(u("https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke"))).toBe("teams");
    expect(webhookFormat(u("https://default123.environment.api.powerplatform.com/powerautomate/automations/direct/x"))).toBe("teams");
    expect(webhookFormat(u("https://contoso.webhook.office.com/webhookb2/x"))).toBe("teams");
    for (const s of [
      "https://hooks.slack.com.evil.example/x",
      "https://evilhooks.slack.com/x",
      "https://discord.com/channels/1/2", // not a webhook path
      "https://notdiscord.com/api/webhooks/1/abc",
      "https://logic.azure.com.evil.example/x",
      "https://evil-logic.azure.com/x",
      "https://hooks.example.com/x",
    ]) {
      expect(webhookFormat(u(s)), s).toBe("json");
    }
  });
  it("lets ALERT_WEBHOOK_FORMAT override the guess; an unknown value keeps it", () => {
    expect(webhookFormat(u("https://hooks.example.com/x"), "Slack ")).toBe("slack");
    expect(webhookFormat(u("https://hooks.slack.com/services/x"), "json")).toBe("json");
    expect(webhookFormat(u("https://hooks.slack.com/services/x"), "email")).toBe("slack");
  });
});

describe("formatBody", () => {
  it("slack: {text} only (docs.slack.dev — text is required)", () => {
    expect(formatBody("slack", payload)).toEqual({ text: payload.text });
  });
  it("discord: {content} within 2000 characters, and no mention can ping (docs.discord.com)", () => {
    expect(formatBody("discord", payload)).toEqual({ content: payload.text, allowed_mentions: { parse: [] } });
    const long = formatBody("discord", { text: "x".repeat(2500) }) as { content: string };
    expect(long.content).toHaveLength(2000);
    expect(long.content.endsWith("…")).toBe(true);
  });
  it("teams: a Workflows message with one Adaptive Card, title bold, one block per line (Microsoft's sample shape)", () => {
    expect(formatBody("teams", payload)).toEqual({
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
              { type: "TextBlock", text: "cf-ai-waf-demo — external guardrail health", weight: "Bolder", wrap: true },
              { type: "TextBlock", text: "🔑 Cato REJECTED THE KEY: 12 of 12 checks", wrap: true },
            ],
          },
        },
      ],
    });
  });
  it("json: the payload as built", () => {
    expect(formatBody("json", payload)).toBe(payload);
  });
});

describe("deliverAlert", () => {
  it("posts the receiver's shape and logs the format — never the URL", async () => {
    const sent: { url: string; body: unknown }[] = [];
    const lines: unknown[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      sent.push({ url, body: JSON.parse(String(init?.body)) });
      return new Response(null, { status: 204 }); // Discord's success
    }) as typeof fetch;
    const env = { ALERT_WEBHOOK_URL: "https://discord.com/api/webhooks/1/secret-token" } as unknown as Env;
    expect(await deliverAlert(env, "guardrail_alert", payload, { fetchImpl, log: (l) => lines.push(l) })).toBe("webhook");
    expect(sent[0].body).toEqual({ content: payload.text, allowed_mentions: { parse: [] } });
    expect(lines[0]).toMatchObject({ event: "guardrail_alert", delivered: "webhook", format: "discord", status: 204 });
    expect(JSON.stringify(lines)).not.toContain("secret-token");
  });
});
