// Console and documentation links for every product on the Settings page, so an operator can jump to the vendor's
// own console (to rotate a key, read a policy) or its docs without hunting for them.
//
// Every URL here was opened on 2026-10-14: each docs page answered 200, and each console answered 200 or a 302 to that
// vendor's own login. Hosts come from the vendor's docs, never guessed from an API host's spelling. Where a vendor
// documents no deep link, the link is the console's front door and its label says so (Cisco's Security Cloud Control,
// Cato's Management Application). A product with no documented console URL gets docs only, not a guess.
//
// These are plain outbound links: nothing from the page (no key, profile name or prompt) is put in them.
import type { ExternalGuardrailProvider } from "./types";

export interface ProductLink {
  kind: "console" | "docs" | "api";
  label: string; // the visible text
  title: string; // the tooltip: where it goes
  url: string;
}

// CrowdStrike's Falcon console has one host per cloud. The docs link US-1's (`falcon.crowdstrike.com/…/aidr/visibility`,
// aidr-docs.crowdstrike.com/docs/aidr/get-started), and AIDR runs in US-1, US-2 and EU-1 (same page). The US-2 and EU-1
// hosts follow Falcon's per-cloud console naming and redirect to their own login with the same path.
const FALCON_HOSTS: Record<string, string> = {
  "us-1": "https://falcon.crowdstrike.com",
  "us-2": "https://falcon.us-2.crowdstrike.com",
  "eu-1": "https://falcon.eu-1.crowdstrike.com",
};

// `region` is the provider's saved region id; `regionUrl` is that region's API base from the server's allowlist. For
// Datadog the API base IS the site's app host (app.datadoghq.com, us3.datadoghq.com…), so it doubles as the console.
export function vendorLinks(provider: ExternalGuardrailProvider, region: string, regionUrl?: string): ProductLink[] {
  switch (provider) {
    case "prisma-airs":
      return [
        {
          kind: "console",
          label: "Console",
          title: "Strata Cloud Manager — products settings, where the AI security profile and API keys live",
          url: "https://stratacloudmanager.paloaltonetworks.com/settings/products",
        },
        { kind: "docs", label: "Docs", title: "Prisma AIRS documentation", url: "https://docs.paloaltonetworks.com/prisma-airs" },
        { kind: "api", label: "API", title: "Prisma AIRS on pan.dev (API reference)", url: "https://pan.dev/airs/" },
      ];
    case "crowdstrike-aidr": {
      const host = Object.hasOwn(FALCON_HOSTS, region) ? FALCON_HOSTS[region] : undefined; // not "toString" etc.
      return [
        ...(host
          ? [
              {
                kind: "console" as const,
                label: "Console",
                title: `Falcon console (${region.toUpperCase()}) — AI detection and response → Visibility`,
                url: `${host}/aidr/visibility`,
              },
            ]
          : []),
        {
          kind: "docs",
          label: "Docs",
          title: "CrowdStrike Falcon AIDR documentation",
          url: "https://aidr-docs.crowdstrike.com/docs/aidr/",
        },
      ];
    }
    case "cisco-ai-defense":
      return [
        {
          kind: "console",
          label: "Console",
          title: "Cisco Security Cloud Control — AI Defense is administered there (sign in, then open AI Defense)",
          url: "https://security.cisco.com/",
        },
        {
          kind: "docs",
          label: "Docs",
          title: "AI Defense User Guide (Cisco Security Documentation)",
          url: "https://securitydocs.cisco.com/docs/ai-def/user/97384.dita",
        },
        {
          kind: "api",
          label: "API",
          title: "AI Defense Inspection API (Cisco DevNet)",
          url: "https://developer.cisco.com/docs/ai-defense-inspection/",
        },
      ];
    case "lakera-guard":
      return [
        { kind: "console", label: "Console", title: "Lakera platform — projects, policies and API keys", url: "https://platform.lakera.ai/" },
        { kind: "docs", label: "Docs", title: "Lakera documentation", url: "https://docs.lakera.ai/" },
        { kind: "api", label: "API", title: "Lakera Guard API reference (/v2/guard)", url: "https://docs.lakera.ai/docs/api/guard" },
      ];
    case "cato-ai-security":
      // Cato publishes no API reference for /fw/v1/analyze (CLAUDE.md), so there is no API link.
      return [
        {
          kind: "console",
          label: "Console",
          title: "Cato Management Application (sign in, then AI Security)",
          url: "https://cc.catonetworks.com/",
        },
        {
          kind: "docs",
          label: "Docs",
          title: "Getting Started with AI Security (Cato knowledge base)",
          url: "https://knowledge.catonetworks.com/docs/getting-started-with-ai-security",
        },
      ];
    case "datadog-ai-guard":
      return [
        ...(regionUrl
          ? [{ kind: "console" as const, label: "Console", title: `Datadog (${new URL(regionUrl).host})`, url: `${regionUrl}/` }]
          : []),
        { kind: "docs", label: "Docs", title: "Datadog AI Guard documentation", url: "https://docs.datadoghq.com/security/ai_guard/" },
        {
          kind: "api",
          label: "API",
          title: "AI Guard HTTP API (Datadog docs)",
          url: "https://docs.datadoghq.com/security/ai_guard/setup/http_api/",
        },
      ];
  }
}

// Cloudflare's own products, as the Settings page shows them. `dash.cloudflare.com/?to=/:account/…` is the deep-link
// form Cloudflare's docs use ("Go to AI Gateway" on ai-gateway/configuration/manage-gateway, `workers/d1` on
// d1/get-started, `workers-and-pages` on workers/configuration/cron-triggers, `:zone/security/settings` on
// waf/detections/ai-security-for-apps/get-started): the dashboard fills in the account (and asks for the zone).
// Workers AI has no documented deep link, so it gets docs only.
const dash = (to: string) => `https://dash.cloudflare.com/?to=${to}`;

export const CLOUDFLARE_LINKS = {
  edge: [
    { kind: "console", label: "Console", title: "Cloudflare dashboard — the zone's Security settings", url: dash("/:account/:zone/security/settings") },
    {
      kind: "docs",
      label: "Docs",
      title: "AI Security for Apps (Cloudflare WAF docs)",
      url: "https://developers.cloudflare.com/waf/detections/ai-security-for-apps/",
    },
  ],
  d1: [
    { kind: "console", label: "Console", title: "Cloudflare dashboard — D1", url: dash("/:account/workers/d1") },
    { kind: "docs", label: "Docs", title: "Cloudflare D1 docs", url: "https://developers.cloudflare.com/d1/" },
  ],
  cron: [
    { kind: "console", label: "Console", title: "Cloudflare dashboard — Workers & Pages", url: dash("/:account/workers-and-pages") },
    {
      kind: "docs",
      label: "Docs",
      title: "Cron Triggers (Cloudflare Workers docs)",
      url: "https://developers.cloudflare.com/workers/configuration/cron-triggers/",
    },
  ],
  access: [
    { kind: "console", label: "Console", title: "Cloudflare Zero Trust dashboard", url: "https://one.dash.cloudflare.com/" },
    {
      kind: "docs",
      label: "Docs",
      title: "Cloudflare Access docs",
      url: "https://developers.cloudflare.com/cloudflare-one/access-controls/",
    },
  ],
  aiGateway: [
    { kind: "console", label: "Console", title: "Cloudflare dashboard — AI Gateway", url: dash("/:account/ai/ai-gateway") },
    { kind: "docs", label: "Docs", title: "Cloudflare AI Gateway docs", url: "https://developers.cloudflare.com/ai-gateway/" },
  ],
  workersAi: [
    { kind: "docs", label: "Docs", title: "Cloudflare Workers AI docs", url: "https://developers.cloudflare.com/workers-ai/" },
    { kind: "docs", label: "Models", title: "Workers AI model catalog", url: "https://developers.cloudflare.com/workers-ai/models/" },
  ],
} satisfies Record<string, ProductLink[]>;
