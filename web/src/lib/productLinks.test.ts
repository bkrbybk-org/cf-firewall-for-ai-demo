// Console and docs links on Settings (2026-10-14). Pinned: every product has docs; every link is https to the vendor's
// own domain; a per-region console follows the saved region and is left out, never guessed, for a region it does not know.
import { describe, expect, it } from "vitest";
import type { ExternalGuardrailProvider } from "./types";
import { CLOUDFLARE_LINKS, vendorLinks, type ProductLink } from "./productLinks";

const VENDORS: Record<ExternalGuardrailProvider, string[]> = {
  "prisma-airs": ["paloaltonetworks.com", "pan.dev"],
  "crowdstrike-aidr": ["crowdstrike.com"],
  "cisco-ai-defense": ["cisco.com"],
  "lakera-guard": ["lakera.ai"],
  "cato-ai-security": ["catonetworks.com"],
  "datadog-ai-guard": ["datadoghq.com", "datadoghq.eu"],
};

const ownDomain = (l: ProductLink, domains: string[]) => {
  const host = new URL(l.url).host;
  return domains.some((d) => host === d || host.endsWith(`.${d}`));
};

describe("vendorLinks", () => {
  it("every vendor has docs, and every link is https on that vendor's own domain", () => {
    for (const [p, domains] of Object.entries(VENDORS) as [ExternalGuardrailProvider, string[]][]) {
      const links = vendorLinks(p, "us-1", "https://app.datadoghq.com");
      expect(links.some((l) => l.kind === "docs"), p).toBe(true);
      for (const l of links) {
        expect(new URL(l.url).protocol, `${p} ${l.url}`).toBe("https:");
        expect(ownDomain(l, domains), `${p} ${l.url}`).toBe(true);
      }
      expect(new Set(links.map((l) => l.url)).size, `${p}: duplicate url (React key)`).toBe(links.length);
    }
  });

  it("CrowdStrike's console follows the saved cloud, and is left out for one it does not know", () => {
    const consoleOf = (region: string) => vendorLinks("crowdstrike-aidr", region).find((l) => l.kind === "console")?.url;
    expect(consoleOf("us-1")).toBe("https://falcon.crowdstrike.com/aidr/visibility");
    expect(consoleOf("us-2")).toBe("https://falcon.us-2.crowdstrike.com/aidr/visibility");
    expect(consoleOf("eu-1")).toBe("https://falcon.eu-1.crowdstrike.com/aidr/visibility");
    expect(consoleOf("gov-1")).toBeUndefined();
    expect(consoleOf("toString")).toBeUndefined();
  });

  it("Datadog's console is the saved site's own app host, and is left out without one", () => {
    expect(vendorLinks("datadog-ai-guard", "eu1", "https://app.datadoghq.eu").find((l) => l.kind === "console")?.url).toBe(
      "https://app.datadoghq.eu/",
    );
    expect(vendorLinks("datadog-ai-guard", "eu1").some((l) => l.kind === "console")).toBe(false);
  });
});

describe("CLOUDFLARE_LINKS", () => {
  it("every link is https to Cloudflare's dashboard or docs", () => {
    for (const [k, links] of Object.entries(CLOUDFLARE_LINKS)) {
      expect(links.some((l) => l.kind === "docs"), k).toBe(true);
      for (const l of links) {
        expect(["dash.cloudflare.com", "one.dash.cloudflare.com", "developers.cloudflare.com"], `${k} ${l.url}`).toContain(
          new URL(l.url).host,
        );
      }
    }
  });
});
