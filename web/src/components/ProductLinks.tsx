// A product's console / docs / API links (lib/productLinks.ts), as a row of small outbound links. The visible text is
// short ("Console"), so each link's accessible name carries the product: a screen reader's link list would otherwise
// read "Console, Console, Console…" for six vendors.
import { ExternalLink } from "lucide-react";
import type { ProductLink } from "../lib/productLinks";

export function ProductLinks({ product, links, className = "" }: { product: string; links: ProductLink[]; className?: string }) {
  if (links.length === 0) return null;
  return (
    <span className={`flex flex-wrap items-center gap-x-3 gap-y-1 ${className}`}>
      {links.map((l) => (
        <a
          key={l.url}
          href={l.url}
          target="_blank"
          rel="noopener noreferrer"
          title={l.title}
          aria-label={`${product} ${l.label} (opens in a new tab)`}
          className="inline-flex items-center gap-1 rounded text-[11.5px] font-medium whitespace-nowrap text-accent-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {l.label}
          <ExternalLink size={11} aria-hidden />
        </a>
      ))}
    </span>
  );
}
