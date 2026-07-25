import type { ReactNode } from "react";
import { NavTabs } from "./NavTabs";

// Two-row header: brand + page-specific actions on top, shared route tab strip
// below. `actions` holds only page-level controls (Run demo, theme, neuron) —
// navigation is the tab strip, consistent across every page.
export function Header({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="sticky top-0 z-10 border-b border-line bg-surface/80 backdrop-blur-md">
      <div className="flex flex-wrap items-center gap-3 px-5 pt-3 pb-2">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2.5 text-[15.5px] font-semibold tracking-tight">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-accent shadow-[0_0_0_4px] shadow-accent/25" />
            {title}
          </h1>
          <div className="mt-0.5 text-xs text-muted">{subtitle}</div>
        </div>
        {actions && <div className="ml-auto flex flex-wrap items-center gap-2.5">{actions}</div>}
      </div>
      <NavTabs />
    </header>
  );
}
