import { useMemo, useState } from "react";
import { ChevronRight, Search } from "lucide-react";
import { CATEGORIES, type Tone } from "../lib/data";
import { categoryIcon } from "../lib/icons";

const ACCENT: Record<Tone, string> = {
  green: "bg-cf-green",
  red: "bg-cf-red",
  amber: "bg-cf-amber",
  blue: "bg-cf-blue",
  purple: "bg-cf-purple",
};
const ICON_TONE: Record<Tone, string> = {
  green: "bg-cf-green/12 text-cf-green",
  red: "bg-cf-red/12 text-cf-red",
  amber: "bg-cf-amber/12 text-cf-amber",
  blue: "bg-cf-blue/12 text-cf-blue",
  purple: "bg-cf-purple/12 text-cf-purple",
};

export function AttackLibrary({
  onPick,
  side = "right",
}: {
  onPick: (prompt: string) => void;
  /** Which edge of the panel sits against the chat column. Default "right"
   *  (panel is the rightmost column, so its own left edge gets the border). */
  side?: "left" | "right";
}) {
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();

  // Categories start COLLAPSED. There are a dozen of them and the longest runs
  // to eleven prompts, so expanded-by-default buried the lower half of the list
  // below several screens of scrolling — the panel read as a wall rather than a
  // menu. Held as a set of open titles (not a single id) so several can be open
  // at once while comparing categories.
  const [openTitles, setOpenTitles] = useState<Set<string>>(new Set());
  const toggle = (title: string) =>
    setOpenTitles((prev) => {
      const next = new Set(prev);
      if (!next.delete(title)) next.add(title);
      return next;
    });

  const filtered = useMemo(() => {
    if (!query) return CATEGORIES.map((c) => ({ cat: c, presets: c.presets }));
    return CATEGORIES.map((c) => {
      const titleHit = c.title.toLowerCase().includes(query);
      const presets = titleHit
        ? c.presets
        : c.presets.filter(
            (p) => p.label.toLowerCase().includes(query) || p.prompt.toLowerCase().includes(query),
          );
      return { cat: c, presets };
    }).filter((x) => x.presets.length > 0);
  }, [query]);

  // Searching overrides the collapsed state: a hit the user cannot see is the
  // same as no hit, so anything the filter kept is expanded for as long as the
  // query stands. Clearing the box returns to whatever they had opened by hand.
  const searching = query.length > 0;

  const borderSide = side === "right" ? "lg:border-l" : "lg:border-r";

  return (
    <aside className={`w-full shrink-0 overflow-y-auto border-t border-line bg-surface p-4 lg:w-[380px] lg:border-t-0 ${borderSide}`}>
      <div className="mb-1 text-[11.5px] font-bold uppercase tracking-wider text-subtle">Attack Library</div>
      <div className="mb-3 text-xs leading-relaxed text-muted">
        Grouped by threat category, mapped to OWASP LLM Top 10 (2025) &amp; MITRE ATLAS. Click a prompt to load it.
      </div>

      <div className="relative mb-4">
        <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search prompts…"
          className="w-full rounded-lg border border-line bg-surface-2 py-2 pl-9 pr-3 text-[13px] text-text outline-none focus:border-accent"
        />
      </div>

      {filtered.map(({ cat, presets }) => {
        const Icon = categoryIcon(cat.iconKey);
        const open = searching || openTitles.has(cat.title);
        const panelId = `atk-${cat.title.replace(/\W+/g, "-").toLowerCase()}`;
        return (
          <div
            key={cat.title}
            className="relative mb-3 overflow-hidden rounded-xl border border-line bg-surface-2 p-3.5 transition hover:border-line-strong hover:shadow-md"
          >
            <span className={`absolute inset-y-0 left-0 w-[3px] ${ACCENT[cat.tone]}`} />
            <button
              type="button"
              onClick={() => toggle(cat.title)}
              aria-expanded={open}
              aria-controls={panelId}
              className="flex w-full items-center gap-2.5 text-left"
            >
              <span className={`grid h-7 w-7 place-items-center rounded-lg ${ICON_TONE[cat.tone]}`}>
                <Icon size={15} />
              </span>
              <span className="text-sm font-semibold tracking-tight">{cat.title}</span>
              {/* Collapsed, the count is the only signal of how much is inside. */}
              <span className="ml-auto shrink-0 font-mono text-[11px] text-subtle tabular-nums">{presets.length}</span>
              <ChevronRight
                size={14}
                className={`shrink-0 text-subtle transition-transform ${open ? "rotate-90" : ""}`}
              />
            </button>
            <div id={panelId} hidden={!open} className="mt-2">
            {(cat.owasp || cat.atlas) && (
              <div className="mb-2 flex flex-wrap gap-1.5">
                {cat.owasp && (
                  <span className="rounded-full border border-cf-blue/40 bg-cf-blue/10 px-2 py-0.5 text-[10.5px] font-semibold text-cf-blue">
                    {cat.owasp}
                  </span>
                )}
                {cat.atlas && (
                  <span className="rounded-full border border-cf-purple/40 bg-cf-purple/10 px-2 py-0.5 text-[10.5px] font-semibold text-cf-purple">
                    {cat.atlas}
                  </span>
                )}
              </div>
            )}
            <div className="mb-2.5 text-[11px] leading-snug text-muted">{cat.field}</div>
            <div className="flex flex-col gap-1.5">
              {presets.map((p) => (
                <button
                  key={p.label + p.prompt}
                  type="button"
                  onClick={() => onPick(p.prompt)}
                  className="rounded-lg border border-line bg-surface px-2.5 py-2 text-left text-[12.5px] leading-snug transition hover:border-accent hover:bg-surface-hover active:scale-[.985]"
                >
                  <span className="block font-semibold">{p.label}</span>
                  <span className="mt-0.5 block text-[11px] text-muted">{p.prompt}</span>
                </button>
              ))}
            </div>
            </div>
          </div>
        );
      })}
      {filtered.length === 0 && <div className="text-sm text-muted">No prompts match “{q}”.</div>}
    </aside>
  );
}
