import { useMemo, useState } from "react";
import { Search } from "lucide-react";
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
        return (
          <div
            key={cat.title}
            className="relative mb-3 overflow-hidden rounded-xl border border-line bg-surface-2 p-3.5 transition hover:border-line-strong hover:shadow-md"
          >
            <span className={`absolute inset-y-0 left-0 w-[3px] ${ACCENT[cat.tone]}`} />
            <div className="mb-2 flex items-center gap-2.5">
              <span className={`grid h-7 w-7 place-items-center rounded-lg ${ICON_TONE[cat.tone]}`}>
                <Icon size={15} />
              </span>
              <span className="text-sm font-semibold tracking-tight">{cat.title}</span>
            </div>
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
        );
      })}
      {filtered.length === 0 && <div className="text-sm text-muted">No prompts match “{q}”.</div>}
    </aside>
  );
}
