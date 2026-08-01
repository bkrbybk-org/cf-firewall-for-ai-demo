import { useMemo, useState } from "react";
import { PRESET_SYSTEM_PROMPTS } from "../lib/data";

export function SystemPromptPanel({
  value,
  onChange,
  defaultPrompt,
  maxLen,
}: {
  value: string;
  onChange: (v: string) => void;
  defaultPrompt: string;
  maxLen: number;
}) {
  const [open, setOpen] = useState(false);

  // First preset's prompt comes from the server default.
  const presets = useMemo(
    () => PRESET_SYSTEM_PROMPTS.map((p, i) => (i === 0 ? { ...p, prompt: defaultPrompt } : p)),
    [defaultPrompt],
  );
  const match = presets.find((p) => p.prompt.trim() === value.trim());
  const activeName = match ? match.label : "Custom";
  const selectValue = match ? match.id : "custom";
  const preview = value.trim() ? (value.length > 140 ? value.slice(0, 140) + "…" : value) : "(empty — server default used)";



  return (
    <section className="p-4">
      <div className="mb-1 text-[11.5px] font-bold uppercase tracking-wider text-subtle">System Prompt</div>
      <div className="mb-3 text-xs leading-relaxed text-muted">
        Choose a preset persona or write your own. Applies to every new message.
      </div>

      <div className="relative mb-3 overflow-hidden rounded-xl border border-line bg-surface-2 p-3 pl-4">
        <span className="absolute inset-y-0 left-0 w-[3px] bg-accent" />
        <div className="mb-1 text-[12.5px] font-semibold">{activeName}</div>
        <div className="max-h-[4.5em] overflow-hidden text-[11.5px] leading-snug text-muted">{preview}</div>
      </div>

      <select
        value={selectValue}
        onChange={(e) => {
          const id = e.target.value;
          if (id === "custom") {
            setOpen(true);
            return;
          }
          const p = presets.find((x) => x.id === id);
          if (p) onChange(p.prompt);
        }}
        className="mb-2.5 w-full rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] text-text outline-none focus:border-accent"
      >
        {presets.map((p) => (
          <option key={p.id} value={p.id}>
            {p.label}
          </option>
        ))}
        <option value="custom">Custom…</option>
      </select>

      <details open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer list-none text-[12.5px] text-muted hover:text-text">
          Customize system prompt
        </summary>
        <div className="mt-2 flex flex-col gap-1.5">
          <textarea
            value={value}
            maxLength={maxLen}
            onChange={(e) => onChange(e.target.value)}
            rows={6}
            placeholder={defaultPrompt || "System prompt sent with every request…"}
            className="min-h-16 resize-y rounded-lg border border-line bg-surface p-3 text-[13px] leading-relaxed text-text outline-none focus:border-accent"
          />
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span>
              {value.length} / {maxLen} chars
            </span>
            <button
              type="button"
              onClick={() => onChange(defaultPrompt)}
              className="rounded-md border border-line bg-surface-2 px-2.5 py-1 text-xs transition hover:border-accent hover:bg-surface-hover"
            >
              Reset to default
            </button>
          </div>
        </div>
      </details>
    </section>
  );
}
