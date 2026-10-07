// Building blocks of the Settings page. The page has two kinds of setting that
// must never be mistaken for each other — a preference saved in this browser and
// a system setting every user shares — so each section says which it is in its
// header, in words and with its own icon, before any control.
import type { ReactNode } from "react";

export function SectionHeader({
  id,
  icon,
  title,
  scope,
  scopeTone,
  children,
}: {
  id: string;
  icon: ReactNode;
  title: string;
  scope: string; // "This browser only" / "Shared — every user"
  scopeTone: "viewer" | "system";
  children?: ReactNode; // the one-paragraph explanation of what "scope" means here
}) {
  const chip =
    scopeTone === "viewer" ? "border-cf-blue/50 bg-cf-blue/10 text-cf-blue" : "border-cf-amber/60 bg-cf-amber/10 text-cf-amber";
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-line bg-surface-2 text-muted">
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id={id} className="text-[16px] font-bold text-text">
            {title}
          </h2>
          <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${chip}`}>{scope}</span>
        </div>
        {children && <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{children}</p>}
      </div>
    </div>
  );
}

// A titled group inside a section, e.g. "Traffic flow". `id` is the in-page nav target.
export function Group({ id, title, hint, children }: { id: string; title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div id={id} className="scroll-mt-4">
      <div className="mb-2 px-1">
        <h3 className="text-[13px] font-bold text-text">{title}</h3>
        {hint && <div className="mt-0.5 text-[11.5px] leading-relaxed text-muted">{hint}</div>}
      </div>
      {children}
    </div>
  );
}

// One setting: what it is on the left, the control on the right (stacked on a
// phone). `note` is the line under it — a save failure replaces it.
export function SettingRow({
  label,
  labelId,
  description,
  control,
  note,
}: {
  label: string;
  labelId: string;
  description: ReactNode;
  control: ReactNode;
  note?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2 border-t border-line px-4 py-3 first:border-t-0 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
      <div className="min-w-0 sm:max-w-[60%]">
        <div id={labelId} className="text-[13px] font-semibold text-text">
          {label}
        </div>
        <div className="mt-0.5 text-[12px] leading-relaxed text-muted">{description}</div>
        {note && (
          <div aria-live="polite" className="mt-1 text-[11.5px] leading-relaxed text-subtle">
            {note}
          </div>
        )}
      </div>
      <div className="shrink-0">{control}</div>
    </div>
  );
}

export function Segmented<T extends string>({
  labelledBy,
  options,
  value,
  onChange,
}: {
  labelledBy: string;
  options: { id: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div role="group" aria-labelledby={labelledBy} className="inline-flex overflow-hidden rounded-full border border-line">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-pressed={value === o.id}
          onClick={() => onChange(o.id)}
          className={`px-3 py-1.5 text-[12.5px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset ${
            value === o.id ? "bg-accent/15 font-semibold text-accent" : "bg-surface text-muted hover:text-text"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export const PANEL = "rounded-2xl border border-line bg-surface shadow-sm";
