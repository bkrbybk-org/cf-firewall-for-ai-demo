// Tailwind's standard toggle-switch pattern (Tailwind Plus "Toggle" component,
// reimplemented from scratch since the block's source is behind a paywall) —
// a pill track with a sliding thumb, driven by plain state instead of
// Headless UI's Switch so it stays dependency-free.
export function Switch({
  checked,
  onChange,
  label,
  title,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: React.ReactNode;
  title?: string;
  disabled?: boolean;
}) {
  return (
    <span className={`inline-flex items-center gap-2 ${disabled ? "opacity-50" : ""}`} title={title}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg disabled:cursor-not-allowed ${
          checked ? "bg-accent" : "bg-line-strong"
        }`}
      >
        <span
          aria-hidden="true"
          className={`pointer-events-none inline-block h-5 w-5 translate-x-0.5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
            checked ? "translate-x-[22px]" : "translate-x-0.5"
          }`}
        />
      </button>
      {label && <span className="cursor-pointer text-[13px]" onClick={() => !disabled && onChange(!checked)}>{label}</span>}
    </span>
  );
}
