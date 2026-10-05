// The red-team result pill, shared by the live attack table and the saved-run diff
// so a state reads the same everywhere it appears.
export const STATE_PILL: Record<string, { label: string; cls: string }> = {
  allow: { label: "reached", cls: "border-cf-red/50 text-cf-red" },
  log: { label: "reached · logged", cls: "border-cf-amber/50 text-cf-amber" },
  block: { label: "blocked", cls: "border-cf-green/50 text-cf-green" },
  challenge: { label: "challenged", cls: "border-cf-green/50 text-cf-green" },
  denied: { label: "denied (non-WAF)", cls: "border-line text-muted" },
  guardrails: { label: "guardrails", cls: "border-cf-purple/50 text-cf-purple" },
  // Amber, matching the chat's external-guardrail card — never the WAF's red or
  // AI Gateway Guardrails' purple, so the three controls cannot be confused.
  external: { label: "external guardrail", cls: "border-cf-amber/50 text-cf-amber" },
  pending: { label: "no verdict", cls: "border-line text-subtle" },
  error: { label: "failed", cls: "border-line text-subtle" },
};

export function StatePill({ state }: { state: string }) {
  // An unknown state is shown as itself, never mapped onto a known one.
  const pill = STATE_PILL[state] ?? { label: state, cls: "border-line text-muted" };
  return (
    <span className={`rounded-full border px-1.5 py-px text-[10px] font-semibold whitespace-nowrap ${pill.cls}`}>
      {pill.label}
    </span>
  );
}
