// "Raw responses": each external guardrail vendor's response body as it came back, for
// the viewer who switched it on (Settings → Your preferences → Raw vendor responses). A debug view —
// what the parser read, so a verdict this app shows can be checked against what the
// vendor actually said.
//
// It can quote the prompt and whatever the vendor detected (Cato's detection_message
// repeats an SSN), so: collapsed by default, labelled as such, and only ever rendered
// from the one JSON response that carried it — it is never stored, logged or exported.
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useShowRawResponses } from "../hooks/useShowRawResponses";
import { providerLabel } from "../lib/guardrailView";
import { jsonTokens, type JsonTokenKind } from "../lib/jsonTokens";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "../lib/types";

function rawText(r: ExternalGuardrailResult): string {
  const raw = r.raw!;
  return raw.json ? JSON.stringify(raw.body, null, 2) : String(raw.body);
}

// Full class names, never built from the kind: Tailwind and the reader both see them.
const TOKEN_CLASS: Record<JsonTokenKind, string> = {
  key: "tok-key",
  string: "tok-string",
  number: "tok-number",
  boolean: "tok-boolean",
  null: "tok-null",
  punct: "tok-punct",
};

function RawBlock({ r }: { r: ExternalGuardrailResult }) {
  const [copied, setCopied] = useState<"yes" | "no" | null>(null);
  const preRef = useRef<HTMLPreElement>(null);
  const raw = r.raw!;
  const text = rawText(r);
  // Up to 32,000 characters: tokenised once per body, not on every re-render.
  const tokens = useMemo(() => (raw.json ? jsonTokens(text) : null), [raw.json, text]);
  // The label says what happened, then goes back to "Copy" — a stale "Copied" read as if
  // a later click had worked too.
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(null), 2500);
    return () => clearTimeout(t);
  }, [copied]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied("yes");
    } catch {
      // Clipboard refused (permissions, an embedded frame, plain http): say so, never
      // pretend — and select the text so ⌘C / Ctrl+C still works.
      setCopied("no");
      const sel = window.getSelection();
      if (preRef.current && sel) {
        const range = document.createRange();
        range.selectNodeContents(preRef.current);
        sel.removeAllRanges();
        sel.addRange(range);
      }
    }
  }
  const name = providerLabel(r.provider);
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
        <span className="font-semibold text-text">{name}</span>
        <span className="font-mono text-muted">HTTP {raw.status}</span>
        {!raw.json && <span className="text-subtle">{raw.truncated ? "text, cut at 32,000 characters" : "not JSON"}</span>}
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={`Copy the ${name} raw response`}
          className="ml-auto inline-flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 text-[10.5px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Copy size={11} aria-hidden="true" />
          <span aria-live="polite">{copied === "yes" ? "Copied" : copied === "no" ? "Selected — press ⌘C" : "Copy"}</span>
        </button>
      </div>
      {/* `relative`: an overflow box contains its own positioned descendants (CLAUDE.md).
          Focusable and named: a long body scrolls inside this box, which a keyboard user
          could otherwise never reach. Tokens are React text — vendor content is never
          parsed as markup. */}
      <pre
        ref={preRef}
        tabIndex={0}
        aria-label={`${name} raw response`}
        className="relative mt-1 max-h-72 overflow-auto rounded-lg border border-line bg-bg p-2.5 font-mono text-[11px] leading-snug whitespace-pre-wrap break-words text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {tokens
          ? tokens.map((t, i) => (
              <span key={i} className={TOKEN_CLASS[t.kind]}>
                {t.text}
              </span>
            ))
          : text}
      </pre>
    </div>
  );
}

export function GuardrailRawResponses({ pipeline }: { pipeline: GuardrailPipelineResult }) {
  const [enabled] = useShowRawResponses();
  const [open, setOpen] = useState(false);
  const id = useId();
  const withRaw = pipeline.results.filter((r) => r.raw);
  if (withRaw.length === 0) {
    // Switched on, guardrails ran, but this turn has none: say why instead of showing
    // nothing, so it never reads as "the vendors sent empty bodies".
    if (!enabled || pipeline.results.length === 0) return null;
    return (
      <p className="mt-1.5 text-[11px] text-subtle">
        No raw vendor responses for this turn — a streamed reply carries none (turn off “stream replies”), and a turn
        sent before the switch was on has none.
      </p>
    );
  }
  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={id}
        className="inline-flex items-center gap-1 rounded-md text-[11.5px] font-semibold text-muted transition-colors hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        Raw responses ({withRaw.length})
      </button>
      {open && (
        <div id={id} className="mt-1.5 flex flex-col gap-2.5">
          <p className="text-[11px] text-subtle">
            Each vendor's response body as it came back — it can include your prompt and anything the vendor detected
            in it. Shown to you only; not stored, logged or exported.
          </p>
          {withRaw.map((r) => (
            <RawBlock key={r.provider} r={r} />
          ))}
        </div>
      )}
    </div>
  );
}
