// "Raw responses": each external guardrail vendor's response body as it came back, for
// the viewer who switched it on (/guardrails → Raw vendor responses). A debug view —
// what the parser read, so a verdict this app shows can be checked against what the
// vendor actually said.
//
// It can quote the prompt and whatever the vendor detected (Cato's detection_message
// repeats an SSN), so: collapsed by default, labelled as such, and only ever rendered
// from the one JSON response that carried it — it is never stored, logged or exported.
import { useId, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useShowRawResponses } from "../hooks/useShowRawResponses";
import { providerLabel } from "../lib/guardrailView";
import type { ExternalGuardrailResult, GuardrailPipelineResult } from "../lib/types";

function rawText(r: ExternalGuardrailResult): string {
  const raw = r.raw!;
  return raw.json ? JSON.stringify(raw.body, null, 2) : String(raw.body);
}

function RawBlock({ r }: { r: ExternalGuardrailResult }) {
  const [copied, setCopied] = useState<"yes" | "no" | null>(null);
  const preRef = useRef<HTMLPreElement>(null);
  const raw = r.raw!;
  const text = rawText(r);
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
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
        <span className="font-semibold text-text">{providerLabel(r.provider)}</span>
        <span className="font-mono text-muted">HTTP {raw.status}</span>
        {!raw.json && <span className="text-subtle">{raw.truncated ? "text, cut at 32,000 characters" : "not JSON"}</span>}
        <button
          type="button"
          onClick={() => void copy()}
          className="ml-auto inline-flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 text-[10.5px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Copy size={11} aria-hidden="true" />
          {copied === "yes" ? "Copied" : copied === "no" ? "Selected — press ⌘C" : "Copy"}
        </button>
      </div>
      {/* `relative`: an overflow box contains its own positioned descendants (CLAUDE.md). */}
      <pre ref={preRef} className="relative mt-1 max-h-72 overflow-auto rounded-lg border border-line bg-bg p-2.5 font-mono text-[11px] leading-snug whitespace-pre-wrap break-words text-text">
        {text}
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
