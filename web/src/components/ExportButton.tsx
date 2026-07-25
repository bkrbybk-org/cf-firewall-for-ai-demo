// "Export" dropdown for the chat controls row — downloads the current
// session as JSON (structured, re-analyzable) or Markdown (human-readable,
// for handing to a customer). See lib/export.ts for the assembly logic.
import { useEffect, useRef, useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { buildSessionExport, downloadFile, toMarkdown } from "../lib/export";
import type { Msg } from "../hooks/useChat";

export function ExportButton({ messages, systemPrompt }: { messages: Msg[]; systemPrompt: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const hasTurns = messages.some((m) => m.kind === "user");

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  async function run(format: "json" | "md") {
    setOpen(false);
    setBusy(true);
    try {
      const exp = await buildSessionExport(messages, systemPrompt);
      const stamp = exp.exportedAt.replace(/[:.]/g, "-");
      if (format === "json") {
        downloadFile(`cf-ai-security-session-${stamp}.json`, JSON.stringify(exp, null, 2), "application/json");
      } else {
        downloadFile(`cf-ai-security-session-${stamp}.md`, toMarkdown(exp), "text/markdown");
      }
    } finally {
      setBusy(false);
    }
  }

  if (!hasTurns) return null;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={busy}
        className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-[12px] text-muted transition hover:border-accent hover:text-text disabled:opacity-50"
      >
        {busy ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
        Export
      </button>
      {open && (
        <div className="absolute right-0 top-full z-20 mt-1.5 w-52 overflow-hidden rounded-xl border border-line bg-surface shadow-lg">
          <button
            type="button"
            onClick={() => run("json")}
            className="block w-full px-3 py-2 text-left text-[12.5px] text-text transition hover:bg-surface-hover"
          >
            Export as JSON
            <div className="text-[10.5px] text-muted">full data, re-analyzable</div>
          </button>
          <button
            type="button"
            onClick={() => run("md")}
            className="block w-full border-t border-line px-3 py-2 text-left text-[12.5px] text-text transition hover:bg-surface-hover"
          >
            Export as Markdown
            <div className="text-[10.5px] text-muted">readable report, easy to share</div>
          </button>
        </div>
      )}
    </div>
  );
}
