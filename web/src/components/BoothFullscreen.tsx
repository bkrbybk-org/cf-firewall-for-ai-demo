// Booth mode's fullscreen switch: the browser's own Fullscreen API, so the booth screen loses the address bar and tabs.
// Hidden where the browser offers no fullscreen (an iframe without permission, some kiosks). Esc leaves it — the
// browser's rule, not ours — and the button follows whatever state the browser reports.
import { useEffect, useState } from "react";
import { Maximize2, Minimize2 } from "lucide-react";

export function BoothFullscreen() {
  const [full, setFull] = useState(() => typeof document !== "undefined" && !!document.fullscreenElement);
  useEffect(() => {
    const on = () => setFull(!!document.fullscreenElement);
    document.addEventListener("fullscreenchange", on);
    return () => document.removeEventListener("fullscreenchange", on);
  }, []);
  if (typeof document === "undefined" || !document.fullscreenEnabled) return null;
  return (
    <button
      type="button"
      data-attract-control
      aria-pressed={full}
      onClick={() => (full ? document.exitFullscreen() : document.documentElement.requestFullscreen()).catch(() => {})}
      title={full ? "Leave fullscreen (Esc)" : "Fullscreen for the booth screen"}
      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] font-semibold text-muted transition hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      {full ? <Minimize2 size={14} /> : <Maximize2 size={14} />} {full ? "Exit fullscreen" : "Fullscreen"}
    </button>
  );
}
