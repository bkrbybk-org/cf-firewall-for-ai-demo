// Booth mode's running score since this page load (lib/boothTally.ts decides the words). Every number states its
// window ("Since 14:05 on this screen"); a category with no turns is left out, not shown as zero.
import { useStore } from "../lib/sessionStore";
import { boothTally, scoreboard } from "../lib/boothTally";
import { fmtTime } from "../lib/format";

export function BoothScoreboard() {
  const t = useStore(boothTally);
  if (t.since == null || t.turns === 0) return null;
  const { parts, edgeLog } = scoreboard(t);
  return (
    <div className="mx-auto w-full max-w-3xl shrink-0 px-1 text-center" aria-label="Score since this screen started">
      <p className="text-[13px] text-muted">
        <span className="font-semibold text-text">
          Since {fmtTime(new Date(t.since)).slice(0, 5)} on this screen: {t.turns} prompt{t.turns === 1 ? "" : "s"}
        </span>
        {parts.map((p) => (
          <span key={p.key}>
            {" · "}
            <b className={p.key === "edge" ? "text-[15px] text-cf-green-ink" : "text-text"}>{p.count}</b> {p.label}
          </span>
        ))}
      </p>
      {edgeLog && <p className="text-[11.5px] text-subtle">{edgeLog}</p>}
    </div>
  );
}
