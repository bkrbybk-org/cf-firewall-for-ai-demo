// Booth attract mode (2026-11-17): a loop of real traffic must stop when told, stop by itself, and judge each
// prompt alone.
import { describe, expect, it } from "vitest";
import type { TurnResult } from "../hooks/useChat";
import { ATTRACT_DWELL_MS, ATTRACT_GAP_MS, ATTRACT_MAX_ERRORS, ATTRACT_MAX_MS, runAttract, type AttractDeps } from "./attractMode";

// A fake clock: sleep advances time instantly, so an hour of looping runs in milliseconds.
function harness(opts: { results?: (n: number) => TurnResult; stopAfterSends?: number } = {}) {
  let t = 0;
  let stop = false;
  const log: string[] = [];
  let sends = 0;
  const deps: AttractDeps = {
    prompts: ["a", "b", "c"],
    send: async (p) => {
      log.push(`send:${p}`);
      sends++;
      t += 1_000;
      if (opts.stopAfterSends && sends >= opts.stopAfterSends) stop = true;
      return opts.results?.(sends) ?? { kind: "reply" };
    },
    clear: () => log.push("clear"),
    sleep: async (ms) => {
      t += ms;
    },
    now: () => t,
    stopped: () => stop,
  };
  return { deps, log, sends: () => sends, time: () => t };
}

describe("runAttract", () => {
  it("clears before every prompt (each judged alone) and cycles the script in order", async () => {
    const h = harness({ stopAfterSends: 4 });
    expect(await runAttract(h.deps)).toBe("stopped");
    expect(h.log).toEqual(["clear", "send:a", "clear", "send:b", "clear", "send:c", "clear", "send:a"]);
  });

  it("stops at once when stopped mid-request: no dwell, no further prompt", async () => {
    const h = harness({ stopAfterSends: 1 });
    expect(await runAttract(h.deps)).toBe("stopped");
    expect(h.sends()).toBe(1);
    expect(h.time()).toBe(ATTRACT_GAP_MS + 1_000); // returned right after the request, without the dwell
  });

  it("stops by itself after ATTRACT_MAX_MS — a forgotten screen does not loop forever", async () => {
    const h = harness();
    expect(await runAttract(h.deps)).toBe("timeLimit");
    const perTurn = ATTRACT_GAP_MS + 1_000 + ATTRACT_DWELL_MS;
    expect(h.sends()).toBe(Math.ceil(ATTRACT_MAX_MS / perTurn));
  });

  it(`stops after ${ATTRACT_MAX_ERRORS} failures in a row, not after scattered ones`, async () => {
    const scattered = harness({ results: (n) => ({ kind: n % 2 ? "error" : "reply" }), stopAfterSends: 12 });
    expect(await runAttract(scattered.deps)).toBe("stopped");
    const down = harness({ results: () => ({ kind: "error" }) });
    expect(await runAttract(down.deps)).toBe("errors");
    expect(down.sends()).toBe(ATTRACT_MAX_ERRORS);
  });

  it("does nothing with an empty script", async () => {
    const h = harness();
    h.deps.prompts = [];
    expect(await runAttract(h.deps)).toBe("stopped");
    expect(h.log).toEqual([]);
  });
});
