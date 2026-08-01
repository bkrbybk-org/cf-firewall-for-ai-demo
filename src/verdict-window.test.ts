// Tests for the edge-verdict lookup window.
//
// This exists because of a real bug: the window was hardcoded to
// [now − 15min, now + 1min], so a verdict lookup only ever searched a slice
// around *the moment you clicked*. Expanding a prompt-log row from an hour
// ago was therefore guaranteed to find nothing — not because Cloudflare had
// discarded the data, but because we asked the wrong time range. The UI then
// blamed an "ingestion delay", which was actively misleading.
//
// The contract now: given the request's own timestamp, search around THAT
// instant; without one, keep the old live behaviour for a just-sent prompt.
import { describe, expect, it } from "vitest";
import {
  isBeyondRetention,
  VERDICT_ANCHOR_SLACK_MS,
  VERDICT_LIVE_LOOKAHEAD_MS,
  VERDICT_LIVE_LOOKBACK_MS,
  verdictWindow,
} from "./config";

const NOW = Date.parse("2026-07-30T12:00:00.000Z");
const ms = (iso: string) => Date.parse(iso);

describe("verdictWindow", () => {
  it("brackets a known timestamp symmetrically", () => {
    const at = ms("2026-07-30T09:30:00.000Z");
    const { since, until } = verdictWindow(at, NOW);
    expect(ms(since)).toBe(at - VERDICT_ANCHOR_SLACK_MS);
    expect(ms(until)).toBe(at + VERDICT_ANCHOR_SLACK_MS);
  });

  it("covers an hours-old request that the live window would miss", () => {
    const at = ms("2026-07-30T09:30:00.000Z"); // 2.5h before NOW
    const anchored = verdictWindow(at, NOW);
    expect(ms(anchored.since)).toBeLessThanOrEqual(at);
    expect(ms(anchored.until)).toBeGreaterThanOrEqual(at);

    // The regression itself: the unanchored window excludes that timestamp.
    const live = verdictWindow(undefined, NOW);
    expect(ms(live.since)).toBeGreaterThan(at);
  });

  it("falls back to the live window with no timestamp", () => {
    const { since, until } = verdictWindow(undefined, NOW);
    expect(ms(since)).toBe(NOW - VERDICT_LIVE_LOOKBACK_MS);
    expect(ms(until)).toBe(NOW + VERDICT_LIVE_LOOKAHEAD_MS);
  });

  it("ignores a non-finite timestamp rather than producing an invalid range", () => {
    for (const bad of [NaN, Infinity]) {
      const { since, until } = verdictWindow(bad, NOW);
      expect(ms(since)).toBe(NOW - VERDICT_LIVE_LOOKBACK_MS);
      expect(ms(until)).toBe(NOW + VERDICT_LIVE_LOOKAHEAD_MS);
    }
  });

  it("still brackets a just-sent request when anchored", () => {
    const { since, until } = verdictWindow(NOW, NOW);
    expect(ms(since)).toBeLessThan(NOW);
    expect(ms(until)).toBeGreaterThan(NOW);
  });
});

describe("isBeyondRetention", () => {
  const THIRTY_ONE_DAYS = 31 * 86_400;

  it("passes a request inside the window", () => {
    expect(isBeyondRetention(NOW - 30 * 86_400_000, THIRTY_ONE_DAYS, NOW)).toBe(false);
  });

  it("flags a request past the window", () => {
    expect(isBeyondRetention(NOW - 32 * 86_400_000, THIRTY_ONE_DAYS, NOW)).toBe(true);
  });

  it("treats the exact boundary as still available", () => {
    expect(isBeyondRetention(NOW - THIRTY_ONE_DAYS * 1000, THIRTY_ONE_DAYS, NOW)).toBe(false);
  });

  // Without a timestamp there is nothing to compare, so the lookup must still
  // be attempted rather than pre-emptively declared expired.
  it("never flags an unknown timestamp", () => {
    expect(isBeyondRetention(undefined, THIRTY_ONE_DAYS, NOW)).toBe(false);
    expect(isBeyondRetention(NaN, THIRTY_ONE_DAYS, NOW)).toBe(false);
  });
});
