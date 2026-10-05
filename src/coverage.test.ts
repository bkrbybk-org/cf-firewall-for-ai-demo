// Tests for markReadCoverage (PROGRESS bug #23): a capped read must never let
// an unread bucket pass as a zero.
import { describe, expect, it } from "vitest";
import { markReadCoverage } from "./coverage";

const H = 3_600_000;
// Six hourly buckets, 00:00 … 05:00.
const hours = () =>
  Array.from({ length: 6 }, (_, i) => ({ t: new Date(Date.UTC(2026, 9, 5, i)).toISOString(), block: 0, log: 0, other: 0 }));
const at = (h: number, m = 0) => new Date(Date.UTC(2026, 9, 5, h, m)).toISOString();
const reads = (s: { t: string; read?: string }[]) => s.map((r) => r.read ?? "full");

describe("markReadCoverage", () => {
  it("tags nothing when the read was not capped — zeros there are real zeros", () => {
    const s = markReadCoverage(hours(), false, at(3, 20), H);
    expect(reads(s)).toEqual(["full", "full", "full", "full", "full", "full"]);
  });

  it("marks buckets before the oldest row read as not read, its own bucket as partial", () => {
    // Oldest row read at 03:20 → 00–02 never read; 03:00 partly; 04–05 fully.
    const s = markReadCoverage(hours(), true, at(3, 20), H);
    expect(reads(s)).toEqual(["none", "none", "none", "partial", "full", "full"]);
  });

  it("an oldest row exactly on a bucket boundary makes that bucket partial and the previous one unread", () => {
    const s = markReadCoverage(hours(), true, at(3, 0), H);
    expect(reads(s)).toEqual(["none", "none", "none", "partial", "full", "full"]);
  });

  it("keeps the counts untouched — coverage is a label, not a rewrite of what was read", () => {
    const rows = hours().map((r, i) => ({ ...r, block: i }));
    const s = markReadCoverage(rows, true, at(2, 30), H);
    expect(s.map((r) => r.block)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("capped with no usable timestamp claims nothing rather than full coverage", () => {
    expect(reads(markReadCoverage(hours(), true, null, H))).toEqual(["none", "none", "none", "none", "none", "none"]);
    expect(reads(markReadCoverage(hours(), true, "not a date", H))).toEqual(["none", "none", "none", "none", "none", "none"]);
  });

  // The shape of the prod measurement that filed the bug: 24 h window, the 500
  // newest rows reaching back ~6.5 h. At 12:10 with the oldest row at 05:40:
  // 12:00 (yesterday) … 04:00 are unread (17), 05:00 is partial, 06:00 … 12:00
  // are read (7). (The bug's "18 of 25" was the same shape at another clock time.)
  it("a 24 h window whose rows reach back 6.5 h: 17 not read, 1 partial, 7 read", () => {
    const now = Date.UTC(2026, 9, 5, 12, 10);
    const start = Math.floor((now - 24 * H) / H) * H;
    const series = Array.from({ length: 25 }, (_, i) => ({ t: new Date(start + i * H).toISOString() }));
    const s = markReadCoverage(series, true, new Date(now - 6.5 * H).toISOString(), H);
    const r = reads(s);
    expect(r.filter((x) => x === "none")).toHaveLength(17);
    expect(r.filter((x) => x === "partial")).toHaveLength(1);
    expect(r.filter((x) => x === "full")).toHaveLength(7);
    expect(r.slice(0, 17).every((x) => x === "none")).toBe(true); // contiguous, oldest first
  });
});
