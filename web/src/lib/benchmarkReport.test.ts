import { describe, expect, it } from "vitest";
import { buildBenchmarkReport, mdText, reportFilename, reportToMarkdown } from "./benchmarkReport";
import type { RtSavedRun, RtStoredResult, RtVendorOutcome } from "./redteam";

const V = (airs?: [RtVendorOutcome["verdict"], number?], aidr?: [RtVendorOutcome["verdict"], number?]) => {
  const v: RtVendorOutcome[] = [];
  if (airs) v.push({ provider: "prisma-airs", verdict: airs[0], ...(airs[1] != null ? { latencyMs: airs[1] } : {}) });
  if (aidr) v.push({ provider: "crowdstrike-aidr", verdict: aidr[0], ...(aidr[1] != null ? { latencyMs: aidr[1] } : {}) });
  return v;
};
const R = (attackId: string, state: RtStoredResult["state"], vendors: RtVendorOutcome[] | null, over: Partial<RtStoredResult> = {}): RtStoredResult => ({
  attackKey: "k-" + attackId,
  attackId,
  category: "Jailbreak",
  severity: null,
  state,
  ray: null,
  ts: null,
  promptPreview: "preview " + attackId,
  vendors,
  pipelineMode: vendors ? "parallel" : null,
  pipelineLatencyMs: null,
  expected: null,
  topic: "Jailbreak",
  lang: "Latin script",
  ...over,
});
const run = (results: RtStoredResult[], over: Partial<RtSavedRun> = {}): RtSavedRun => ({
  id: 7,
  ts: Date.UTC(2026, 9, 7, 3, 4),
  label: "before",
  route: "gateway",
  gatewayId: "demo-gw",
  guarded: 0,
  corpusName: "AI Red Team Sample",
  corpusSize: results.length,
  corpusFingerprint: "abc123",
  delayMs: 0,
  total: 0,
  scored: 0,
  reached: 0,
  stopped: 0,
  denied: 0,
  guardrails: 0,
  external: 0,
  skipped: 0,
  pending: 0,
  error: 0,
  reachedPct: 0,
  results,
  ...over,
});
const LABELS = { "prisma-airs": "Prisma AIRS", "crowdstrike-aidr": "CrowdStrike AIDR" };

// Five attacks (one a Base64 variant) and two harmless rows. Hand counts in each test.
const FIXTURE = run([
  R("a1", "allow", V(["block", 100], ["allow", 200])),
  R("a2", "log", V(["block", 120], ["block", 300])),
  R("a3", "block", null), // the edge refused it: no guardrail saw it
  R("a4", "allow", V(["allow", 90], ["error"])),
  R("a1~base64", "allow", V(["allow"], ["block"])),
  R("h1", "allow", V(["block"], ["allow"]), { expected: "allow", topic: "Weather" }),
  R("h2", "allow", V(["allow"], ["allow"]), { expected: "allow", topic: "Weather" }),
]);

describe("buildBenchmarkReport", () => {
  const r = buildBenchmarkReport(FIXTURE, LABELS, Date.UTC(2026, 9, 7, 5, 0));
  const score = (id: string) => r.attackScores.find((c) => c.control === id)!;

  it("matches a hand count: each control scored only on what it scanned", () => {
    expect(r.run).toMatchObject({ attacks: 5, harmless: 2, savedAt: "2026-10-07T03:04:00.000Z", verdictsRecorded: true });
    // Edge: a3 blocked; a1 a2 a4 a1~base64 reached → 1 of 5 caught; 4 of 5 reached.
    expect(score("edge")).toMatchObject({ caught: 1, scanned: 5, catchPct: 20 });
    expect(r.edge).toMatchObject({ scored: 5, reached: 4, stopped: 1, reachedPct: 80 });
    // AIRS: a1 a2 caught, a4 a1~base64 missed, a3 never seen → 2 of 4.
    expect(score("prisma-airs")).toMatchObject({ caught: 2, scanned: 4, catchPct: 50, notSeen: 1, errors: 0 });
    // AIDR: a2 a1~base64 caught, a1 missed, a4 an error (not scanned) → 2 of 3.
    expect(score("crowdstrike-aidr")).toMatchObject({ caught: 2, scanned: 3, catchPct: 67, errors: 1, notSeen: 1 });
    // a4: scanned by the edge and AIRS, caught by neither (AIDR's error is not a scan).
    expect(r.missedByAll).toBe(1);
    // Wilson on 2/4 ≈ 15.0–85.0%.
    expect(score("prisma-airs").ci!.lo).toBeCloseTo(15.0, 0);
    expect(score("prisma-airs").ci!.hi).toBeCloseTo(85.0, 0);
  });

  it("false blocks, balanced accuracy, head to head and latency agree with a hand count", () => {
    const fb = (id: string) => r.harmless!.scores.find((f) => f.control === id)!;
    expect(fb("prisma-airs")).toMatchObject({ blocked: 1, checked: 2, falseBlockPct: 50 });
    expect(fb("crowdstrike-aidr")).toMatchObject({ blocked: 0, checked: 2, falseBlockPct: 0 });
    expect(r.harmless!.blockedByAny).toBe(1);
    // (2/4 + 1/2)/2 = 50; (2/3 + 2/2)/2 = 83.3; edge (1/5 + 2/2)/2 = 60.
    expect([score("prisma-airs").balancedPct, score("crowdstrike-aidr").balancedPct, score("edge").balancedPct]).toEqual([50, 83, 60]);
    // Both scanned a1, a2, a1~base64 (a4: AIDR errored). a1 only AIRS, a2 both, variant only AIDR.
    expect(r.headToHead).toEqual([
      expect.objectContaining({ n: 3, both: 1, onlyA: 1, onlyB: 1, neither: 0 }),
    ]);
    // AIRS timings 100, 120, 90 → nearest-rank p50 = 100; AIDR's error excluded, counted.
    const lat = (id: string) => r.latency.perControl.find((p) => p.control === id)!.stat;
    expect(lat("prisma-airs")).toMatchObject({ n: 3, p50: 100, max: 120 });
    expect(lat("crowdstrike-aidr")).toMatchObject({ n: 2, errorsExcluded: 1 });
  });

  it("adds a technique grid only when the run has variants, and harmless grids only with harmless rows", () => {
    expect(r.grids.map((g) => `${g.metric}/${g.groupBy}`)).toEqual([
      "catch/topic",
      "catch/language",
      "catch/technique",
      "falseBlock/topic",
      "falseBlock/language",
    ]);
    const plain = buildBenchmarkReport(run(FIXTURE.results.filter((x) => !x.attackId.includes("~") && !x.expected)), LABELS);
    expect(plain.grids.map((g) => `${g.metric}/${g.groupBy}`)).toEqual(["catch/topic", "catch/language"]);
    expect(plain.harmless).toBeNull();
  });

  it("never marks a winner the page would not: 2/4 vs 2/3 overlaps", () => {
    for (const g of r.grids) for (const row of g.rows) for (const c of row.cells) expect(c.mark).toBeNull();
  });

  it("carries the stored previews and verdict words — nothing a vendor wrote", () => {
    const p = r.prompts.find((x) => x.id === "a1~base64")!;
    expect(p).toMatchObject({ kind: "attack", technique: "Base64", promptPreview: "preview a1~base64", edgeState: "allow" });
    expect(p.verdicts).toEqual({ edge: "missed", "prisma-airs": "missed", "crowdstrike-aidr": "caught" });
    expect(JSON.stringify(r)).not.toMatch(/"raw"/);
  });

  it("a run saved before verdicts were stored says so, and an unscanned control is a dash, not 0%", () => {
    const old = buildBenchmarkReport(run([R("a1", "allow", null, { lang: null, topic: null })]), LABELS);
    expect(old.run.verdictsRecorded).toBe(false);
    expect(old.notes[0]).toMatch(/edge results only/);
    const md = reportToMarkdown(buildBenchmarkReport(run([R("a3", "pending", null)]), LABELS));
    expect(md).toMatch(/No attack has an edge verdict/);
    expect(md).not.toMatch(/\b0% \(0\/0/);
  });

  it("reads a harmless row's block as a false block, and missing timings as not recorded", () => {
    const md = reportToMarkdown(r);
    const h1 = md.split("\n").find((l) => l.startsWith("| h1 "))!;
    expect(h1).toContain("| blocked (false block) | passed |");
    expect(md.split("\n").find((l) => l.startsWith("| a1 "))).toContain("| caught | missed |");
    expect(md).toContain("1 was stopped by the edge");
    // a1~base64, h1, h2 carry no AIRS timing; a4's AIDR error is excluded. Untimed only:
    const untimed = reportToMarkdown(buildBenchmarkReport(run([R("a1", "allow", V(["block"], ["allow"]))]), LABELS));
    expect(untimed).toContain("not recorded (1 untimed)");
    expect(untimed).not.toMatch(/Prisma AIRS[^\n]*\| — \|$/m);
  });

  it("names the file after the run and the time it was saved", () => {
    expect(reportFilename(r, "md")).toBe("redteam-benchmark-run-7-20261007-0304.md");
  });
});

describe("Markdown safety", () => {
  it("mdText neutralises table, link, HTML, autolink, math and invisible characters", () => {
    const hostile = "a|b <img src=x onerror=alert(1)> [x](javascript:alert(1)) https://evil.test www.evil.test $x$ &amp;\nnext\u200bz\u202e";
    const out = mdText(hostile);
    expect(out).not.toMatch(/(^|[^\\])[|<>[\]()$&]/);
    expect(out).toContain("https\\://");
    expect(out).toContain("www\\.evil");
    expect(out).toContain(" ↵ next⟨U+200B⟩z⟨U+202E⟩");
    expect(out).not.toMatch(/[\n\u200b\u202e]/);
  });

  it("a hostile prompt or label cannot add or split a table row", () => {
    const evil = R("x|1", "allow", V(["allow"], ["allow"]), {
      promptPreview: "ignore | all\n| fake | row |\n\n# heading",
      topic: "T|opic",
    });
    const md = reportToMarkdown(buildBenchmarkReport(run([evil], { label: "lab|el\n# x" }), LABELS));
    const section = md.split("## Prompts")[1];
    const rows = section.split("\n").filter((l) => l.startsWith("|"));
    expect(rows).toHaveLength(3); // header, separator, one prompt
    // Every unescaped pipe is a column border: 6 fixed + 3 controls + preview = 10 columns → 11 borders.
    expect(rows[2].match(/(?<!\\)\|/g)).toHaveLength(11);
    expect(md.split("\n").filter((l) => l.startsWith("# "))).toHaveLength(1);
  });
});
