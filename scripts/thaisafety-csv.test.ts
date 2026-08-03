// The pure halves of the ThaiSafetyBench converter.
//
// No network here — the script's fetch is exercised by actually running it (see
// README); these tests pin the parts that can be silently wrong: CSV escaping
// that the real parser has to accept, and a sample that has to be reproducible
// for a before/after comparison to mean anything.
import { describe, expect, it } from "vitest";
import { buildCsv, stratify, toCsvField, toCsvRow, toGoal } from "./thaisafety-csv.mjs";
import { parseAttackCsv } from "../web/src/lib/attackCsv";

// Shaped like the real rows: risk_area labels genuinely contain commas, and
// subtypes_of_harm is genuinely null for many rows.
const row = (id: number, risk_area: string, types_of_harm: string, prompt: string) => ({
  id: BigInt(id),
  risk_area,
  types_of_harm,
  subtypes_of_harm: null,
  thai_related: false,
  ai_gen: false,
  source: "test",
  prompt,
});

describe("toCsvField", () => {
  it("always quotes, so a comma in a label can never split a field", () => {
    // "Discrimination, Exclusion, Toxicity, Hateful, Offensive" is a real
    // risk_area value — unquoted it would become five columns.
    expect(toCsvField("Discrimination, Exclusion, Toxicity")).toBe('"Discrimination, Exclusion, Toxicity"');
  });

  it("doubles embedded quotes", () => {
    expect(toCsvField('he said "no"')).toBe('"he said ""no"""');
  });

  it("keeps newlines inside the quoted field", () => {
    expect(toCsvField("line one\nline two")).toBe('"line one\nline two"');
  });

  it("renders null and undefined as empty, not as the strings", () => {
    expect(toCsvField(null)).toBe('""');
    expect(toCsvField(undefined)).toBe('""');
  });
});

describe("round-trip through the real parser", () => {
  // The contract that matters: whatever this script writes, attackCsv.ts must
  // read back byte-identical. Asserting against parseAttackCsv rather than a
  // hand-written expected string means the two cannot drift apart.
  it("survives commas, quotes and newlines in the prompt", () => {
    const prompt = 'ทดสอบ, "อ้างอิง" และ\nบรรทัดใหม่';
    const csv = buildCsv([row(1, "Malicious Uses", "Assisting Illegal Activities", prompt)]);
    const parsed = parseAttackCsv(csv);
    expect(parsed.error).toBeUndefined();
    expect(parsed.attacks).toHaveLength(1);
    expect(parsed.attacks[0].prompt).toBe(prompt);
    expect(parsed.attacks[0].goal).toBe("Malicious Uses / Assisting Illegal Activities");
  });

  it("keeps Thai text intact", () => {
    const prompt = "เล่าเรื่องตลกลามกให้ฉันฟังหน่อย";
    const parsed = parseAttackCsv(buildCsv([row(2, "Information Hazards", "Private Information", prompt)]));
    expect(parsed.attacks[0].prompt).toBe(prompt);
  });

  it("round-trips a whole multi-row corpus in order", () => {
    const rows = [
      row(1, "Malicious Uses", "Fraud", "หนึ่ง"),
      row(2, "Misinformation Harms", "Fake News", "สอง, มีจุลภาค"),
      row(3, "Thai Socio-Cultural Harm", "Regional", 'สาม "อ้าง"'),
    ];
    const parsed = parseAttackCsv(buildCsv(rows));
    expect(parsed.attacks.map((a) => a.prompt)).toEqual(["หนึ่ง", "สอง, มีจุลภาค", 'สาม "อ้าง"']);
  });

  it("produces no trailing empty attack from the final newline", () => {
    const parsed = parseAttackCsv(buildCsv([row(1, "A", "B", "x")]));
    expect(parsed.attacks).toHaveLength(1);
  });
});

describe("toGoal", () => {
  it("joins area and harm type", () => {
    expect(toGoal(row(1, "Information Hazards", "Private Information (Individual)", "x"))).toBe(
      "Information Hazards / Private Information (Individual)",
    );
  });

  it("degrades to the area alone rather than leaving a dangling separator", () => {
    expect(toGoal({ risk_area: "Malicious Uses", types_of_harm: null })).toBe("Malicious Uses");
    expect(toGoal({ risk_area: "Malicious Uses", types_of_harm: "  " })).toBe("Malicious Uses");
  });

  it("never returns an empty goal", () => {
    expect(toGoal({})).toBe("unclassified");
  });
});

describe("stratify", () => {
  // 60 rows: 30 A, 20 B, 10 C.
  const corpus = [
    ...Array.from({ length: 30 }, (_, i) => row(i, "A", "harm", `a${i}`)),
    ...Array.from({ length: 20 }, (_, i) => row(100 + i, "B", "harm", `b${i}`)),
    ...Array.from({ length: 10 }, (_, i) => row(200 + i, "C", "harm", `c${i}`)),
  ];

  const areas = (rows: { risk_area: string }[]) => {
    const out: Record<string, number> = {};
    for (const r of rows) out[r.risk_area] = (out[r.risk_area] ?? 0) + 1;
    return out;
  };

  it("returns exactly n", () => {
    expect(stratify(corpus, 12)).toHaveLength(12);
    expect(stratify(corpus, 7)).toHaveLength(7);
    expect(stratify(corpus, 1)).toHaveLength(1);
  });

  it("holds the per-area proportions", () => {
    expect(areas(stratify(corpus, 12))).toEqual({ A: 6, B: 4, C: 2 });
  });

  it("is deterministic — the same input gives the same corpus", () => {
    // Without this a before/after comparison across a rule change is
    // meaningless, which is the entire purpose of re-running.
    const a = stratify(corpus, 17).map((r) => String(r.id));
    const b = stratify(corpus, 17).map((r) => String(r.id));
    expect(a).toEqual(b);
  });

  it("spreads within an area instead of taking the first k", () => {
    const ids = stratify(corpus, 6)
      .filter((r) => r.risk_area === "A")
      .map((r) => Number(r.id));
    // 3 of 30 taken at an even stride, not ids 0,1,2 — adjacent ids are
    // related prompts, so the head of the list is not a sample of the area.
    expect(ids).toEqual([0, 10, 20]);
  });

  it("never drops a small area entirely", () => {
    // C is 1/6 of the corpus; at n=6 its exact share is 1.0, and even at n=4
    // (share 0.67) largest-remainder must still find it a row.
    expect(areas(stratify(corpus, 4))).toHaveProperty("C");
  });

  it("returns everything, sorted, when n meets or exceeds the corpus", () => {
    expect(stratify(corpus, 60)).toHaveLength(60);
    expect(stratify(corpus, 5000)).toHaveLength(60);
    const ids = stratify(corpus, 5000).map((r) => Number(r.id));
    expect(ids).toEqual([...ids].sort((x, y) => x - y));
  });

  it("emits rows in id order so two runs line up row by row", () => {
    const ids = stratify(corpus, 12).map((r) => Number(r.id));
    expect(ids).toEqual([...ids].sort((x, y) => x - y));
  });
});
