#!/usr/bin/env node
// Build a /redteam custom corpus from the ThaiSafetyBench benchmark.
//
//   npm run corpus:thai -- --n=100 --out=thai-corpus.csv
//
// Source: https://huggingface.co/datasets/typhoon-ai/ThaiSafetyBench
// 1,889 Thai attack prompts, apache-2.0, with a risk_area / types_of_harm /
// subtypes_of_harm taxonomy.
//
// WHY A SCRIPT AND NOT A CHECKED-IN CSV: the generated file is a few hundred
// harmful Thai prompts. It stays out of git (see .gitignore) — the dataset card
// states the data is "intended for academic purposes only", which does not
// match the apache-2.0 licence it also carries, and that discrepancy is not
// ours to resolve by committing the prompts into a customer-facing repo.
//
// The upstream authors removed Monarchy-related content per Thai regulations
// (1,954 → 1,889 rows). Do not re-add such prompts or author replacements.
//
// The output is read by web/src/lib/attackCsv.ts, so the CSV it writes must be
// exactly what that parser accepts — see toCsvRow.
import { asyncBufferFromUrl, parquetReadObjects } from "hyparquet";

const DATASET =
  "https://huggingface.co/datasets/typhoon-ai/ThaiSafetyBench/resolve/main/data/test-00000-of-00001.parquet";

// Defaults chosen from what a run actually costs, not from what fits: the
// runner sends sequentially at ~4s each, so 100 ≈ 8 min plus the 90s settle.
// 200 is the parser's hard cap (MAX_CUSTOM_ATTACKS) and ≈ 15 min. Every prompt
// is a billable inference call against the daily free Neuron allocation, so the
// full 1,889 is a load test, not a demo, and is not offered.
const DEFAULT_N = 100;
const HARD_CAP = 200;
const SECONDS_PER_ATTACK = 4;
const SETTLE_SECONDS = 90;

/**
 * One CSV field, always quoted.
 *
 * Quoting unconditionally rather than only-when-needed: every field here can
 * contain a comma (the risk_area labels are comma-separated phrases), a quote,
 * or a newline, and "quote only if it looks risky" is exactly the check that
 * gets a case wrong. Embedded quotes are doubled, per RFC 4180 and per what
 * parseAttackCsv reads back.
 */
export function toCsvField(value) {
  return '"' + String(value ?? "").replace(/"/g, '""') + '"';
}

export function toCsvRow(fields) {
  return fields.map(toCsvField).join(",");
}

/**
 * The `goal` column: the row's taxonomy, which is what makes a result
 * actionable — "these 12 reached the model, all of them Information Hazards"
 * points straight at a custom topic to add.
 *
 * Note this is a LABEL, not something the app evaluates. /redteam has no LLM
 * judge and never claims the model complied; it measures only whether the edge
 * stopped the request.
 */
export function toGoal(row) {
  const area = String(row.risk_area ?? "").trim();
  const harm = String(row.types_of_harm ?? "").trim();
  if (area && harm) return `${area} / ${harm}`;
  return area || harm || "unclassified";
}

/**
 * Pick `n` rows, proportionally across risk_area, deterministically.
 *
 * Deterministic is the requirement that shapes this. The whole point of the
 * page is running the same corpus before and after a rule change, so a random
 * sample would make the comparison meaningless. Rows are ordered by `id` and
 * taken at an even stride within each area, which spreads the sample across the
 * area instead of taking the first k (adjacent ids are related prompts).
 *
 * Allocation uses largest-remainder so the parts sum to exactly `n` rather than
 * drifting a few rows off from independent rounding.
 */
export function stratify(rows, n) {
  if (n >= rows.length) return [...rows].sort(byId);
  const groups = new Map();
  for (const row of rows) {
    const key = String(row.risk_area ?? "unclassified");
    const list = groups.get(key);
    if (list) list.push(row);
    else groups.set(key, [row]);
  }
  // Sort groups by name so allocation never depends on Map insertion order.
  const entries = [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const exact = entries.map(([key, list]) => ({
    key,
    list: [...list].sort(byId),
    share: (list.length / rows.length) * n,
  }));
  // Everyone gets their floor, then the largest fractional parts get the
  // leftovers — a group whose share rounds to 0 still gets a row if any are
  // left, so no risk area silently disappears from the corpus.
  let used = 0;
  for (const g of exact) {
    g.take = Math.floor(g.share);
    used += g.take;
  }
  const leftover = [...exact].sort((a, b) => b.share - Math.floor(b.share) - (a.share - Math.floor(a.share)));
  for (let i = 0; used < n; i++, used++) {
    leftover[i % leftover.length].take++;
  }

  const picked = [];
  for (const g of exact) {
    const take = Math.min(g.take, g.list.length);
    if (take <= 0) continue;
    const stride = g.list.length / take;
    for (let i = 0; i < take; i++) picked.push(g.list[Math.floor(i * stride)]);
  }
  return picked.sort(byId);
}

function byId(a, b) {
  const x = BigInt(a.id ?? 0);
  const y = BigInt(b.id ?? 0);
  return x < y ? -1 : x > y ? 1 : 0;
}

export function buildCsv(rows) {
  const lines = ["prompt,goal"];
  for (const row of rows) lines.push(toCsvRow([String(row.prompt ?? "").trim(), toGoal(row)]));
  // Trailing newline; parseCsvRows drops the empty final row it produces.
  return lines.join("\n") + "\n";
}

function parseArgs(argv) {
  const opts = { n: DEFAULT_N, out: "thai-corpus.csv" };
  for (const arg of argv) {
    const n = arg.match(/^--n=(\d+)$/);
    if (n) opts.n = Number(n[1]);
    const out = arg.match(/^--out=(.+)$/);
    if (out) opts.out = out[1];
  }
  return opts;
}

async function main() {
  const { writeFile } = await import("node:fs/promises");
  const opts = parseArgs(process.argv.slice(2));
  if (opts.n > HARD_CAP) {
    console.error(
      `--n=${opts.n} exceeds the ${HARD_CAP}-prompt cap the /redteam CSV parser enforces; it would silently drop the rest. Using ${HARD_CAP}.`,
    );
    opts.n = HARD_CAP;
  }

  console.error(`Reading ${DATASET}`);
  const file = await asyncBufferFromUrl({ url: DATASET });
  const all = await parquetReadObjects({ file });
  console.error(`  ${all.length} prompts in the benchmark`);

  const picked = stratify(all, opts.n);
  await writeFile(opts.out, buildCsv(picked), "utf8");

  const byArea = new Map();
  for (const row of picked) {
    const key = String(row.risk_area ?? "unclassified");
    byArea.set(key, (byArea.get(key) ?? 0) + 1);
  }
  console.error(`\nWrote ${picked.length} prompts to ${opts.out}`);
  for (const [area, count] of [...byArea.entries()].sort((a, b) => b[1] - a[1])) {
    console.error(`  ${String(count).padStart(4)}  ${area}`);
  }
  const mins = Math.ceil((picked.length * SECONDS_PER_ATTACK + SETTLE_SECONDS) / 60);
  console.error(
    `\nA full run takes roughly ${mins} min and spends ${picked.length} model calls of the daily Neuron allocation.`,
  );
  console.error("Load it from /redteam → Corpus → Load CSV.");
}

// Only run when invoked directly, so the helpers above can be imported by tests.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
