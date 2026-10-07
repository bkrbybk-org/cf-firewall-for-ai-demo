// The prompt-variant techniques' names (open item G), on their own so the benchmark
// (vendorBenchmark.ts) and the variant builder (variants.ts) can both use them without
// importing each other.
export type Technique = "base64" | "leetspeak" | "zero-width";
export const TECHNIQUES: Technique[] = ["base64", "leetspeak", "zero-width"];

export const TECHNIQUE_LABEL: Record<Technique, string> = {
  base64: "Base64",
  leetspeak: "Leetspeak",
  "zero-width": "Zero-width chars",
};
export const ORIGINAL_LABEL = "Original";

// The technique a variant id carries ("rt-01~base64" → "base64"); undefined for an
// original. This is how a SAVED run recovers it — attackId is stored, so no column.
export function techniqueOfId(id: string): Technique | undefined {
  const m = /~([a-z0-9-]+)$/.exec(id);
  return m && (TECHNIQUES as string[]).includes(m[1]) ? (m[1] as Technique) : undefined;
}
