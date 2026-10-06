// Splits pretty-printed JSON into coloured tokens for the raw-responses panel.
//
// The input is always JSON.stringify(body, null, 2) of a vendor's response — untrusted
// content. That is why this returns TOKENS that React renders as text, never markup:
// a value like "<img onerror=…>" stays text, with no innerHTML anywhere. And because
// the input is our own stringify output, its grammar is narrow: a string never contains
// an unescaped quote, so scanning left to right, a match that starts at `"` always
// consumes the whole string, and numbers/booleans/null are only ever matched outside one.
export type JsonTokenKind = "key" | "string" | "number" | "boolean" | "null" | "punct";
export interface JsonToken {
  kind: JsonTokenKind;
  text: string;
}

const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

export function jsonTokens(pretty: string): JsonToken[] {
  const out: JsonToken[] = [];
  let last = 0;
  for (const m of pretty.matchAll(TOKEN)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ kind: "punct", text: pretty.slice(last, at) });
    if (m[1] !== undefined) {
      // A string followed by a colon is an object key; the colon stays punctuation.
      out.push({ kind: m[2] !== undefined ? "key" : "string", text: m[1] });
      if (m[2] !== undefined) out.push({ kind: "punct", text: m[2] });
    } else {
      const t = m[0];
      out.push({ kind: t === "null" ? "null" : t === "true" || t === "false" ? "boolean" : "number", text: t });
    }
    last = at + m[0].length;
  }
  if (last < pretty.length) out.push({ kind: "punct", text: pretty.slice(last) });
  return out;
}
