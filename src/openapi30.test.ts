// Guards for the OpenAPI 3.0 rendering uploaded to API Shield Schema Validation.
//
// Two ways this file can be wrong, and both are invisible until a customer's
// upload fails or their traffic is mis-flagged: a 3.1-only keyword survives (the
// upload is rejected, as it was with a numeric `exclusiveMinimum`), or a rewrite
// changes what a schema accepts. The second matters more — Schema Validation
// enforces exactly what this document says.
import { validate } from "@readme/openapi-parser";
import { describe, expect, it } from "vitest";
import { openapi } from "./openapi";
import { openapi30For, toSchema30 } from "./openapi30";

const ORIGIN = "https://cf-ai-waf-demo.nttlab.org";
const doc = () => JSON.parse(JSON.stringify(openapi30For(ORIGIN)));

// Every schema node in the document, found the same schema-aware way the converter walks.
function schemas(d: Record<string, any>): unknown[] {
  const found: unknown[] = [];
  const visit = (s: any) => {
    if (!s || typeof s !== "object") return;
    found.push(s);
    for (const p of Object.values(s.properties ?? {})) visit(p);
    for (const k of ["items", "not"]) visit(s[k]);
    if (typeof s.additionalProperties === "object") visit(s.additionalProperties);
    for (const k of ["oneOf", "anyOf", "allOf"]) for (const x of s[k] ?? []) visit(x);
  };
  const media = (c: any) => Object.values(c ?? {}).forEach((m: any) => visit(m.schema));
  for (const s of Object.values(d.components.schemas)) visit(s);
  for (const p of Object.values(d.components.parameters)) visit((p as any).schema);
  for (const item of Object.values(d.paths) as any[]) {
    for (const op of Object.values(item) as any[]) {
      for (const p of op.parameters ?? []) visit(p.schema);
      media(op.requestBody?.content);
      for (const r of Object.values(op.responses ?? {}) as any[]) {
        media(r.content);
        for (const h of Object.values(r.headers ?? {}) as any[]) visit(h.schema);
      }
    }
  }
  return found;
}

describe("OpenAPI 3.0 rendering", () => {
  it("is a valid OpenAPI 3.0 document", async () => {
    const d = doc();
    expect(d.openapi).toBe("3.0.3");
    const result = await validate(d);
    expect(result.valid, JSON.stringify((result as { errors?: unknown }).errors ?? [], null, 2)).toBe(true);
  });

  it("carries no 3.1-only schema keyword anywhere", () => {
    const all = schemas(doc()) as Record<string, unknown>[];
    expect(all.length).toBeGreaterThan(100);
    for (const s of all) {
      expect(Array.isArray(s.type), JSON.stringify(s)).toBe(false);
      expect(s.type, JSON.stringify(s)).not.toBe("null");
      expect(s).not.toHaveProperty("const");
      expect(s).not.toHaveProperty("examples");
      for (const k of ["exclusiveMinimum", "exclusiveMaximum"]) if (k in s) expect(typeof s[k]).toBe("boolean");
    }
  });

  it("uses one absolute server URL — Schema Validation rejects relative ones", () => {
    expect(doc().servers).toEqual([{ url: ORIGIN }]);
  });

  it("keeps every path, operation and request body of the 3.1 document", () => {
    const d = doc();
    expect(Object.keys(d.paths)).toEqual(Object.keys(openapi.paths));
    const chat = d.paths["/api/chat"].post.requestBody.content["application/json"].schema;
    expect(chat).toEqual({ $ref: "#/components/schemas/ChatRequest" });
  });

  it("preserves what the chat request accepts — the schema Schema Validation enforces", () => {
    const req = doc().components.schemas.ChatRequest;
    const src = openapi.components.schemas.ChatRequest as Record<string, any>;
    // Exclusive bounds keep their meaning: > 0, not ≥ 0.
    expect(req.properties.cacheTtl).toMatchObject({ type: "integer", minimum: 0, exclusiveMinimum: true });
    expect(req.properties.requestTimeoutMs).toMatchObject({ type: "integer", minimum: 0, exclusiveMinimum: true });
    // Everything else on the request is untouched.
    for (const [name, s] of Object.entries(src.properties)) {
      if (name === "cacheTtl" || name === "requestTimeoutMs") continue;
      expect(req.properties[name], name).toEqual(s);
    }
    expect(req.required).toEqual(["prompt"]);
  });

  it("does not touch the source document", () => {
    expect(openapi.openapi).toBe("3.1.0");
    expect(openapi.servers).toEqual([{ url: "/" }]);
    expect((openapi.components.schemas.ChatRequest as any).properties.cacheTtl.exclusiveMinimum).toBe(0);
  });
});

describe("toSchema30", () => {
  it("rewrites each 3.1 form to its 3.0 equivalent", () => {
    expect(toSchema30({ type: ["string", "null"], description: "d" })).toEqual({ type: "string", nullable: true, description: "d" });
    expect(toSchema30({ type: "null" })).toEqual({ nullable: true, enum: [null] });
    expect(toSchema30({ const: true })).toEqual({ enum: [true] });
    expect(toSchema30({ type: "integer", exclusiveMaximum: 10 })).toEqual({ type: "integer", maximum: 10, exclusiveMaximum: true });
    expect(toSchema30({ type: "string", examples: ["a", "b"] })).toEqual({ type: "string", example: "a" });
  });

  it("recurses into nested schemas but never into property NAMES", () => {
    // A property called `const` or `type` is a name, not a keyword.
    const s = toSchema30({
      type: "object",
      properties: { const: { type: ["integer", "null"] }, type: { const: "x" } },
      items: { const: 1 },
      oneOf: [{ type: "null" }],
      additionalProperties: { const: 2 },
    }) as Record<string, any>;
    expect(Object.keys(s.properties)).toEqual(["const", "type"]);
    expect(s.properties.const).toEqual({ type: "integer", nullable: true });
    expect(s.properties.type).toEqual({ enum: ["x"] });
    expect(s.items).toEqual({ enum: [1] });
    expect(s.oneOf).toEqual([{ nullable: true, enum: [null] }]);
    expect(s.additionalProperties).toEqual({ enum: [2] });
  });

  it("refuses a union 3.0 cannot express rather than silently narrowing it", () => {
    expect(() => toSchema30({ type: ["string", "integer"] })).toThrow(/Cannot express/);
  });
});
