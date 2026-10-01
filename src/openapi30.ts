// OpenAPI 3.0 rendering of src/openapi.ts, for Cloudflare API Shield Schema Validation.
//
// Why a second document: API Shield parses uploads with OAS 3.0 semantics only
// (developers.cloudflare.com/api-shield/security/schema-validation/#limitations).
// The 3.1 spec fails there before any validation happens — a numeric
// `exclusiveMinimum` is a bool in 3.0, so the Go parser rejects the whole file.
// The 3.1 document stays the source of truth; this is a mechanical
// down-conversion of it, never hand-edited. Swagger UI renders THIS one, so the
// docs page shows exactly what an API Shield upload contains.
//
// The conversion is SCHEMA-AWARE on purpose: it only rewrites nodes that are
// schemas (reached through `schema`, `properties`, `items`, `oneOf`/`anyOf`/
// `allOf`, `additionalProperties`, `not`, `components.schemas`). A blind walk of
// the whole tree would also "convert" example payloads and any property that
// happens to be named `type` or `const` — and a schema that says something other
// than what the 3.1 one says would make Schema Validation flag (or pass) traffic
// nobody intended.
//
// The 3.1 → 3.0 rewrites, each preserving the validation meaning:
//   type: [T, "null"]        → type: T, nullable: true
//   type: "null"             → nullable: true, enum: [null]  (only null is valid)
//   const: v                 → enum: [v]
//   exclusiveMinimum: n      → minimum: n, exclusiveMinimum: true   (same for Maximum)
//   examples: [a, …]         → example: a
//   servers: [{ url: "/" }]  → the absolute origin — Schema Validation does not
//                              support relative server URLs.
import { openapi } from "./openapi";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export function toSchema30(schema: unknown): unknown {
  if (!isObj(schema)) return schema;
  const out: Json = {};
  for (const [k, v] of Object.entries(schema)) {
    switch (k) {
      case "properties":
        out[k] = isObj(v) ? Object.fromEntries(Object.entries(v).map(([name, s]) => [name, toSchema30(s)])) : v;
        break;
      case "items":
      case "not":
        out[k] = toSchema30(v);
        break;
      case "additionalProperties":
        out[k] = typeof v === "boolean" ? v : toSchema30(v);
        break;
      case "oneOf":
      case "anyOf":
      case "allOf":
        out[k] = Array.isArray(v) ? v.map(toSchema30) : v;
        break;
      default:
        out[k] = v;
    }
  }

  if (Array.isArray(out.type)) {
    const types = (out.type as string[]).filter((t) => t !== "null");
    if (types.length !== 1) throw new Error(`Cannot express type ${JSON.stringify(out.type)} in OpenAPI 3.0`);
    if (types.length < (out.type as string[]).length) out.nullable = true;
    out.type = types[0];
  } else if (out.type === "null") {
    delete out.type;
    out.nullable = true;
    out.enum = [null];
  }
  if ("const" in out) {
    out.enum = [out.const];
    delete out.const;
  }
  for (const [ex, bound] of [
    ["exclusiveMinimum", "minimum"],
    ["exclusiveMaximum", "maximum"],
  ] as const) {
    if (typeof out[ex] === "number") {
      out[bound] = out[ex];
      out[ex] = true;
    }
  }
  if (Array.isArray(out.examples)) {
    if (out.examples.length && !("example" in out)) out.example = out.examples[0];
    delete out.examples;
  }
  return out;
}

const mapValues = (o: unknown, f: (v: Json) => Json): unknown =>
  isObj(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, isObj(v) ? f(v) : v])) : o;

// Parameter, header and media-type objects each hold one `schema`.
const withSchema = (o: Json): Json => ("schema" in o ? { ...o, schema: toSchema30(o.schema) } : o);
const content = (o: Json): Json => ("content" in o ? { ...o, content: mapValues(o.content, withSchema) } : o);
const response = (r: Json): Json => {
  const c = content(r);
  return "headers" in c ? { ...c, headers: mapValues(c.headers, withSchema) } : c;
};
const params = (p: unknown): unknown => (Array.isArray(p) ? p.map((x) => (isObj(x) ? withSchema(x) : x)) : p);

const HTTP_METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

function operation(op: Json): Json {
  const out: Json = { ...op };
  if ("parameters" in op) out.parameters = params(op.parameters);
  if (isObj(op.requestBody)) out.requestBody = content(op.requestBody);
  if ("responses" in op) out.responses = mapValues(op.responses, response);
  return out;
}

/** The 3.1 document as OpenAPI 3.0.3, with `origin` as its one absolute server. */
export function toOpenApi30(doc: Json, origin: string): Json {
  const paths = mapValues(doc.paths, (item) =>
    Object.fromEntries(
      Object.entries(item).map(([k, v]) => [
        k,
        k === "parameters" ? params(v) : HTTP_METHODS.has(k) && isObj(v) ? operation(v) : v,
      ]),
    ),
  );
  const components = isObj(doc.components) ? { ...doc.components } : undefined;
  if (components) {
    if ("schemas" in components) components.schemas = mapValues(components.schemas, (s) => toSchema30(s) as Json);
    if ("parameters" in components) components.parameters = mapValues(components.parameters, withSchema);
    if ("responses" in components) components.responses = mapValues(components.responses, response);
  }
  const info = isObj(doc.info) ? doc.info : {};
  return {
    ...doc,
    openapi: "3.0.3",
    info: {
      ...info,
      description: `${info.description ?? ""}\n\n**This is the OpenAPI 3.0 rendering**, generated from the 3.1 source document ([/api/openapi.json](/api/openapi.json)) for Cloudflare API Shield Schema Validation, which only accepts 3.0 semantics. **Upload this file: [/api/openapi-3.0.json](/api/openapi-3.0.json).**`,
    },
    servers: [{ url: origin }],
    paths,
    ...(components ? { components } : {}),
  };
}

export const openapi30For = (origin: string): Json => toOpenApi30(openapi as unknown as Json, origin);
