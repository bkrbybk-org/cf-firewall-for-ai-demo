// Guards for src/openapi.ts.
//
// A hand-written spec rots silently: nothing fails when an endpoint is added, a
// request field is renamed or an enum grows, and the docs page keeps confidently
// describing the old API. These tests turn each of those into a red build. They
// do NOT prove the response schemas match what the handlers return — that needs
// live payloads (see the header of openapi.ts) — only that the document is valid
// and has not drifted from the code it duplicates.
import { validate } from "@readme/openapi-parser";
import { describe, expect, it } from "vitest";
import { MAX_PROMPT_LEN, MAX_SYSTEM_PROMPT_LEN } from "./config";
import indexSrc from "./index.ts?raw";
import { openapi } from "./openapi";
import { PROMPT_LOG_SORTS } from "./promptlog";
import { RT_RESULT_STATES } from "./redteamruns";
import typesSrc from "./types.ts?raw";

// The document is plain data; a JSON round trip also hands the parser a mutable copy.
const doc = () => JSON.parse(JSON.stringify(openapi));

describe("OpenAPI document", () => {
  it("is a valid OpenAPI 3.1 document (every $ref resolves, every schema is well-formed)", async () => {
    const result = await validate(doc());
    expect(result.valid, JSON.stringify((result as { errors?: unknown }).errors ?? [], null, 2)).toBe(true);
  });

  it("gives every operation a unique operationId, a summary and a declared tag", () => {
    const declared = new Set<string>(openapi.tags.map((t) => t.name));
    const ids: string[] = [];
    for (const [path, item] of Object.entries(openapi.paths)) {
      for (const [method, op] of Object.entries(item as Record<string, Record<string, unknown>>)) {
        const where = `${method.toUpperCase()} ${path}`;
        expect(op.operationId, `${where} operationId`).toBeTruthy();
        expect(op.summary, `${where} summary`).toBeTruthy();
        for (const t of op.tags as string[]) expect(declared.has(t), `${where} uses undeclared tag ${t}`).toBe(true);
        ids.push(op.operationId as string);
      }
    }
    expect(new Set(ids).size, "operationIds must be unique").toBe(ids.length);
  });
});

describe("drift from the code it describes", () => {
  it("documents exactly the routes the Worker dispatches", () => {
    const routes = [...indexSrc.matchAll(/case "(\/api\/[^"]+)":/g)].map((m) => m[1]).sort();
    expect(routes.length, "found no routes — the regex no longer matches index.ts").toBeGreaterThan(5);
    expect(Object.keys(openapi.paths).sort()).toEqual(routes);
  });

  it("documents every field ChatRequestBody accepts, and nothing it does not", () => {
    const block = typesSrc.match(/export interface ChatRequestBody \{([\s\S]*?)\n\}/)?.[1] ?? "";
    // Field lines only: two-space indent, then `name?: unknown;` — comments are skipped.
    const fields = [...block.matchAll(/^ {2}([a-zA-Z]+)\?: unknown;/gm)].map((m) => m[1]).sort();
    expect(fields.length, "found no fields — the regex no longer matches types.ts").toBeGreaterThan(10);
    expect(Object.keys(openapi.components.schemas.ChatRequest.properties as Record<string, unknown>).sort()).toEqual(fields);
  });

  it("states the server's own prompt and system-prompt caps", () => {
    const p = openapi.components.schemas.ChatRequest.properties as Record<string, { maxLength?: number }>;
    expect(p.prompt.maxLength).toBe(MAX_PROMPT_LEN);
    expect(p.systemPrompt.maxLength).toBe(MAX_SYSTEM_PROMPT_LEN);
  });

  it("uses the prompt-log sort whitelist as its `sort` enum", () => {
    const op = openapi.paths["/api/prompt-log"].get;
    const sort = op.parameters.find((p) => p.name === "sort") as { schema: { enum: string[] } };
    expect([...sort.schema.enum].sort()).toEqual(Object.keys(PROMPT_LOG_SORTS).sort());
  });

  it("uses the server's result-state whitelist as its RtResultState enum", () => {
    expect([...openapi.components.schemas.RtResultState.enum].sort()).toEqual([...RT_RESULT_STATES].sort());
  });
});
