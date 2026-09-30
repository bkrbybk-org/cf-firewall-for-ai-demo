// `import x from "./file.ts?raw"` is a Vite/vitest feature that yields the file's
// source text. Declared here so the Worker's tsconfig — which deliberately has no
// Node types — can typecheck tests that read source files (src/openapi.test.ts),
// without importing `node:fs` or `__dirname`.
declare module "*?raw" {
  const content: string;
  export default content;
}
