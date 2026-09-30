// Copies the three Swagger UI vendor files into dist/api-docs/. Runs after
// `vite build`, which empties dist/ — so anything placed there earlier would be
// wiped. The page (index.html + swagger-initializer.js) is committed under
// web/public/api-docs/ and reaches dist/ through Vite's public-dir copy; only
// the ~1.8 MB of vendor code is kept out of git.
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const from = join(root, "node_modules", "swagger-ui-dist");
const to = join(root, "dist", "api-docs");
const files = ["swagger-ui-bundle.js", "swagger-ui.css", "favicon-32x32.png"];

if (!existsSync(from)) {
  console.error(`swagger-ui-dist is not installed (${from}). Run npm ci.`);
  process.exit(1);
}
mkdirSync(to, { recursive: true });
for (const f of files) copyFileSync(join(from, f), join(to, f));
console.log(`copied ${files.length} Swagger UI files → dist/api-docs/`);
