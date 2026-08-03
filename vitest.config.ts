import { defineConfig } from "vitest/config";

// Separate from vite.config.ts on purpose: that one sets `root: "web"` for the
// SPA build, which would hide the Worker's own tests under src/.
export default defineConfig({
  test: {
    root: __dirname,
    include: ["src/**/*.test.ts", "web/src/**/*.test.ts", "scripts/**/*.test.ts"],
    environment: "node",
  },
});
