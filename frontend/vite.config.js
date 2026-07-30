import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.js"],
    globals: false,
    // GitHub's Windows runners are meaningfully slower than Linux/macOS for
    // CPU-bound work like this; the default 5s timeout is tight for the
    // "visits every page in one test" navigation test even without a real
    // hang. Raised for headroom there, not to mask an actual bug.
    testTimeout: 15000,
  },
});
