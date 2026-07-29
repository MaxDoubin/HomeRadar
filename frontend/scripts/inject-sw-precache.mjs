// Runs right after `vite build`. public/sw.js is copied to dist/sw.js
// verbatim (Vite's convention for the public/ directory), with two
// placeholders that this script fills in with facts only known after the
// build: the real hashed asset filenames, and a per-build cache name so
// every deploy gets a fresh cache (see the comment in public/sw.js for why).
//
// Deliberately plain Node/fs -- no bundler plugin, no third-party
// dependency -- so the app-shell precache list can never silently drift
// from what Vite actually produced without a build error surfacing here.
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const frontendDir = dirname(dirname(fileURLToPath(import.meta.url)));
const distDir = join(frontendDir, "dist");
const swPath = join(distDir, "sw.js");

function listFiles(dir, urlPrefix) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => `${urlPrefix}/${entry.name}`);
}

const assetPaths = listFiles(join(distDir, "assets"), "/assets");
const iconPaths = listFiles(join(distDir, "icons"), "/icons");
const precacheManifest = ["/", "/manifest.webmanifest", ...assetPaths, ...iconPaths];

if (assetPaths.length === 0) {
  throw new Error(
    "inject-sw-precache: no files found under dist/assets -- did `vite build` run first and actually produce output?",
  );
}

const buildId = Date.now().toString(36);

let sw = readFileSync(swPath, "utf8");

if (!sw.includes("__BUILD_ID__")) {
  throw new Error("inject-sw-precache: __BUILD_ID__ placeholder not found in dist/sw.js -- did public/sw.js change shape?");
}
sw = sw.replace("__BUILD_ID__", buildId);

const corePattern = /const CORE_ASSETS = \[.*?\];.*$/m;
if (!corePattern.test(sw)) {
  throw new Error("inject-sw-precache: CORE_ASSETS declaration not found in dist/sw.js -- did public/sw.js change shape?");
}
sw = sw.replace(corePattern, `const CORE_ASSETS = ${JSON.stringify(precacheManifest)};`);

writeFileSync(swPath, sw);
console.log(
  `inject-sw-precache: precached ${precacheManifest.length} app-shell files under cache "homeradar-shell-${buildId}"`,
);
