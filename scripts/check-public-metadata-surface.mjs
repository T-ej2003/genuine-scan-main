import { readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const files = {
  index: path.join(repoRoot, "backend", "src", "index.ts"),
  routes: path.join(repoRoot, "backend", "src", "routes", "index.ts"),
  smoke: path.join(repoRoot, "scripts", "smoke-release.mjs"),
};

const failures = [];

const indexContents = readFileSync(files.index, "utf8");
if (/X-Release-Version/i.test(indexContents) || /X-Release-Sha/i.test(indexContents)) {
  failures.push("backend/src/index.ts still emits public release headers.");
}

const routeContents = readFileSync(files.routes, "utf8");
if (/router\.get\(\s*["'`]\/version["'`]/i.test(routeContents)) {
  failures.push("backend/src/routes/index.ts still exposes /api/version publicly.");
}

const smokeContents = readFileSync(files.smoke, "utf8");
if (/\/version['"`]/i.test(smokeContents)) {
  failures.push("scripts/smoke-release.mjs still depends on /version.");
}

if (failures.length > 0) {
  console.error("Public metadata surface check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Public metadata surface check passed.");

