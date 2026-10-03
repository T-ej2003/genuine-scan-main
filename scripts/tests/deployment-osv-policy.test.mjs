import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const policy = path.join(root, ".security/osv-production.toml");
const scanner = process.env.OSV_SCANNER && path.resolve(process.env.OSV_SCANNER);

// Deliberately constrain the current recipes, rather than infer arbitrary Docker
// programs. A packaging change must re-establish this boundary before filtering.
function assertPackaging({ frontend, backend }) {
  for (const dockerfile of frontend) {
    const runtime = dockerfile.split(/^FROM nginx:[^\n]+$/m)[1];
    assert.ok(runtime, "frontend must use the static Nginx runtime");
    assert.doesNotMatch(runtime, /node_modules|\bnpm\b|\bnode\b/);
    assert.deepEqual(runtime.match(/^COPY --from=.*$/gm), ["COPY --from=builder /app/dist /usr/share/nginx/html"]);
  }
  const builder = backend.split("FROM deps AS builder")[1]?.split("FROM node:24-bookworm-slim AS runtime")[0];
  assert.ok(builder, "backend builder must be recognized");
  assert.match(builder, /npm prune --omit=dev --no-audit --no-fund\s*$/);
  assert.equal((backend.match(/npm ci/g) || []).length, 1);
  assert.doesNotMatch(backend.split("AS runtime")[1], /COPY --from=deps|npm (?:ci|install)(?! --global)/);
  const publisher = readFileSync(path.join(root, "scripts/aws/publish-ecs-images.sh"), "utf8");
  assert.match(publisher, /backend\|worker\) printf 'runtime'/);
}
const packaging = () => ({
  frontend: ["Dockerfile", "Dockerfile.ecs-frontend"].map(file => readFileSync(path.join(root, file), "utf8")),
  backend: readFileSync(path.join(root, "backend/Dockerfile"), "utf8"),
});

test("production packaging excludes dev dependencies before OSV filtering", () => assertPackaging(packaging()));
test("manifest dev classification cannot hide dependencies copied into runtime", () => {
  const current = packaging();
  assert.throws(() => assertPackaging({ ...current, backend: current.backend.replace("npm prune --omit=dev", "npm prune") }));
  assert.throws(() => assertPackaging({ ...current, frontend: current.frontend.map(file => file + "\nCOPY --from=builder /app/node_modules /app/node_modules\n") }));
});
test("OSV policy is a general dev-group rule, with no advisory/severity exceptions", () => {
  const config = readFileSync(policy, "utf8").replace(/^#.*$/gm, "").trim();
  assert.equal(config, '[[PackageOverrides]]\necosystem = "npm"\ngroup = "dev"\nvulnerability.ignore = true');
  const workflow = readFileSync(path.join(root, ".github/workflows/deployment-audit.yml"), "utf8");
  assert.ok(workflow.indexOf("Verify OSV runtime boundary") < workflow.indexOf("Run OSV Scanner"));
  assert.match(workflow, /--recursive --no-resolve --config=\.security\/osv-production\.toml \./);
  assert.match(workflow, /--format=json --output-file=audit-artifacts\/osv-source.json/);
  assert.match(workflow, /test "\$status" -eq 0 \|\| test "\$status" -eq 1/);
  assert.doesNotMatch(config, /GHSA|IgnoredVulns|severity/i);
});

// Exercise the official scanner itself, not a second implementation of grouping.
// CI supplies the installed binary; local integration uses the same v2.6.0 build.
function scan(groups, filtered = true, transitive = false) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-osv-policy-"));
  try {
    groups.forEach((dev, index) => {
      const folder = path.join(dir, String(index));
      mkdirSync(folder);
      const file = path.join(folder, "package-lock.json");
      writeFileSync(file, JSON.stringify({ name: "osv-boundary-fixture", lockfileVersion: 3, packages: {
        "": { name: "osv-boundary-fixture", [dev ? "devDependencies" : "dependencies"]: transitive ? { "fixture-parent": "1.0.0" } : { braces: "3.0.3" } },
        ...(transitive ? { "node_modules/fixture-parent": { version: "1.0.0", dependencies: { braces: "3.0.3" } } } : {}),
        "node_modules/braces": { version: "3.0.3", ...(dev ? { dev: true } : {}) },
      } }));
    });
    const files = groups.flatMap((_, index) => ["--lockfile", path.join(dir, String(index), "package-lock.json")]);
    const result = spawnSync(scanner, ["--no-resolve", ...(filtered ? [`--config=${policy}`] : []), ...files], { encoding: "utf8", timeout: 120000 });
    assert.equal(result.error, undefined);
    return result;
  } finally { rmSync(dir, { recursive: true }); }
}
for (const [name, groups, expected] of [
  ["high dev-only vulnerability does not block production", [true], 0],
  ["high frontend runtime vulnerability blocks", [false], 1],
  ["high backend runtime vulnerability blocks", [false], 1],
  ["high worker runtime vulnerability blocks", [false], 1],
  ["high transitive runtime vulnerability blocks", [false], 1],
  ["same advisory in dev and runtime closures still blocks", [true, false], 1],
]) test(name, { skip: !scanner }, () => {
  const result = scan(groups, true, name.includes("transitive"));
  assert.equal(result.status, expected, result.stdout + result.stderr);
  if (expected) assert.match(result.stdout + result.stderr, /GHSA-vfj7-8cjw-p6xm/i);
});
test("unfiltered report preserves dev vulnerability visibility", { skip: !scanner }, () => {
  const result = scan([true], false);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /braces \(dev\)/);
});
