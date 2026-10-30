import { readApprovedImages } from "../lib/container-image-identity.mjs";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const script = path.join(root, "scripts/check-dependency-audit.mjs");
const clean = { vulnerabilities: {}, metadata: { vulnerabilities: { total: 0 } } };
const vulnerable = {
  vulnerabilities: {
    unsafe: {
      severity: "high",
      via: [{ source: 1234, url: "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC" }],
    },
  },
};

const run = ({ frontend = clean, backend = clean, exceptions = [] } = {}) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-audit-policy-"));
  const rootReport = path.join(dir, "root.json");
  const backendReport = path.join(dir, "backend.json");
  const allowlist = path.join(dir, "allowlist.json");
  writeFileSync(rootReport, JSON.stringify(frontend));
  writeFileSync(backendReport, JSON.stringify(backend));
  writeFileSync(allowlist, JSON.stringify({ schemaVersion: 1, entries: exceptions }));
  return spawnSync(process.execPath, [script], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      DEPENDENCY_AUDIT_REPORT_ROOT: rootReport,
      DEPENDENCY_AUDIT_REPORT_BACKEND: backendReport,
      DEPENDENCY_AUDIT_ALLOWLIST: allowlist,
    },
  });
};

test("passes clean production trees", () => {
  assert.equal(run().status, 0);
});

test("blocks a high production advisory", () => {
  const result = run({ backend: vulnerable });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /backend: high unsafe \(GHSA-AAAA-BBBB-CCCC\)/);
});

test("accepts only an exact, owned, reasoned, non-expired exception", () => {
  const result = run({
    backend: vulnerable,
    exceptions: [{
      scope: "backend",
      package: "unsafe",
      advisory: "GHSA-AAAA-BBBB-CCCC",
      rationale: "Temporary upstream remediation window.",
      owner: "security@example.invalid",
      expiresOn: "2099-12-31",
    }],
  });
  assert.equal(result.status, 0, result.stderr);
});

test("rejects expired, wildcard, and stale exceptions", () => {
  const common = {
    scope: "backend",
    package: "unsafe",
    advisory: "GHSA-AAAA-BBBB-CCCC",
    rationale: "Temporary upstream remediation window.",
    owner: "security@example.invalid",
  };
  assert.equal(run({ backend: vulnerable, exceptions: [{ ...common, expiresOn: "2000-01-01" }] }).status, 1);
  assert.equal(run({ backend: vulnerable, exceptions: [{ ...common, package: "*", expiresOn: "2099-12-31" }] }).status, 1);
  assert.equal(run({ exceptions: [{ ...common, expiresOn: "2099-12-31" }] }).status, 1);
});

test("high browser-runtime and transitive frontend dependencies still fail", () => {
  assert.equal(run({ frontend: vulnerable }).status, 1);
  const transitive = { vulnerabilities: { ...vulnerable.vulnerabilities, parent: { severity: "high", via: ["unsafe"] } } };
  const result = run({ frontend: transitive });
  assert.equal(result.status, 1); assert.match(result.stderr, /root: high parent/);
});

test("backend and worker share the strict audited runtime dependency closure", () => {
  assert.equal(run({ backend: vulnerable }).status, 1);
  const dockerfile = readFileSync(path.join(root, "backend/Dockerfile"), "utf8");
  assert.match(dockerfile, /npm prune --omit=dev/);
  assert.match(dockerfile, /COPY --from=builder --chown=node:node \/workspace\/backend\/node_modules \.\/node_modules/);
  assert.match(readFileSync(path.join(root, "scripts/aws/publish-ecs-images.sh"), "utf8"), /backend\|worker\) printf 'runtime'/);
});

test("Tailwind compiler/plugin and braces are build-only, not runtime dependency exceptions", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8"));
  assert.equal(manifest.dependencies["tailwindcss-animate"], undefined);
  assert.equal(manifest.devDependencies["tailwindcss-animate"], "^1.0.7");
  for (const name of ["tailwindcss-animate", "tailwindcss", "braces", "chokidar", "fast-glob", "micromatch"]) assert.equal(lock.packages[`node_modules/${name}`].dev, true, name);
  assert.match(readFileSync(path.join(root, "tailwind.config.ts"), "utf8"), /import tailwindcssAnimate from "tailwindcss-animate"/);
  const runtime = readFileSync(path.join(root, "Dockerfile.ecs-frontend"), "utf8").split(`FROM ${readApprovedImages().nginx.reference}`)[1];
  assert.match(runtime, /COPY --from=builder \/app\/dist \/usr\/share\/nginx\/html/);
  assert.doesNotMatch(runtime, /node_modules|npm |node:/);
  assert.equal(run().status, 0, "Audit reports with build dependencies omitted must pass without a waiver");
});

test("lockfile retains optional WASM dependency records required by Linux npm ci", () => {
  const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8"));
  for (const name of ["@emnapi/core", "@emnapi/runtime"]) {
    assert.ok(lock.packages[`node_modules/${name}`], name);
    assert.match(lock.packages[`node_modules/${name}`].integrity, /^sha512-/);
  }
});

// Project tooling uses named APIs; v11 is not a general replacement for v3's callable/default export.
test("scoped minimatch remediation resolves patched copies through every owning tool", () => {
  const require = createRequire(import.meta.url);
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const copies = Object.entries(lock.packages).filter(([name]) => name.endsWith("/minimatch"));
  assert.ok(copies.length > 0);
  for (const [, copy] of copies) { assert.equal(copy.version, "11.0.3"); assert.equal(copy.dev, true); }
  for (const owner of ["eslint", "@eslint/config-array", "@eslint/eslintrc", "@typescript-eslint/typescript-estree"]) {
    assert.deepEqual(manifest.overrides[owner], { minimatch: "11.0.3" });
    const resolve = createRequire(require.resolve(owner));
    assert.equal(resolve("minimatch/package.json").version, "11.0.3");
    const { Minimatch, minimatch } = resolve("minimatch");
    assert.equal(minimatch(".hidden.ts", "*.ts", { dot: true }), true);
    assert.equal(new Minimatch("src/**/!(*.test).{js,ts}", { dot: true }).match("src/nested/app.ts"), true);
    assert.equal(new Minimatch("src/**/!(*.test).{js,ts}", { dot: true }).match("src/app.test.ts"), false);
    assert.equal(new Minimatch("src/**/*.ts", { dot: true }).match("src/nested", true), true);
  }
});

test("patched minimatch preserves ESLint file enumeration and legacy include/exclude matching", async () => {
  const require = createRequire(import.meta.url);
  const { ESLint } = await import("eslint");
  const { OverrideTester } = require("@eslint/eslintrc").Legacy;
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-eslint-minimatch-"));
  try {
    mkdirSync(path.join(dir, "src/generated"), { recursive: true });
    writeFileSync(path.join(dir, "src/app.js"), "const unused = 1;");
    writeFileSync(path.join(dir, "src/valid.mjs"), "export const used = 1;");
    writeFileSync(path.join(dir, "src/generated/skip.js"), "not valid JavaScript {{{");
    const eslint = new ESLint({ cwd: dir, overrideConfigFile: true, overrideConfig: [
      { ignores: ["**/generated/**"] }, { files: ["src/**/*.{js,mjs}"], rules: { "no-unused-vars": "error" } },
    ] });
    const results = await eslint.lintFiles(["src/**/*.{js,mjs}"]);
    assert.deepEqual(results.map(result => path.basename(result.filePath)).sort(), ["app.js", "valid.mjs"]);
    assert.deepEqual(results.flatMap(result => result.messages.map(message => message.ruleId)), ["no-unused-vars"]);
    const legacy = OverrideTester.create(["src/**/*.{js,mjs}"], ["**/generated/**"], dir);
    assert.equal(legacy.test(path.join(dir, "src/app.js")), true);
    assert.equal(legacy.test(path.join(dir, "src/generated/skip.js")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("patched minimatch preserves TypeScript project-service default-project selection", async () => {
  const parser = await import("@typescript-eslint/typescript-estree");
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-typescript-minimatch-"));
  try {
    writeFileSync(path.join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true }, include: ["included.ts"] }));
    writeFileSync(path.join(dir, "included.ts"), "export const included = true;");
    const filePath = path.join(dir, "outside.ts");
    const code = "const answer: number = 42;";
    writeFileSync(filePath, code);
    const parsed = parser.parseAndGenerateServices(code, { filePath, tsconfigRootDir: dir,
      projectService: { allowDefaultProject: ["outside.ts"] } });
    assert.ok(parsed.services.program);
    assert.equal(parsed.ast.body[0].type, "VariableDeclaration");
  } finally { parser.clearCaches(); rmSync(dir, { recursive: true, force: true }); }
});
