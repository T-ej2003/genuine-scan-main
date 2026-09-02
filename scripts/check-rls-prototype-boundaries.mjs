#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

const walk = (dir, out = []) => {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", "dist", ".prisma"].includes(entry.name)) walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
};

const toRel = (file) => path.relative(repoRoot, file).replace(/\\/g, "/");
const failures = [];
const listGitFiles = (...args) =>
  execFileSync("git", ["ls-files", ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .split("\n")
    .map((entry) => entry.trim())
    .filter(Boolean);
const trackedFiles = Array.from(new Set([...listGitFiles(), ...listGitFiles("--others", "--exclude-standard")]));
const automationFileExactPaths = new Set(["package.json", "backend/package.json"]);
const automationDirectoryPrefixes = [
  ".github/workflows/",
  "deploy/",
  "ops/deploy/",
  "backend/prisma/migrations/",
];
const requiredAutomationCoverage = ["ops/deploy/deploy.yml", "ops/deploy/deploy-standby.yml"];
const isAutomationFile = (file) =>
  automationFileExactPaths.has(file) || automationDirectoryPrefixes.some((prefix) => file.startsWith(prefix));

const migrationFiles = walk(path.join(repoRoot, "backend/prisma/migrations")).filter((file) =>
  /\.(sql|ts|js|mjs|cjs)$/.test(file)
);

for (const file of migrationFiles) {
  const rel = toRel(file);
  const source = fs.readFileSync(file, "utf8");
  if (/mscqr_staging_rls_prototype\.sql|ENABLE\s+ROW\s+LEVEL\s+SECURITY|FORCE\s+ROW\s+LEVEL\s+SECURITY/i.test(source)) {
    failures.push(`${rel}: prototype RLS SQL must not be placed in Prisma migrations.`);
  }
}

const srcFiles = walk(path.join(repoRoot, "backend/src")).filter((file) => /\.(ts|tsx|js|mjs|cjs)$/.test(file));

for (const file of srcFiles) {
  const rel = toRel(file);
  if (rel === "backend/src/lib/rlsTransactionContextPrototype.ts") continue;
  const source = fs.readFileSync(file, "utf8");
  if (!/rlsTransactionContextPrototype|withRlsPrototypeTransaction|setRlsPrototypeContext/.test(source)) continue;
  if (!/rls-prototype-approved-import/.test(source)) {
    failures.push(`${rel}: production runtime must not import RLS prototype helper without rls-prototype-approved-import marker.`);
  }
}

const rlsIndexArtifacts = trackedFiles.filter((file) => /^mscqr_rls_index.*non_applied\.sql$/i.test(path.basename(file)));
for (const file of rlsIndexArtifacts) {
  if (!file.startsWith("documents/security/")) {
    failures.push(`${file}: non-applied RLS index SQL artifacts must stay under documents/security.`);
  }
}

const automationFiles = trackedFiles.filter(
  (file) => isAutomationFile(file)
);
for (const file of requiredAutomationCoverage) {
  if (trackedFiles.includes(file) && !automationFiles.includes(file)) {
    failures.push(`${file}: required deploy automation path is not covered by the non-applied RLS index artifact scan.`);
  }
}
for (const file of automationFiles) {
  if (!fs.existsSync(path.join(repoRoot, file))) continue;
  const source = fs.readFileSync(path.join(repoRoot, file), "utf8");
  for (const artifact of rlsIndexArtifacts) {
    const artifactName = path.basename(artifact);
    if (source.includes(artifactName) || source.includes(artifact)) {
      failures.push(`${file}: automatic migration/deploy automation must not reference non-applied RLS index artifact ${artifact}.`);
    }
  }
}

const rlsTestFiles = walk(path.join(repoRoot, "backend/tests")).filter((file) => {
  const base = path.basename(file);
  return /^rls.*Prototype.*\.test\.(js|mjs|cjs|ts)$/.test(base);
});

for (const file of rlsTestFiles) {
  const rel = toRel(file);
  const source = fs.readFileSync(file, "utf8");
  if (!/MSCQR_RLS_[A-Z_]*PROTOTYPE_TEST/.test(source) || !/process\.exit\(0\)/.test(source)) {
    failures.push(`${rel}: RLS prototype tests must stay explicitly env-gated and skip by default.`);
  }
}

if (failures.length > 0) {
  console.error("RLS prototype boundary guard failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`RLS prototype boundary guard passed for ${migrationFiles.length} migration file(s), ${srcFiles.length} runtime file(s), and ${rlsTestFiles.length} prototype test file(s).`);
