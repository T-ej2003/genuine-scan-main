import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { validateException } from "./dependency-risk-acceptance.mjs";

// A reviewed CVE reachability decision, not a claim of complete plugin provenance.
// Any change to executable inputs or the locked build toolchain needs new review.
export function reachabilityInputsSha256(root) {
  const files = [];
  function visit(relative) {
    const absolute = path.join(root, relative);
    if (!existsSync(absolute)) return;
    const stat = lstatSync(absolute);
    assert.ok(!stat.isSymbolicLink(), `Unreviewed symlink: ${relative}`);
    if (stat.isDirectory()) for (const name of readdirSync(absolute).sort()) visit(`${relative}/${name}`);
    else if (stat.isFile()) files.push([relative, createHash("sha256").update(readFileSync(absolute)).digest("hex")]);
  }
  for (const name of ["src", "pages", "components", "app", "public", "shared", "scripts", "docker", "backend/src", "backend/docker", "backend/prisma", "backend/scripts", "backend/package.json", "backend/package-lock.json", "backend/Dockerfile", ".github/workflows", ".github/actions"]) visit(name);
  for (const name of readdirSync(root).sort()) if (/^(?:.*\.(?:json|[cm]?js|ts|html|css|scss|sass)|Dockerfile(?:\..*)?|nginx.*\.conf|\.dockerignore|\.env(?:\..*)?)$/.test(name)) visit(name);
  return createHash("sha256").update(JSON.stringify(files.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))).digest("hex");
}

export function validateNonRuntimeAcceptance(entry, browser, root, today) {
  assert.equal(validateException(entry, today, ["frontend-build-only/non-runtime"]), null, "Invalid/expired non-runtime acceptance");
  assert.match(entry.affectedVersion || "", /^\d+\.\d+\.\d+$/);
  assert.match(entry.cve || "", /^CVE-\d{4}-\d+$/);
  assert.match(entry.createdAt || "", /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(entry.createdAt <= today && entry.createdAt < entry.expiresOn, "Invalid acceptance creation date");
  const evidence = entry.reachability;
  assert.ok(evidence && /^[a-f0-9]{64}$/.test(evidence.inputsSha256), "Missing reviewed reachability evidence");
  assert.equal(browser.canonicalBuild, true, "Unreviewed build/plugin options");
  assert.equal(browser.inputsSha256, reachabilityInputsSha256(root), "Build inputs changed after compilation");
  assert.equal(evidence.inputsSha256, browser.inputsSha256, "Stale reachability review: executable/build inputs changed");
  for (const closure of ["backend", "worker", "frontendServer", "browser"]) {
    assert.equal(evidence.execution?.[closure], "NO", `${closure} execution is YES/UNKNOWN`);
  }
  assert.equal(evidence.productionAttackerControlsPattern, "NO", "Unknown/untrusted vulnerable input");
  assert.ok(!browser.packages.includes(`${entry.package}@${entry.affectedVersion}`), "Positive browser runtime evidence contradicts acceptance");
  const backendLock = JSON.parse(readFileSync(path.join(root, "backend/package-lock.json"), "utf8"));
  assert.ok(!Object.keys(backendLock.packages).some(key => key.endsWith(`/node_modules/${entry.package}`) || key === `node_modules/${entry.package}`), "Backend/worker dependency evidence contradicts acceptance");
  const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const installed = Object.entries(lock.packages).filter(([key]) => key.endsWith(`/node_modules/${entry.package}`) || key === `node_modules/${entry.package}`);
  assert.ok(installed.length && installed.every(([, pkg]) => pkg.version === entry.affectedVersion && pkg.dev === true), "Changed/runtime dependency instance");
}
