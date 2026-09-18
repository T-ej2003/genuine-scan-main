import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createDeterministicArchive } from "./package-production-green-stage-b-broker.mjs";
import { canonical, digest, documentBindings, installationDocuments, installationIdentity } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, identityBootstrapCapabilitySet } from "./component-installation-identity-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const terraformRoot = "infra/aws/terraform/production-component-deployment-state";
const packageRoot = `${terraformRoot}/broker-package`;
const sourceFiles = [
  ...["component-iam-broker", "component-broker-authorization", "component-broker-configuration", "component-installation-identity-contract", "component-iam-installation-contract", "component-session-proof", "iam-policy-document"].map((name) => `scripts/aws/${name}.mjs`),
  ...["normal-deployer-trust-policy", "normal-deployer-policy", "bootstrap-trust-policy", "bootstrap-policy", "release-terminal-state-policy"].map((name) => `${terraformRoot}/${name}.json`),
  `${packageRoot}/package.json`, `${packageRoot}/package-lock.json`,
];
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const entry = 'export { handler } from "./scripts/aws/component-iam-broker.mjs";\n';

// A manifest is build evidence, never installation authorization. The bootstrap
// separately authenticates protected main, clean source, approval and replay.
export function componentBrokerPackageManifest(sourceSha) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(arguments.length, 1, "Package overrides are forbidden");
  const files = Object.fromEntries(sourceFiles.map((name) => {
    const absolute = path.join(root, name);
    assert(fs.lstatSync(absolute).isFile(), "Package inputs must be regular source files");
    return [name, sha256(fs.readFileSync(absolute))];
  }));
  const pkg = JSON.parse(fs.readFileSync(path.join(root, packageRoot, "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(root, packageRoot, "package-lock.json"), "utf8"));
  assert.equal(pkg.scripts, undefined, "Broker package lifecycle scripts are forbidden");
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
  for (const [name, dependency] of Object.entries(lock.packages)) {
    if (!name) continue;
    assert(name.startsWith("node_modules/") && !name.split("/").includes(".."));
    assert.match(dependency.resolved || "", /^https:\/\/registry\.npmjs\.org\//);
    assert.match(dependency.integrity || "", /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    assert(!dependency.link, "Linked executable dependency forbidden");
  }
  const identities = bootstrapManagedIdentities();
  return { schemaVersion: 1, account: installationIdentity.account, region: installationIdentity.region, sourceSha,
    targets: installationDocuments(), identities, documentBindingsSha256: digest(documentBindings()),
    capabilitySetSha256: digest(identities), bootstrapCapabilitySetSha256: digest(identityBootstrapCapabilitySet()),
    sourceFiles: files, entrySha256: sha256(entry) };
}

export async function buildComponentBrokerPackage() {
  assert.equal(arguments.length, 0, "Caller-selected package inputs are forbidden");
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const sourceSha = git("rev-parse", "HEAD");
  assert.equal(sourceSha, git("rev-parse", "origin/main"), "Package source is not authenticated main");
  assert.equal(git("status", "--porcelain", "--untracked-files=all"), "", "Package source must be clean");
  const manifest = componentBrokerPackageManifest(sourceSha);
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-broker-package-"));
  fs.chmodSync(workspace, 0o700);
  try {
    const destination = path.join(workspace, "package");
    fs.mkdirSync(destination, { mode: 0o700 });
    for (const name of sourceFiles) {
      const target = path.join(destination, name.startsWith(`${packageRoot}/`) ? path.basename(name) : name);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      const bytes = fs.readFileSync(path.join(root, name));
      assert.equal(sha256(bytes), manifest.sourceFiles[name], "Package source changed while copying");
      fs.writeFileSync(target, bytes, { mode: 0o644, flag: "wx" });
    }
    fs.writeFileSync(path.join(destination, "index.mjs"), entry, { mode: 0o644, flag: "wx" });
    fs.writeFileSync(path.join(destination, "scripts/aws/installation-manifest.json"), canonical(manifest), { mode: 0o644, flag: "wx" });
    const npm = path.resolve(path.dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js");
    assert(fs.statSync(npm).isFile(), "Canonical Node installation lacks npm");
    for (const name of ["user.npmrc", "global.npmrc"]) fs.writeFileSync(path.join(workspace, name), "", { flag: "wx", mode: 0o600 });
    execFileSync(process.execPath, [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org", `--userconfig=${path.join(workspace, "user.npmrc")}`, `--globalconfig=${path.join(workspace, "global.npmrc")}`, `--cache=${path.join(workspace, "cache")}`], {
      cwd: destination, stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`, HOME: workspace, LANG: "C", TZ: "UTC" },
    });
    assert.equal(git("rev-parse", "HEAD"), sourceSha);
    assert.equal(git("status", "--porcelain", "--untracked-files=all"), "");
    assert.equal(digest(componentBrokerPackageManifest(sourceSha)), digest(manifest), "Source moved while packaging");
    const bytes = await createDeterministicArchive(destination);
    return { manifest, manifestSha256: digest(manifest), packageSha256: sha256(bytes), bytes };
  } finally {
    fs.rmSync(workspace, { recursive: true }); // Only this invocation's mkdtemp tree.
  }
}
