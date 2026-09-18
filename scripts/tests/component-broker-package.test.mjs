import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { componentBrokerPackageManifest, buildComponentBrokerPackage } from "../aws/component-broker-package.mjs";
import { digest, documentBindings } from "../aws/component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities } from "../aws/component-installation-identity-contract.mjs";

test("package manifest binds all fixed runtime source, locked dependencies, and source-owned IAM documents", () => {
  const manifest = componentBrokerPackageManifest("a".repeat(40));
  assert.deepEqual(manifest, componentBrokerPackageManifest("a".repeat(40)));
  assert.equal(manifest.documentBindingsSha256, digest(documentBindings()));
  assert.deepEqual(manifest.identities, bootstrapManagedIdentities());
  assert.equal(Object.keys(manifest.sourceFiles).length, 17);
  for (const [name, hash] of Object.entries(manifest.sourceFiles)) {
    const bytes = fs.readFileSync(new URL(`../../${name}`, import.meta.url));
    assert.equal(hash, crypto.createHash("sha256").update(bytes).digest("hex"));
    if (!name.endsWith(".mjs")) continue;
    for (const [, dependency] of bytes.toString().matchAll(/from "(\.\/[^"\n]+)"/g)) {
      assert(Object.hasOwn(manifest.sourceFiles, `scripts/aws/${dependency.slice(2)}`), `Missing package runtime dependency: ${dependency}`);
    }
  }
  assert.notEqual(digest(manifest), digest(componentBrokerPackageManifest("b".repeat(40))));
});

test("package API cannot accept alternate source directory, ZIP, policy, or dependency paths", async () => {
  assert.throws(() => componentBrokerPackageManifest("a".repeat(40), { policy: "override" }));
  assert.throws(() => componentBrokerPackageManifest("main"));
  for (const override of [{ zip: "/tmp/other.zip" }, { directory: "/tmp" }, { sourceSha: "a".repeat(40) }, { npm: "/tmp/npm" }]) {
    await assert.rejects(buildComponentBrokerPackage(override), /Caller-selected/);
  }
});
