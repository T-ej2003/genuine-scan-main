import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";
import JSZip from "jszip";

// A disposable local repository exercises the real build without representing
// these fixture commits as protected production source or contacting AWS.
test("real locked package builds reproducibly from a clean source tree and refuses dirty source", { timeout: 120000 }, async () => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-package-test-"));
  const stack = "infra/aws/terraform/production-component-deployment-state";
  try {
    fs.cpSync(path.join(root, "scripts/aws"), path.join(fixture, "scripts/aws"), { recursive: true });
    fs.cpSync(path.join(root, stack), path.join(fixture, stack), { recursive: true, filter: (name) => !name.includes("/.terraform") && !name.endsWith(".tfstate") });
    fs.symlinkSync(fs.realpathSync(path.join(root, "node_modules")), path.join(fixture, "node_modules"));
    fs.writeFileSync(path.join(fixture, ".gitignore"), "node_modules\n");
    const git = (...args) => execFileSync("git", args, { cwd: fixture, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    git("init", "--quiet");
    git("add", ".");
    git("-c", "user.name=Component package fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Disposable package fixture");
    git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"));
    const { buildComponentBrokerPackage } = await import(pathToFileURL(path.join(fixture, "scripts/aws/component-broker-package.mjs")));
    const first = await buildComponentBrokerPackage();
    const second = await buildComponentBrokerPackage();
    assert.equal(first.packageSha256, second.packageSha256);
    assert(first.bytes.equals(second.bytes));
    const zip = await JSZip.loadAsync(first.bytes);
    assert.equal(await zip.file("index.mjs").async("string"), 'export { handler } from "./scripts/aws/component-iam-broker.mjs";\n');
    assert(zip.file("node_modules/@aws-sdk/client-iam/package.json"));
    assert(zip.file("scripts/aws/installation-manifest.json"));
    assert.deepEqual(JSON.parse(await zip.file("scripts/aws/installation-manifest.json").async("string")), first.manifest);
    assert(!Object.keys(zip.files).some((name) => name.includes(".git/") || name.includes(".aws/") || name.includes(".npm/")));
    const unpacked = path.join(fixture, "unpacked");
    for (const [name, member] of Object.entries(zip.files)) {
      assert(!path.isAbsolute(name) && !name.split("/").includes(".."));
      const target = path.join(unpacked, name);
      if (member.dir) fs.mkdirSync(target, { recursive: true });
      else {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, await member.async("nodebuffer"));
      }
    }
    // Load the actual ZIP's handler and pinned SDKs with no host credential
    // environment. It must reject before constructing any AWS request.
    execFileSync(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import { handler } from './index.mjs';
      for (const service of ['iam', 's3', 'lambda', 'cloudtrail']) {
        assert(await import('@aws-sdk/client-' + service));
      }
      await assert.rejects(handler({operation:'INSTALL'}, {
        functionVersion:'1',
        invokedFunctionArn:'arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer:1'
      }), /Component installation broker request rejected/);
    `], { cwd: unpacked, env: {}, stdio: ["ignore", "pipe", "pipe"] });
    fs.appendFileSync(path.join(fixture, "scripts/aws/component-iam-broker.mjs"), "\n// Unreviewed source change\n");
    await assert.rejects(buildComponentBrokerPackage(), /source must be clean/);
  } finally {
    fs.rmSync(fixture, { recursive: true }); // Only the disposable fixture above.
  }
});
