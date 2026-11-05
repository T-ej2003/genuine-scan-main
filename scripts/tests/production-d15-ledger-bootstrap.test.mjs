import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertProtectedMainBranch, assertTrustedBootstrapExecutable, runD15LedgerBootstrap } from "../aws/production-d15-ledger-readback.mjs";

const bootstrap = fileURLToPath(new URL("../aws/production-d15-ledger-readback.mjs", import.meta.url));
const branch = (sha) => ({ name: "main", _links: { self: "https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main" },
  commit: { sha, url: `https://api.github.com/repos/T-ej2003/genuine-scan-main/commits/${sha}` } });

test("trusted bootstrap rejects wrong GitHub identity and executable substitution", () => {
  const sha = "a".repeat(40);
  assert.equal(assertProtectedMainBranch(branch(sha)), sha);
  assert.throws(() => assertProtectedMainBranch({ ...branch(sha), name: "other" }));
  assert.throws(() => assertProtectedMainBranch({ ...branch(sha), _links: { self: "https://attacker.invalid/main" } }));
  assert.throws(() => assertProtectedMainBranch({ ...branch(sha), commit: { ...branch(sha).commit, url: "https://attacker.invalid/commit" } }));
  assert.throws(() => assertTrustedBootstrapExecutable("/tmp/attacker", {
    realpathSync: () => "/tmp/attacker", statSync: () => ({ isFile: () => true, uid: 1000, mode: 0o755 }) }));
  assert.throws(() => assertTrustedBootstrapExecutable("/usr/bin/git", {
    realpathSync: () => "/tmp/attacker/git", statSync: () => ({ isFile: () => true, uid: 0, mode: 0o755 }) }));
});

test("trusted bootstrap loads only the authenticated dependency closure and fails closed on tampering", async () => {
  const repo = fs.realpathSync(fs.mkdtempSync("/tmp/mscqr-d15-bootstrap-test-"));
  const marker = path.join(repo, "dependency-executed");
  const awsDir = path.join(repo, "scripts/aws");
  const infraDir = path.join(repo, "infra/aws/terraform/lambda/production-rls-approval-broker");
  const git = (args) => execFileSync("/usr/bin/git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
  const verifyArgs = [path.join(repo, "authorization.json"), path.join(repo, "receipt.json")];
  try {
    fs.mkdirSync(awsDir, { recursive: true }); fs.mkdirSync(infraDir, { recursive: true });
    fs.copyFileSync(bootstrap, path.join(awsDir, "production-d15-ledger-readback.mjs"));
    fs.writeFileSync(path.join(awsDir, "production-d15-ledger-runtime.mjs"), "import './dependency.mjs'; export async function runD15LedgerReadback() { return { status: 'VERIFIED' }; }\n");
    fs.writeFileSync(path.join(awsDir, "dependency.mjs"), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'authenticated');\n`);
    fs.writeFileSync(path.join(infraDir, "ecs-task-definition-readback.mjs"), "export const fixed = true;\n");
    git(["init", "--quiet"]); git(["config", "user.email", "test@example.invalid"]); git(["config", "user.name", "test"]);
    git(["add", "scripts"]); git(["add", "infra"]); git(["commit", "--quiet", "-m", "approved source"]);
    const approved = git(["rev-parse", "HEAD"]);
    const run = (sha = approved, options = {}) => runD15LedgerBootstrap({ toolingSha: sha, sourceRepository: repo,
      mode: "verify", args: verifyArgs, readMain: async () => branch(sha), ...options });

    await assert.rejects(run(approved, { readMain: async () => branch("b".repeat(40)), mode: "run" }));
    assert.equal(fs.existsSync(marker), false, "Malicious dependency cannot execute before main authentication");
    await assert.rejects(run("f".repeat(40)));
    assert.equal(fs.existsSync(marker), false, "Unknown source cannot execute a dependency");
    fs.writeFileSync(path.join(awsDir, "dependency.mjs"), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'checkout tampering');\n`);
    assert.deepEqual(await run(), { status: "VERIFIED" });
    assert.equal(fs.readFileSync(marker, "utf8"), "authenticated", "The copied dependency came from the approved tree");
    fs.unlinkSync(marker);
    await assert.rejects(run(approved, { beforeLoad: (copy) => fs.writeFileSync(path.join(copy, "scripts/aws/dependency.mjs"), "tampered\n") }), /source copy changed/);
    assert.equal(fs.existsSync(marker), false, "Mutation between copy and import did not execute");
    await assert.rejects(run(approved, { beforeLoad: (copy) => fs.writeFileSync(path.join(copy, "scripts/aws/production-d15-ledger-readback.mjs"), "tampered\n") }), /source copy changed/);
    const alias = `${repo}-symlink`;
    fs.symlinkSync(repo, alias);
    try { await assert.rejects(run(approved, { sourceRepository: alias })); }
    finally { fs.unlinkSync(alias); }
    assert.equal(fs.existsSync(marker), false, "A symlinked source path cannot load a dependency");

    git(["add", "scripts"]); git(["commit", "--quiet", "-m", "malicious checkout content"]);
    const replacement = git(["rev-parse", "HEAD"]);
    git(["replace", approved, replacement]);
    assert.deepEqual(await run(), { status: "VERIFIED" });
    assert.equal(fs.readFileSync(marker, "utf8"), "authenticated", "Git replacement cannot change the approved source");
    fs.unlinkSync(marker);
    fs.symlinkSync("/tmp/attacker", path.join(awsDir, "escape.mjs"));
    git(["add", "scripts"]); git(["commit", "--quiet", "-m", "symlink attack"]);
    const withSymlink = git(["rev-parse", "HEAD"]);
    await assert.rejects(run(withSymlink), /symlink/);
    assert.equal(fs.existsSync(marker), false);
  } finally { fs.rmSync(repo, { recursive: true, force: true }); }
});

test("authenticated source copy contains the real ledger runtime dependency closure", async () => {
  const sourceRoot = fileURLToPath(new URL("../../", import.meta.url));
  const repo = fs.realpathSync(fs.mkdtempSync("/tmp/mscqr-d15-closure-test-"));
  const git = (args) => execFileSync("/usr/bin/git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
  try {
    fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
    fs.cpSync(path.join(sourceRoot, "scripts/aws"), path.join(repo, "scripts/aws"), { recursive: true });
    const relativeInfra = "infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
    fs.mkdirSync(path.dirname(path.join(repo, relativeInfra)), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, relativeInfra), path.join(repo, relativeInfra));
    git(["init", "--quiet"]); git(["config", "user.email", "test@example.invalid"]); git(["config", "user.name", "test"]);
    fs.mkdirSync(path.join(repo, ".git/objects/info"), { recursive: true });
    const objects = execFileSync("/usr/bin/git", ["-C", sourceRoot, "rev-parse", "--git-path", "objects"], { encoding: "utf8" }).trim();
    fs.writeFileSync(path.join(repo, ".git/objects/info/alternates"), `${fs.realpathSync(path.resolve(sourceRoot, objects))}\n`);
    git(["update-ref", "refs/heads/main", "d15b79e4779d64be4c6c7ec905caea1e91d410f2"]);
    git(["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(["read-tree", "d15b79e4779d64be4c6c7ec905caea1e91d410f2"]);
    git(["add", "scripts/aws", relativeInfra]); git(["commit", "--quiet", "-m", "authenticated closure"]);
    const sha = git(["rev-parse", "HEAD"]);
    await assert.rejects(runD15LedgerBootstrap({ toolingSha: sha, sourceRepository: repo, mode: "verify",
      args: [path.join(repo, "absent-authorization.json"), path.join(repo, "absent-receipt.json")], readMain: async () => branch(sha) }),
    /ENOENT.*absent-authorization\.json/, "Runtime imports must load from the authenticated copy before a missing auth file fails");
  } finally { fs.rmSync(repo, { recursive: true, force: true }); }
});
