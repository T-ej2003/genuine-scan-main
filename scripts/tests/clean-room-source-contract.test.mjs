import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { cleanRoomSourcePaths, calculateCleanRoomSourceContract } from "../rls/lib/clean-room-source-contract.mjs";

const bootstrap = "backend/src/rls-waves/session-c/c04/bootstrapConfiguredSuperAdmin.sql";
const operators = "backend/src/rls-waves/session-c/c04/operatorProcedures.sql";
const operatorRollback = "backend/src/rls-waves/session-c/c04/operatorProceduresRollback.sql";
const rolloutClassifier = "scripts/aws/exact-ecs-rollout-state.mjs";
const root = process.cwd();

const copyContractInputs = (target) => {
  for (const relative of cleanRoomSourcePaths) {
    const source = path.join(root, relative); const destination = path.join(target, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.copyFileSync(source, destination);
  }
  const migrations = path.join(root, "backend/prisma/migrations");
  for (const entry of fs.readdirSync(migrations, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const destination = path.join(target, "backend/prisma/migrations", entry.name);
    fs.mkdirSync(destination, { recursive: true }); fs.copyFileSync(path.join(migrations, entry.name, "migration.sql"), path.join(destination, "migration.sql"));
  }
};

test("security-sensitive runtime and initial-admin sources bind the clean-room source contract", (t) => {
  for (const relative of [bootstrap, operators, operatorRollback, rolloutClassifier]) assert(cleanRoomSourcePaths.includes(relative));
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-source-contract-")); t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  copyContractInputs(fixture);
  const baseline = calculateCleanRoomSourceContract(fixture).sourceContractSha256;
  const generated = JSON.parse(fs.readFileSync("documents/security/rls-program/generated/full-rls-implementation-manifest.json", "utf8"));
  assert.equal(generated.sourceContractSha256, baseline);
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, baseline);
  for (const relative of [bootstrap, operators, operatorRollback, rolloutClassifier]) {
    const candidate = path.join(fixture, relative);
    fs.appendFileSync(candidate, `\n-- contract mutation ${crypto.randomUUID()}\n`);
    assert.notEqual(calculateCleanRoomSourceContract(fixture).sourceContractSha256, generated.sourceContractSha256);
    fs.copyFileSync(path.join(root, relative), candidate);
  }
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, baseline);
});

test('receipt identity and trust dependency changes invalidate the generated source binding', (t) => {
  const dependencies = [
    'scripts/aws/production-receipt-read.mjs',
    'scripts/aws/production-green-stage-b-contract.mjs',
    'scripts/aws/stage-b-terraform-backend-contract.mjs',
    'scripts/aws/stage-b-deployment-identity.mjs',
    'scripts/aws/production-release-oidc-contract.mjs',
    'scripts/aws/iam-policy-document.mjs',
  ];
  for (const relative of dependencies) assert.ok(cleanRoomSourcePaths.includes(relative), `Unbound receipt authority dependency: ${relative}`);
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-receipt-source-contract-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  copyContractInputs(fixture);
  fs.cpSync(path.join(root, 'backend/src/rls-waves'), path.join(fixture, 'backend/src/rls-waves'), { recursive: true });
  fs.cpSync(path.join(root, 'scripts/rls'), path.join(fixture, 'scripts/rls'), { recursive: true });
  fs.cpSync(path.join(root, 'documents/security/rls-program'), path.join(fixture, 'documents/security/rls-program'), { recursive: true });
  fs.symlinkSync(path.join(root, 'node_modules'), path.join(fixture, 'node_modules'), 'dir');
  const generated = JSON.parse(fs.readFileSync('documents/security/rls-program/generated/checksums.json', 'utf8'));
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, generated.sourceContractSha256);
  for (const relative of dependencies) {
    const target = path.join(fixture, relative);
    if (relative.endsWith('stage-b-deployment-identity.mjs')) {
      const source = fs.readFileSync(target, 'utf8');
      assert.ok(source.includes('if (originMainHead !== toolingSha)'));
      fs.writeFileSync(target, source.replace('if (originMainHead !== toolingSha)', 'if (false)'));
    } else if (relative.endsWith('production-release-oidc-contract.mjs')) {
      const source = fs.readFileSync(target, 'utf8');
      assert.ok(source.includes('Action: "sts:AssumeRole",'));
      fs.writeFileSync(target, source.replace('Action: "sts:AssumeRole",', 'Action: ["sts:AssumeRole", "sts:TagSession"],'));
      const trust = JSON.parse(fs.readFileSync(path.join(root, 'documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json'), 'utf8'));
      trust.Statement.find(statement => statement.Sid === 'BootstrapOperatorHandoffOnlyWithMfa').Action = ['sts:AssumeRole', 'sts:TagSession'];
      const probe = spawnSync(process.execPath, ['--input-type=module', '-e', `import {classifyProductionReleaseTrustPolicy} from ${JSON.stringify('file://' + target)}; console.log(classifyProductionReleaseTrustPolicy(${JSON.stringify(trust)}));`], { encoding: 'utf8' });
      assert.equal(probe.status, 0, probe.stderr);
      assert.equal(probe.stdout.trim(), 'TARGET', 'Fixture must materially permit TagSession');
    } else fs.appendFileSync(target, '\n// changed receipt authority dependency\n');
    assert.notEqual(calculateCleanRoomSourceContract(fixture).sourceContractSha256, generated.sourceContractSha256, relative);
    const verification = spawnSync(process.execPath, [fs.realpathSync(path.join(fixture, 'scripts/rls/verify-full-rls-package.mjs'))], { cwd: fixture, encoding: 'utf8' });
    assert.notEqual(verification.status, 0, relative);
    assert.match(verification.stderr, /Generated package is stale relative to its authoritative source contract/, relative);
    fs.copyFileSync(path.join(root, relative), target);
  }
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, generated.sourceContractSha256);
});
