import test from 'node:test';
import assert from 'node:assert/strict';
import { buildInventoryInstallationTask } from '../aws/apply-production-rotation-inventory-contract.mjs';
import { canonicalInventoryInstallation } from '../aws/production-rotation-inventory-installation.mjs';
import { PRINTING_ROUTINE_DELTA } from '../aws/apply-production-printing-routine-delta.mjs';

test('fixed installation command retains the canonical SQL and scoped secret without exposing its value', () => {
  const built = buildInventoryInstallationTask({ sourceSha: 'a'.repeat(40), databaseHostname: 'mscqr-production-rls-green-phase2.example.eu-west-2.rds.amazonaws.com' });
  const task = built.definition.containerDefinitions[0];
  assert.equal(task.image, PRINTING_ROUTINE_DELTA.executorImage);
  assert.equal(task.readonlyRootFilesystem, true);
  assert.equal(built.definition.taskRoleArn, undefined);
  assert.deepEqual(task.secrets, [{ name: 'MSCQR_INVENTORY_ADMIN_PASSWORD', valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }]);
  assert.equal(built.statementsSha256, canonicalInventoryInstallation().statementsSha256);
  assert.ok(task.command[1].includes(JSON.stringify(canonicalInventoryInstallation())));
  assert.ok(task.command[1].includes("process.env.MSCQR_INVENTORY_ADMIN_PASSWORD"));
  assert.throws(() => buildInventoryInstallationTask({ sourceSha: 'a'.repeat(40), databaseHostname: 'other.example.com' }));
  assert.throws(() => buildInventoryInstallationTask({ sourceSha: 'invalid', databaseHostname: 'mscqr-production-rls-green-phase2.example.eu-west-2.rds.amazonaws.com' }));
});

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { applyProductionInventoryContract } from '../aws/apply-production-rotation-inventory-contract.mjs';
import { STAGE_B } from '../aws/production-green-stage-b-contract.mjs';
import { APP_ONLY } from '../aws/production-app-only-contract.mjs';

test('reporting recovery authenticates the retained task and never registers or launches again', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'inventory-installer-checkout-'));
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'inventory-installer-receipt-'));
  fs.chmodSync(output, 0o700);
  const git = (args) => execFileSync('/usr/bin/git', args, { cwd: root, encoding: 'utf8' }).trim();
  try {
    git(['init', '-q']); git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture']);
    const sourceSha = git(['rev-parse', 'HEAD']); git(['update-ref', 'refs/remotes/origin/main', sourceSha]);
    const databaseHostname = 'mscqr-production-rls-green-phase2.example.eu-west-2.rds.amazonaws.com';
    const built = buildInventoryInstallationTask({ sourceSha, databaseHostname });
    const taskDefinitionArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rotation-inventory-contract:1`;
    const taskArn = `${STAGE_B.clusterArn.replace(':cluster/', ':task/')}/${'a'.repeat(32)}`;
    const receiptOut = path.join(output, 'receipt.json');
    fs.writeFileSync(receiptOut, JSON.stringify({ sourceSha, taskDefinitionArn, ...built }), { mode: 0o600 });
    fs.writeFileSync(`${receiptOut}.launch.json`, JSON.stringify({ sourceSha, taskArn, taskDefinitionArn, contractSha256: built.contractSha256 }), { mode: 0o600 });
    const receipt = { kind: 'PRODUCTION_ROTATION_INVENTORY_INSTALLATION', sourceSha, contractSha256: built.contractSha256, statementsSha256: built.statementsSha256, status: 'APPLIED', directTableGrantsAdded: 0 };
    const calls = [];
    const run = (_exe, args) => {
      calls.push(args.slice(0, 2).join(':'));
      if (args[0] === 'sts') return JSON.stringify({ Account: STAGE_B.account, Arn: `arn:aws:iam::${STAGE_B.account}:root` });
      if (args[0] === 'rds') return JSON.stringify({ DBInstances: [{ DBInstanceIdentifier: STAGE_B.greenDatabaseIdentifier, DBInstanceStatus: 'available', Endpoint: { Address: databaseHostname } }] });
      if (args[0] === 'ecr') return JSON.stringify({ imageDetails: [{ imageDigest: PRINTING_ROUTINE_DELTA.executorImage.split('@')[1] }] });
      if (args[1] === 'describe-task-definition') return JSON.stringify({ taskDefinition: { ...built.definition, taskDefinitionArn, revision: 1, status: 'ACTIVE' } });
      if (args[1] === 'describe-tasks') return JSON.stringify({ tasks: [{ taskArn, clusterArn: APP_ONLY.clusterArn, taskDefinitionArn, lastStatus: 'STOPPED', containers: [{ name: 'inventory-contract', exitCode: 0 }] }] });
      if (args[0] === 'logs') return JSON.stringify({ events: [{ message: JSON.stringify(receipt) }] });
      throw new Error('Unexpected or mutating AWS operation');
    };
    assert.equal((await applyProductionInventoryContract({ sourceSha, awsProfile: 'fixture', receiptOut, repositoryRoot: root, verifyOnly: true, run })).status, 'APPLIED');
    assert.equal(calls.includes('ecs:run-task'), false); assert.equal(calls.includes('ecs:register-task-definition'), false);
    assert.equal(fs.statSync(`${receiptOut}.result.json`).mode & 0o777, 0o600);
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(output, { recursive: true, force: true }); }
});
