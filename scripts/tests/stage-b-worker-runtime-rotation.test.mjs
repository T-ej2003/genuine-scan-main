import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { assertStageBTaskDefinitionRotation } from '../aws/stage-b-reference-audit-contract.mjs';
import { taskChange, rotationVariables } from './fixtures/stage-b-task-rotation.mjs';
const address = 'aws_ecs_task_definition.candidate["worker"]';
const template = JSON.parse(fs.readFileSync('infra/aws/terraform/production-green-stage-b/task-definitions/green-worker-candidate.json'));
const names = new Set(['MSCQR_WORKER_DATABASE_ROLE', 'SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_REQUIRE_TLS', 'SMTP_USER', 'SMTP_FROM']);
function fixture() {
  const change = taskChange(address, 25);
  const before = JSON.parse(change.change.before.container_definitions)[0];
  before.secrets = template.containerDefinitions[0].secrets.filter(s => s.name !== 'SMTP_PASS');
  const after = structuredClone(before);
  after.image = rotationVariables.worker_image.value;
  after.environment[0].value = rotationVariables.image_release_sha.value;
  after.environment.push(...template.containerDefinitions[0].environment.filter(e => names.has(e.name)));
  after.secrets = template.containerDefinitions[0].secrets;
  return { change, before, after };
}
function check(f) {
  f.change.change.before.container_definitions = JSON.stringify([f.before]);
  f.change.change.after.container_definitions = JSON.stringify([f.after]);
  return assertStageBTaskDefinitionRotation(f.change, { variables: rotationVariables });
}
test('exact reviewed worker runtime registration, then ordinary image rotation', () => {
  const f = fixture(); assert.equal(check(f).classification, 'rollover');
  f.before = structuredClone(f.after); f.before.image = f.before.image.replace('2'.repeat(64), 'f'.repeat(64));
  assert.equal(check(f).classification, 'rollover');
});
for (const name of names) test(`worker rejects changed ${name}`, () => {
  const f = fixture(); f.after.environment.find(e => e.name === name).value += '-unreviewed';
  assert.throws(() => check(f));
});
for (const [name, mutate] of Object.entries({
  'partial configuration': f => f.after.environment.pop(),
  'partial predecessor': f => f.before.environment.push(f.after.environment[1]),
  'extra environment': f => f.after.environment.push({ name: 'NODE_OPTIONS', value: '--require=/tmp/code' }),
  'duplicate environment': f => f.after.environment.push(f.after.environment[1]),
  'missing SMTP secret': f => f.after.secrets = f.before.secrets,
  'wrong SMTP secret': f => f.after.secrets = f.after.secrets.map(s => s.name === 'SMTP_PASS' ? { ...s, valueFrom: s.valueFrom + '-other' } : s),
  'changed database secret': f => f.after.secrets = f.after.secrets.map(s => s.name === 'DATABASE_URL' ? { ...s, valueFrom: 'other' } : s),
  'extra secret': f => f.after.secrets = [...f.after.secrets, { name: 'OTHER', valueFrom: 'other' }],
  'duplicate secret': f => f.after.secrets = [...f.after.secrets, f.after.secrets.at(-1)],
  'entrypoint override': f => f.after.entryPoint = ['sh'],
  'wrong image': f => f.after.image = f.after.image.replace('2'.repeat(64), '1'.repeat(64)),
  'task role escalation': f => f.change.change.after.task_role_arn += '-admin',
  'execution role escalation': f => f.change.change.after.execution_role_arn += '-admin',
  'wrong candidate': f => f.change.address = 'aws_ecs_task_definition.candidate["canary"]',
})) test(`worker runtime rejects ${name}`, () => { const f = fixture(); mutate(f); assert.throws(() => check(f)); });
test('SMTP remains owned only by the existing support-worker Terraform policy', () => {
  const stageB = fs.readFileSync('infra/aws/terraform/production-green-stage-b/main.tf', 'utf8');
  assert.match(stageB, /if kind != "worker" \|\| secret.name != "SMTP_PASS"/);
  const worker = fs.readFileSync('infra/aws/terraform/production-support-email-worker/main.tf', 'utf8');
  assert.match(worker, /resource "aws_iam_role_policy" "smtp_secret_read"/);
  assert.match(worker, /Action\s*= \["secretsmanager:GetSecretValue"\]/);
  assert.match(worker, /Resource\s*= data.aws_secretsmanager_secret.smtp.arn/);
});
